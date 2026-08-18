/**
 * Regras de detecção para localStorage/sessionStorage/cookies
 * Detecta dados sensíveis armazenados no client-side
 */

import { classifyCookie } from './context-rules.mjs';

const SENSITIVE_PATTERNS = [
  // Tokens e autenticação
  { pattern: /token/i, category: 'auth', label: 'Token de autenticação' },
  { pattern: /jwt/i, category: 'auth', label: 'JSON Web Token' },
  { pattern: /access.?token/i, category: 'auth', label: 'Access Token' },
  { pattern: /refresh.?token/i, category: 'auth', label: 'Refresh Token' },
  // Delimitado: /auth/i solto casava `oauth`, `authDomain` e `author` e virava
  // CRITICAL "dados de autenticação" numa app Keycloak/Firebase comum.
  { pattern: /(^|[_.\-])auth(orization)?([_.\-]|$)/i, category: 'auth', label: 'Dados de autenticação' },
  { pattern: /session/i, category: 'auth', label: 'Dados de sessão' },
  { pattern: /bearer/i, category: 'auth', label: 'Bearer Token' },

  // Chaves e segredos
  { pattern: /api.?key/i, category: 'keys', label: 'API Key' },
  { pattern: /secret/i, category: 'keys', label: 'Secret/Segredo' },
  { pattern: /private.?key/i, category: 'keys', label: 'Chave privada' },
  { pattern: /password/i, category: 'keys', label: 'Senha' },
  { pattern: /passwd/i, category: 'keys', label: 'Senha' },
  { pattern: /credential/i, category: 'keys', label: 'Credencial' },

  // Dados pessoais (PII)
  { pattern: /cpf/i, category: 'pii', label: 'CPF' },
  { pattern: /cnpj/i, category: 'pii', label: 'CNPJ' },
  { pattern: /email/i, category: 'pii', label: 'Email' },
  { pattern: /phone|telefone|celular/i, category: 'pii', label: 'Telefone' },
  { pattern: /address|endereco|endereço/i, category: 'pii', label: 'Endereço' },
  { pattern: /credit.?card|cartao|cartão/i, category: 'pii', label: 'Cartão de crédito' },
  { pattern: /card.?number/i, category: 'pii', label: 'Número do cartão' },
  { pattern: /cvv/i, category: 'pii', label: 'CVV' },

  // Dados do usuário
  // Delimitado: /role/i solto casava `roleplay`, `controle`, `payrolePolicy`…
  { pattern: /(^|[_.\-])roles?([_.\-]|$)|user.?roles?|(^|[_.\-])pap[eé]l([_.\-]|$)/i, category: 'user', label: 'Role/Papel do usuário' },
  { pattern: /user.?type|tipo.?usuario/i, category: 'user', label: 'Tipo de usuário' },
  { pattern: /is.?admin/i, category: 'user', label: 'Flag de administrador' },
  { pattern: /permission|permissao|permissão/i, category: 'user', label: 'Permissões' },
  { pattern: /privilege|privilegio|privilégio/i, category: 'user', label: 'Privilégios' },
];

/**
 * JWT NÃO ancorado (sem ^...$) e sem flag /g (evita lastIndex compartilhado).
 * O regex ancorado antigo ignorava o caso mais comum em produção: o token
 * gravado DENTRO de um JSON — que é exatamente como `oidc-client-ts`,
 * `next-auth` e `keycloak-js` persistem (`{"access_token":"eyJ..."}` sob a
 * chave `oidc.user:<issuer>:<clientId>`). Resultado: o achado carro-chefe
 * nunca era emitido.
 */
const JWT_REGEX = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/;

/** Extrai o primeiro JWT presente no valor (solto ou embutido em JSON). */
function extractJwt(value) {
  if (typeof value !== 'string') return null;
  const m = value.match(JWT_REGEX);
  return m ? m[0] : null;
}

/**
 * Decodifica o payload de um JWT.
 * NÃO usar atob(): em Node 24 ele LANÇA InvalidCharacterError em base64url com
 * `-` ou `_`, presentes em praticamente todo JWT real. Como o finding inteiro
 * ficava dentro do try, o `storage_jwt_exposed` (CRITICAL) simplesmente nunca
 * era emitido — falso NEGATIVO silencioso.
 */
function decodeJwtPayload(token) {
  const part = token.split('.')[1];
  if (!part) return null;
  const b64 = part.replace(/-/g, '+').replace(/_/g, '/');
  const json = Buffer.from(b64, 'base64').toString('utf8');
  const payload = JSON.parse(json);
  return (payload && typeof payload === 'object') ? payload : null;
}

/** Monta o bloco jwtDecoded padronizado a partir de um payload já decodificado. */
function buildJwtDecoded(payload) {
  return {
    payload: maskSensitiveFields(payload),
    expiresAt: payload.exp ? new Date(payload.exp * 1000).toISOString() : 'sem expiração (!)',
    issuedAt: payload.iat ? new Date(payload.iat * 1000).toISOString() : 'desconhecido',
    hasExpiration: !!payload.exp,
  };
}

// ─── Corroboração pelo VALOR ───────────────────────────────
// Princípio: o NOME da chave é indício, não prova. Só escalamos a severidade
// quando o VALOR corrobora que ali existe mesmo um segredo/PII.

/**
 * Chaves que costumam casar os padrões sensíveis guardando dados públicos.
 * Não são silenciadas (continuam sendo reportadas), apenas não escalam sozinhas.
 * FP concreto: `csrf-token`, `recaptcha-token`, `session-state` do OIDC.
 */
const BENIGN_KEY_PATTERNS = [
  /(^|[_.\-])x?csrf([_.\-]|$)|(^|[_.\-])xsrf([_.\-]|$)/i,
  /re?captcha|hcaptcha|turnstile/i,
  /(^|[_.\-])(session|auth|login)[_.\-]?state([_.\-]|$)/i,
  /(^|[_.\-])(nonce|code[_.\-]?verifier|code[_.\-]?challenge)([_.\-]|$)/i,
];

function isBenignKey(key) {
  return BENIGN_KEY_PATTERNS.some(p => p.test(key));
}

/** Entropia de Shannon em bits por caractere. */
function shannonEntropy(str) {
  const freq = new Map();
  for (const ch of str) freq.set(ch, (freq.get(ch) || 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / str.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * O valor parece um segredo de verdade?
 * FP concreto evitado: numa app Keycloak, `kc-callback-<uuid>` e chaves `oidc.*`
 * guardam `{"redirectUri":"/home"}` e viravam CRITICAL "chave/segredo exposto"
 * só pelo nome. JSON/URL/booleano/número não é credencial.
 */
function looksLikeSecret(value) {
  if (typeof value !== 'string') return false;
  const v = value.trim();
  if (!v) return false;
  if (v.startsWith('{') || v.startsWith('[')) return false;   // estrutura de estado da app
  if (v.length < 20) return false;                            // curto demais para ser token/chave
  if (/^(true|false|null|undefined)$/i.test(v)) return false;
  if (/^-?\d+(\.\d+)?$/.test(v)) return false;                // timestamp/id numérico
  if (/^https?:\/\//i.test(v) || v.startsWith('/')) return false; // redirectUri/path
  return shannonEntropy(v) >= 3.2;                            // aleatoriedade compatível com segredo
}

// Formatos de PII que valem como evidência positiva mesmo com baixa entropia
// (um e-mail real tem entropia baixa, mas é PII inegável).
const PII_VALUE_PATTERNS = [
  /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i,        // e-mail
  /\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b/,              // CPF
  /\b\d{2}\.?\d{3}\.?\d{3}\/?\d{4}-?\d{2}\b/,      // CNPJ
  /\b(?:\+?55\s?)?\(?\d{2}\)?\s?9?\d{4}-?\d{4}\b/, // telefone BR
  /\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b/,       // cartão
];

function looksLikePii(value) {
  if (typeof value !== 'string' || !value.trim()) return false;
  return PII_VALUE_PATTERNS.some(p => p.test(value));
}

/**
 * Existe evidência POSITIVA no valor para escalar a severidade da categoria?
 * Sem evidência → LOW (ver getSeverity).
 */
function hasValueEvidence(category, value) {
  if (category === 'pii') return looksLikePii(value) || looksLikeSecret(value);
  return looksLikeSecret(value);
}

/**
 * Cookie de CSRF (double-submit) — precisa ser legível por JS por definição.
 * Cobre XSRF-TOKEN, csrf-token, _csrf, __Host-csrf-token etc.
 */
function isCsrfCookie(name) {
  const bare = String(name || '').replace(/^__(Host|Secure)-/i, '');
  return /(^|[_.\-])(x?csrf|xsrf)([_.\-]|$)/i.test(bare);
}

/**
 * Cookie prefixes __Host- e __Secure- (RFC 6265bis / "cookie prefixes"), já
 * suportados por todos os browsers modernos. São AUTO-DECLARAÇÃO DE SEGURANÇA
 * imposta pelo BROWSER no momento da gravação do cookie — não é uma checagem
 * nossa, é hard enforcement:
 *   - `__Host-x`  só é aceito se secure=true, SEM atributo Domain= (cookie
 *     host-only) e Path=/.
 *   - `__Secure-x` só é aceito se secure=true.
 * Se um cookie chegou até o Playwright com um desses prefixos, ele NECESSARIAMENTE
 * já passou nessa validação — do contrário o browser teria REJEITADO o cookie
 * inteiro (silenciosamente, sem erro visível). Ou seja: é IMPOSSÍVEL observar
 * aqui um `__Host-`/`__Secure-` "quebrado". O valor desta checagem é o oposto:
 * identificar cookies de SESSÃO/AUTENTICAÇÃO que ainda não usam o prefixo e
 * ganhariam essa camada extra de defesa do browser contra cookie injection
 * (ex.: subdomínio comprometido setando um cookie que sobrescreve o do domínio
 * pai, ou atacante de rede em contexto misto HTTP/HTTPS).
 */
function hasHostPrefix(name) {
  return /^__Host-/.test(String(name || ''));
}
function hasSecurePrefix(name) {
  return /^__Secure-/.test(String(name || ''));
}

/**
 * Heurística para "cookie host-only" (sem atributo Domain= explícito), usada
 * só para decidir QUAL prefixo recomendar — nunca para reportar um problema.
 * O Chromium (via CDP, que é o que o Playwright expõe) normaliza cookies com
 * Domain= explícito prefixando um `.` no campo `domain`; cookies host-only
 * (sem Domain=) não carregam esse `.`. Não é garantido em 100% dos casos, por
 * isso o pior efeito colateral de errar é recomendar __Secure- quando __Host-
 * também seria possível — uma recomendação sub-ótima, nunca um falso positivo.
 */
function looksHostOnly(cookie) {
  return !!cookie.domain && !cookie.domain.startsWith('.') && cookie.path === '/';
}

/**
 * Cookie de sessão/autenticação de verdade (reaproveita a categoria 'auth' de
 * SENSITIVE_PATTERNS: token/jwt/access_token/refresh_token/auth.../session/bearer).
 * Exclui cookies de CSRF (double-submit, não é credencial em si) e chaves
 * benignas (csrf/recaptcha/*-state/nonce/code_verifier) para não gerar ruído
 * em cookies de analytics/preferência ou artefatos de fluxo OIDC.
 */
function isSensitiveAuthCookie(name) {
  if (isCsrfCookie(name)) return false;
  if (isBenignKey(name)) return false;
  return SENSITIVE_PATTERNS.some(r => r.category === 'auth' && r.pattern.test(name));
}

/**
 * Analisa dados de storage (localStorage ou sessionStorage)
 */
export function analyzeStorage(storageData, storageType) {
  const findings = [];

  for (const [key, value] of Object.entries(storageData)) {
    const jwt = extractJwt(value);

    // Checar chave contra padrões sensíveis
    for (const rule of SENSITIVE_PATTERNS) {
      if (rule.pattern.test(key)) {
        // Severidade parte da corroboração pelo valor; o JWT abaixo pode escalar.
        const evidence = hasValueEvidence(rule.category, value);
        const finding = {
          type: 'storage_sensitive_data',
          severity: (evidence && !isBenignKey(key)) ? getSeverity(rule.category) : 'LOW',
          storage: storageType,
          key,
          valuePreview: maskValue(value),
          valueLength: value.length,
          category: rule.category,
          label: rule.label,
          valueEvidence: evidence,
          risk: getRiskDescription(rule.category, key, storageType),
          recommendation: getRecommendation(rule.category, storageType),
        };

        if (!evidence || isBenignKey(key)) {
          // Deixa explícito no relatório POR QUE não é CRITICAL — evita que o
          // leitor interprete o rebaixamento como omissão.
          finding.risk += '\n(ℹ️  Severidade reduzida: o nome da chave casou um padrão sensível, mas o VALOR não corrobora um segredo/PII — sem alta entropia, ou é estrutura JSON/URL/flag. Confirmar manualmente.)';
        }

        // Tentar decodificar JWT (inclusive quando embutido em JSON)
        if (jwt) {
          try {
            const payload = decodeJwtPayload(jwt);
            if (payload) {
              finding.jwtDecoded = buildJwtDecoded(payload);
              finding.severity = 'CRITICAL'; // evidência positiva: token real e legível
              finding.valueEvidence = true;
              finding.risk += '\n⚠️  JWT DECODIFICÁVEL: O token pode ser lido por qualquer script na página (XSS → roubo de sessão).';
            }
          } catch {
            // JWT inválido ou corrompido
          }
        }

        // Checar se o valor parece ser JSON com dados sensíveis
        try {
          const parsed = JSON.parse(value);
          if (typeof parsed === 'object' && parsed !== null) {
            const sensitiveFields = findSensitiveFields(parsed);
            if (sensitiveFields.length > 0) {
              finding.nestedSensitiveFields = sensitiveFields;
              finding.risk += `\n⚠️  Objeto JSON contém campos sensíveis aninhados: ${sensitiveFields.join(', ')}`;
            }
          }
        } catch {
          // Não é JSON
        }

        findings.push(finding);
        break; // Só precisa do primeiro match por chave
      }
    }

    // Checar valor independente da chave (detectar JWTs em qualquer lugar,
    // inclusive dentro de JSON — caso oidc-client-ts/next-auth/keycloak-js).
    if (jwt) {
      const alreadyFound = findings.some(f => f.key === key);
      if (!alreadyFound) {
        try {
          const payload = decodeJwtPayload(jwt);
          if (payload) {
            findings.push({
              type: 'storage_jwt_exposed',
              severity: 'CRITICAL',
              storage: storageType,
              key,
              valuePreview: maskValue(value),
              jwtDecoded: buildJwtDecoded(payload),
              risk: `JWT encontrado em ${storageType}["${key}"]. Qualquer script (incluindo XSS) pode ler este token e se passar pelo usuário.`,
              recommendation: 'Mover JWT para httpOnly cookie. Nunca armazenar tokens de autenticação em localStorage/sessionStorage.',
            });
          }
        } catch {
          // JWT inválido
        }
      }
    }
  }

  return findings;
}

/**
 * Analisa cookies
 */
export function analyzeCookies(cookies, pageOrigin = '') {
  const findings = [];

  for (const cookie of cookies) {
    const { thirdParty, vendor } = classifyCookie(cookie.domain, pageOrigin);
    const issues = [];
    const csrfByDesign = isCsrfCookie(cookie.name);

    // Cookie sem httpOnly.
    // Cookies de CSRF (XSRF-TOKEN, csrf-token…) PRECISAM ser legíveis por JS:
    // é o padrão double-submit (Angular/axios leem via document.cookie para
    // ecoar o valor num header). Cobrar httpOnly neles é FP por design.
    if (!cookie.httpOnly && !csrfByDesign) {
      issues.push({
        flag: 'httpOnly=false',
        risk: 'Cookie acessível via JavaScript. Em caso de XSS, atacante pode roubar o cookie.',
      });
    }

    // Cookie sem secure
    if (!cookie.secure) {
      issues.push({
        flag: 'secure=false',
        risk: 'Cookie transmitido em HTTP (sem criptografia). Atacante em rede compartilhada pode interceptar (Man-in-the-Middle).',
      });
    }

    // SameSite: só acusamos o valor EXPLÍCITO 'None'.
    // Verificado no Playwright 1.62.1 (chromium `doGetCookies`): cookie sem o
    // atributo chega como `sameSite: 'Lax'` (`sameSite ?? "Lax"`), refletindo o
    // Lax-by-default do Chrome. Portanto `!cookie.sameSite` é inalcançável e,
    // se um dia voltasse como 'None' por default, acusaria de CSRF todo cookie
    // que o navegador já trata como Lax.
    if (cookie.sameSite === 'None') {
      issues.push({
        flag: 'sameSite=None',
        risk: 'Cookie explicitamente liberado para requests cross-site. Amplia a superfície de CSRF e de vazamento em contexto de terceiros.',
      });
    }

    // Cookie com dados sensíveis na chave
    let specificFindingEmitted = false;
    for (const rule of SENSITIVE_PATTERNS) {
      if (!rule.pattern.test(cookie.name)) continue;
      if (!cookie.httpOnly && !csrfByDesign && !isBenignKey(cookie.name)) {
        // Corroboração pelo valor: um cookie de sessão real tem valor opaco e
        // de alta entropia. Nome sensível com valor trivial (ex.: `authStep=2`)
        // não é credencial roubável — não merece CRITICAL.
        const evidence = looksLikeSecret(cookie.value);
        findings.push({
          type: 'cookie_sensitive_no_httponly',
          severity: evidence ? 'CRITICAL' : 'MEDIUM',
          thirdParty,
          vendor,
          cookieName: cookie.name,
          label: rule.label,
          domain: cookie.domain,
          path: cookie.path,
          valuePreview: maskValue(cookie.value),
          valueEvidence: evidence,
          // Agrega as demais flags aqui: como este finding substitui o
          // cookie_insecure_flags para o mesmo cookie, nada se perde.
          issues,
          flags: {
            httpOnly: cookie.httpOnly,
            secure: cookie.secure,
            sameSite: cookie.sameSite,
            expires: cookie.expires > 0 ? new Date(cookie.expires * 1000).toISOString() : 'sessão',
          },
          risk: `Cookie "${cookie.name}" contém ${rule.label} mas NÃO é httpOnly. Atacante pode roubar via document.cookie em XSS.`
            + (evidence ? '' : '\n(ℹ️  Severidade reduzida: o valor do cookie não tem cara de credencial (curto/baixa entropia). Confirmar manualmente.)'),
          recommendation: 'Marcar como httpOnly, secure, SameSite=Strict (ou Lax).',
        });
        specificFindingEmitted = true;
      }
      break;
    }

    // Cookies com flags inseguras.
    // Só emitido quando o cookie NÃO gerou o finding específico acima — antes,
    // o mesmo cookie sensível sem httpOnly produzia CRITICAL + HIGH pelo mesmo
    // motivo, inflando as duas contagens ao mesmo tempo.
    if (issues.length > 0 && !specificFindingEmitted) {
      // Checar se é um cookie sensível
      const isSensitive = SENSITIVE_PATTERNS.some(r => r.pattern.test(cookie.name)) && !isBenignKey(cookie.name);
      findings.push({
        type: 'cookie_insecure_flags',
        severity: isSensitive ? 'HIGH' : 'MEDIUM',
        thirdParty,
        vendor,
        cookieName: cookie.name,
        domain: cookie.domain,
        path: cookie.path,
        valuePreview: maskValue(cookie.value),
        issues,
        recommendation: 'Configurar cookies com: httpOnly=true, secure=true, SameSite=Strict (ou Lax para cookies de navegação).',
      });
    }

    // Cookie prefixes __Host-/__Secure- (ver comentário em isSensitiveAuthCookie
    // e hasHostPrefix/hasSecurePrefix acima). Hardening, não vulnerabilidade —
    // por isso severidade LOW/INFO, nunca escala. Só para 1ª parte: o site não
    // controla o prefixo de cookies setados por terceiros.
    if (!thirdParty && isSensitiveAuthCookie(cookie.name) && !hasHostPrefix(cookie.name)) {
      if (hasSecurePrefix(cookie.name)) {
        // Já usa __Secure- (secure=true garantido pelo browser). Só vale a pena
        // sugerir o upgrade para __Host- quando o cookie já cumpriria os
        // requisitos extras (host-only + Path=/) — senão a sugestão obrigaria
        // a remover o Domain=, o que pode quebrar o app (cookie compartilhado
        // entre subdomínios de propósito).
        if (looksHostOnly(cookie)) {
          const bare = cookie.name.replace(/^__Secure-/, '');
          findings.push({
            type: 'cookie_missing_secure_prefix',
            severity: 'INFO',
            thirdParty,
            vendor,
            cookieName: cookie.name,
            domain: cookie.domain,
            path: cookie.path,
            risk: `Cookie de sessão/autenticação "${cookie.name}" usa __Secure- (secure=true imposto pelo browser), mas parece host-only e já usa Path=/ — ou seja, provavelmente já cumpriria os requisitos do prefixo __Host-, que é mais restritivo (o browser também garante ausência de Domain= e Path=/).`,
            recommendation: `Avaliar renomear para __Host-${bare}: mesma proteção de __Secure- e, adicionalmente, o browser passa a IMPEDIR que subdomínios (mesmo maliciosos) sobrescrevam esse cookie via Domain=.`,
          });
        }
      } else {
        const suggestHost = looksHostOnly(cookie);
        findings.push({
          type: 'cookie_missing_secure_prefix',
          severity: 'LOW',
          thirdParty,
          vendor,
          cookieName: cookie.name,
          domain: cookie.domain,
          path: cookie.path,
          risk: `Cookie de sessão/autenticação "${cookie.name}" não usa os prefixos __Host-/__Secure-. Esses prefixos são validados pelo PRÓPRIO BROWSER na gravação do cookie (hard enforcement, não é sugestão de app) — um cookie __Host-x só é aceito se secure=true, sem Domain= e Path=/. Adotar o prefixo dá defesa em profundidade contra cookie injection (ex.: subdomínio comprometido, atacante de rede em contexto HTTP).`,
          recommendation: suggestHost
            ? `Renomear para __Host-${cookie.name} (o cookie já parece host-only e usar Path=/ — só falta o prefixo para o browser passar a IMPOR essas garantias).`
            : `Renomear para __Secure-${cookie.name} (exige apenas secure=true). Se possível, também remover o Domain= explícito e fixar Path=/ para poder usar __Host-${cookie.name}, ainda mais forte.`,
        });
      }
    }
  }

  return findings;
}

// ─── Helpers ───────────────────────────────────────────────

// Severidade MÁXIMA da categoria — só aplicada quando o valor corrobora
// (ver hasValueEvidence). Sem corroboração o chamador usa 'LOW'.
function getSeverity(category) {
  const map = {
    auth: 'CRITICAL',
    keys: 'CRITICAL',
    pii: 'HIGH',
    user: 'HIGH',
  };
  return map[category] || 'MEDIUM';
}

function getRiskDescription(category, key, storageType) {
  const base = `Dado sensível "${key}" encontrado em ${storageType}.`;

  const risks = {
    auth: `${base} Um atacante com XSS pode roubar o token e se autenticar como o usuário (session hijacking).`,
    keys: `${base} Chave/segredo exposto no client-side. Atacante pode usar para acessar APIs, serviços externos ou dados protegidos.`,
    pii: `${base} Dados pessoais no client-side violam LGPD/GDPR. Em XSS, atacante extrai dados do usuário.`,
    user: `${base} Roles/permissões no frontend podem ser alterados pelo usuário via DevTools para escalar privilégios.`,
  };

  return risks[category] || base;
}

function getRecommendation(category, storageType) {
  const recs = {
    auth: `NUNCA armazenar tokens em ${storageType}. Usar httpOnly cookies. Se precisar de estado de auth no frontend, usar apenas {id, name} (sem tokens).`,
    keys: 'Chaves de API devem ficar APENAS no backend. Usar proxy/BFF (Backend for Frontend) para chamadas a APIs externas.',
    pii: `Minimizar dados pessoais no ${storageType}. Manter apenas o necessário para UX (ex: primeiro nome). Dados sensíveis devem ser buscados do backend sob demanda.`,
    user: 'NUNCA confiar em roles/permissões do frontend para controle de acesso. O backend DEVE validar permissões em TODAS as rotas. Frontend usa roles apenas para renderização condicional.',
  };

  return recs[category] || `Avaliar se este dado precisa estar em ${storageType}.`;
}

function maskValue(value) {
  if (!value) return '(vazio)';
  if (value.length <= 8) return '***';
  return value.substring(0, 4) + '...' + value.substring(value.length - 4);
}

function maskSensitiveFields(obj) {
  const masked = { ...obj };
  const sensitiveKeys = ['password', 'passwd', 'secret', 'apiKey', 'api_key', 'credit_card', 'cvv', 'cpf', 'cnpj'];
  for (const key of Object.keys(masked)) {
    if (sensitiveKeys.some(sk => key.toLowerCase().includes(sk))) {
      masked[key] = '***MASKED***';
    }
  }
  return masked;
}

function findSensitiveFields(obj, prefix = '') {
  const found = [];
  for (const [key, value] of Object.entries(obj)) {
    const fullKey = prefix ? `${prefix}.${key}` : key;
    for (const rule of SENSITIVE_PATTERNS) {
      if (rule.pattern.test(key)) {
        found.push(fullKey);
        break;
      }
    }
    if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      found.push(...findSensitiveFields(value, fullKey));
    }
  }
  return found;
}
