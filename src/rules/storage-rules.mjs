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
  { pattern: /auth/i, category: 'auth', label: 'Dados de autenticação' },
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
  { pattern: /user.?role|papel|role/i, category: 'user', label: 'Role/Papel do usuário' },
  { pattern: /user.?type|tipo.?usuario/i, category: 'user', label: 'Tipo de usuário' },
  { pattern: /is.?admin/i, category: 'user', label: 'Flag de administrador' },
  { pattern: /permission|permissao|permissão/i, category: 'user', label: 'Permissões' },
  { pattern: /privilege|privilegio|privilégio/i, category: 'user', label: 'Privilégios' },
];

const JWT_REGEX = /^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

/**
 * Analisa dados de storage (localStorage ou sessionStorage)
 */
export function analyzeStorage(storageData, storageType) {
  const findings = [];

  for (const [key, value] of Object.entries(storageData)) {
    // Checar chave contra padrões sensíveis
    for (const rule of SENSITIVE_PATTERNS) {
      if (rule.pattern.test(key)) {
        const finding = {
          type: 'storage_sensitive_data',
          severity: getSeverity(rule.category),
          storage: storageType,
          key,
          valuePreview: maskValue(value),
          valueLength: value.length,
          category: rule.category,
          label: rule.label,
          risk: getRiskDescription(rule.category, key, storageType),
          recommendation: getRecommendation(rule.category, storageType),
        };

        // Tentar decodificar JWT
        if (JWT_REGEX.test(value)) {
          try {
            const payload = JSON.parse(atob(value.split('.')[1]));
            finding.jwtDecoded = {
              payload: maskSensitiveFields(payload),
              expiresAt: payload.exp ? new Date(payload.exp * 1000).toISOString() : 'sem expiração (!)',
              issuedAt: payload.iat ? new Date(payload.iat * 1000).toISOString() : 'desconhecido',
              hasExpiration: !!payload.exp,
            };
            finding.severity = 'CRITICAL';
            finding.risk += '\n⚠️  JWT DECODIFICÁVEL: O token pode ser lido por qualquer script na página (XSS → roubo de sessão).';
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

    // Checar valor independente da chave (detectar JWTs em qualquer lugar)
    if (JWT_REGEX.test(value)) {
      const alreadyFound = findings.some(f => f.key === key);
      if (!alreadyFound) {
        try {
          const payload = JSON.parse(atob(value.split('.')[1]));
          findings.push({
            type: 'storage_jwt_exposed',
            severity: 'CRITICAL',
            storage: storageType,
            key,
            valuePreview: maskValue(value),
            jwtDecoded: {
              payload: maskSensitiveFields(payload),
              expiresAt: payload.exp ? new Date(payload.exp * 1000).toISOString() : 'sem expiração (!)',
              issuedAt: payload.iat ? new Date(payload.iat * 1000).toISOString() : 'desconhecido',
              hasExpiration: !!payload.exp,
            },
            risk: `JWT encontrado em ${storageType}["${key}"]. Qualquer script (incluindo XSS) pode ler este token e se passar pelo usuário.`,
            recommendation: 'Mover JWT para httpOnly cookie. Nunca armazenar tokens de autenticação em localStorage/sessionStorage.',
          });
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

    // Cookie sem httpOnly
    if (!cookie.httpOnly) {
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

    // Cookie sem SameSite ou com SameSite=None
    if (!cookie.sameSite || cookie.sameSite === 'None') {
      issues.push({
        flag: `sameSite=${cookie.sameSite || 'não definido'}`,
        risk: 'Cookie enviado em requests cross-site. Vulnerável a CSRF (Cross-Site Request Forgery).',
      });
    }

    // Cookie com dados sensíveis na chave
    for (const rule of SENSITIVE_PATTERNS) {
      if (rule.pattern.test(cookie.name)) {
        if (!cookie.httpOnly) {
          findings.push({
            type: 'cookie_sensitive_no_httponly',
            severity: 'CRITICAL',
            thirdParty,
            vendor,
            cookieName: cookie.name,
            label: rule.label,
            domain: cookie.domain,
            path: cookie.path,
            flags: {
              httpOnly: cookie.httpOnly,
              secure: cookie.secure,
              sameSite: cookie.sameSite,
              expires: cookie.expires > 0 ? new Date(cookie.expires * 1000).toISOString() : 'sessão',
            },
            risk: `Cookie "${cookie.name}" contém ${rule.label} mas NÃO é httpOnly. Atacante pode roubar via document.cookie em XSS.`,
            recommendation: 'Marcar como httpOnly, secure, SameSite=Strict (ou Lax).',
          });
        }
        break;
      }
    }

    // Cookies com muitas flags inseguras
    if (issues.length > 0) {
      // Checar se é um cookie sensível
      const isSensitive = SENSITIVE_PATTERNS.some(r => r.pattern.test(cookie.name));
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
  }

  return findings;
}

// ─── Helpers ───────────────────────────────────────────────

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
