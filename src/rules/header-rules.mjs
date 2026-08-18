/**
 * Regras de detecção para headers HTTP de segurança
 * Verifica se o servidor envia os headers de proteção necessários
 *
 * Princípio: ausência de evidência NÃO é evidência de vulnerabilidade.
 * Severidade só escala quando existe evidência positiva (diretiva realmente
 * permissiva, header realmente presente com valor fraco, host onde o controle
 * realmente se aplica).
 */

import net from 'node:net';

// ─── Helpers de host ───────────────────────────────────────

/** Extrai o hostname de uma URL, já sem os colchetes de literal IPv6. */
function hostnameOf(url) {
  try {
    let h = new URL(url).hostname;
    if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1); // URL() devolve IPv6 como "[::1]"
    return h;
  } catch {
    return '';
  }
}

/**
 * Host é um endereço IP literal?
 * Importa porque navegadores NÃO aplicam HSTS a IPs (RFC 6797 §8.1.1 exige um
 * hostname registrável). Sem isso, o alvo real `https://10.4.0.20:8443` recebia
 * um HIGH "falta HSTS" que é tecnicamente inaplicável — o navegador ignoraria o
 * header mesmo se ele fosse enviado.
 */
function isIpHost(url) {
  return net.isIP(hostnameOf(url)) !== 0;
}

/**
 * Host é loopback / rede privada / link-local?
 * Usa `hostname` em vez de substring: `url.includes('localhost')` casava
 * `https://exemplo.com/?redirect=localhost` e suprimia um achado legítimo de HTTP.
 */
function isPrivateOrLoopbackHost(url) {
  const h = hostnameOf(url).toLowerCase();
  if (!h) return false;
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local')) return true;

  const kind = net.isIP(h);
  if (kind === 4) {
    const o = h.split('.').map(Number);
    if (o[0] === 127) return true;                        // 127.0.0.0/8 loopback
    if (o[0] === 10) return true;                         // 10.0.0.0/8
    if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true; // 172.16.0.0/12
    if (o[0] === 192 && o[1] === 168) return true;        // 192.168.0.0/16
    if (o[0] === 169 && o[1] === 254) return true;        // 169.254.0.0/16 link-local
    return false;
  }
  if (kind === 6) {
    if (h === '::1') return true;                          // loopback
    if (/^fe[89ab]/.test(h)) return true;                  // fe80::/10 link-local
    if (/^f[cd]/.test(h)) return true;                     // fc00::/7 unique-local
    return false;
  }
  return false;
}

// ─── Helpers de CSP ────────────────────────────────────────

/**
 * Parsing real da CSP: diretiva → lista de sources.
 * Duplicatas são ignoradas (a primeira ocorrência vence, como manda a spec).
 */
function parseCsp(value) {
  const map = new Map();
  for (const chunk of String(value).split(';')) {
    const parts = chunk.trim().split(/\s+/).filter(Boolean);
    if (!parts.length) continue;
    const name = parts.shift().toLowerCase();
    // Sources ficam em lowercase só para comparação de prefixo ('nonce-', 'sha256-'),
    // o que não altera a semântica dessas checagens.
    if (!map.has(name)) map.set(name, parts.map(p => p.toLowerCase()));
  }
  return map;
}

/**
 * Lista de sources que governa <script> inline: script-src-elem > script-src > default-src.
 * Sem esse fallback correto, `style-src 'unsafe-inline'` (obrigatório com
 * styled-jsx/Tailwind) era confundido com script-src e gerava HIGH falso.
 */
function effectiveScriptSrc(csp) {
  return csp.get('script-src-elem') || csp.get('script-src') || csp.get('default-src') || null;
}

/** Nonce/hash/strict-dynamic presente? Se sim, navegadores modernos IGNORAM 'unsafe-inline'. */
function hasNonceOrHash(sources) {
  return sources.some(s =>
    s.startsWith("'nonce-") ||
    s.startsWith("'sha256-") || s.startsWith("'sha384-") || s.startsWith("'sha512-") ||
    s === "'strict-dynamic'"
  );
}

// Diretivas que aceitam lista de sources (as demais — report-uri, sandbox,
// upgrade-insecure-requests… — não têm "curinga" a checar).
const FETCH_DIRECTIVES = new Set([
  'default-src', 'script-src', 'script-src-elem', 'script-src-attr',
  'style-src', 'style-src-elem', 'style-src-attr',
  'img-src', 'connect-src', 'font-src', 'frame-src', 'media-src',
  'object-src', 'worker-src', 'child-src', 'manifest-src',
  'form-action', 'frame-ancestors', 'base-uri',
]);

// Diretivas onde `data:` significa executar/embutir conteúdo arbitrário.
// Em img-src/font-src, `data:` é uso rotineiro e legítimo — não é achado.
const DATA_URI_RISKY = new Set(['default-src', 'script-src', 'script-src-elem', 'object-src']);

const SECURITY_HEADERS = [
  {
    name: 'Content-Security-Policy',
    aliases: ['content-security-policy'],
    severity: 'HIGH',
    description: 'Controla quais recursos podem ser carregados na página.',
    risk: 'Sem CSP, qualquer script/estilo/iframe pode ser injetado na página via XSS.',
    recommendation: "Implementar CSP restritivo. Mínimo: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;",
    checkValue: (value, url, headerMap) => {
      // Cada issue carrega sua própria severidade — a CSP pode falhar em várias
      // diretivas de risco bem diferente (unsafe-inline é HIGH, faltar form-action
      // é LOW), e o achado final deve refletir a pior evidência real encontrada,
      // não um HIGH fixo para qualquer desvio. Ver cálculo de `severity` no fim.
      const issues = [];
      const push = (message, severity) => issues.push({ message, severity });

      const csp = parseCsp(value);
      if (csp.size === 0) return { issues: [], severity: undefined }; // valor não parseável: sem evidência, sem achado

      const scriptSrc = effectiveScriptSrc(csp);

      // 1) 'unsafe-inline' SÓ é problema quando está na lista que governa scripts
      //    E não há nonce/hash/strict-dynamic. FP concreto evitado: a CSP típica de
      //    Next.js `script-src 'self' 'nonce-abc'; style-src 'self' 'unsafe-inline'`
      //    — o 'unsafe-inline' está em style-src (exigido por styled-jsx/Tailwind) e,
      //    mesmo se estivesse em script-src, o nonce faz o navegador ignorá-lo
      //    (é fallback deliberado para browsers antigos, não é falha).
      if (!scriptSrc) {
        push("Nenhuma diretiva script-src/script-src-elem/default-src — scripts de qualquer origem são permitidos", 'HIGH');
      } else if (scriptSrc.includes("'unsafe-inline'") && !hasNonceOrHash(scriptSrc)) {
        push("script-src efetivo contém 'unsafe-inline' sem nonce/hash/strict-dynamic — permite execução de scripts inline (XSS)", 'HIGH');
      }

      // 2) 'unsafe-eval' só faz sentido na lista de scripts ('unsafe-eval' em
      //    style-src/img-src é inerte e não deve virar achado).
      const evalSrc = csp.get('script-src') || csp.get('default-src') || [];
      if (evalSrc.includes("'unsafe-eval'") || (scriptSrc && scriptSrc.includes("'unsafe-eval'"))) {
        push("script-src contém 'unsafe-eval' — permite eval() (execução de código arbitrário)", 'HIGH');
      }

      // 3) Curinga precisa ser SOURCE COMPLETO. FP concreto evitado:
      //    `script-src https://*.cmsw.com` era acusado de "permite qualquer origem"
      //    por conter o caractere '*' — mas wildcard de subdomínio é escopado.
      //    O que realmente abre tudo é o source ser exatamente `*`, `https:` ou `http:`.
      for (const [directive, sources] of csp) {
        if (!FETCH_DIRECTIVES.has(directive)) continue;
        for (const src of sources) {
          if (src === '*' || src === 'https:' || src === 'http:') {
            push(`Diretiva ${directive} usa o source "${src}" — permite recursos de qualquer origem`, 'HIGH');
          } else if (src === 'data:' && DATA_URI_RISKY.has(directive)) {
            push(`Diretiva ${directive} aceita "data:" — permite injetar código via data URI`, 'HIGH');
          }
        }
      }

      // 4) frame-ancestors — substituto moderno do X-Frame-Options, e tem
      //    precedência sobre ele nos navegadores atuais. Sem essa diretiva,
      //    QUALQUER site pode carregar a página num <iframe> (clickjacking).
      //    Se X-Frame-Options já cobre o mesmo risco, o achado é rebaixado —
      //    ausência de UMA camada quando a outra existe não é o mesmo risco
      //    que ausência das DUAS.
      if (!csp.has('frame-ancestors')) {
        const hasXfo = !!(headerMap && headerMap['x-frame-options']);
        if (hasXfo) {
          push("Falta frame-ancestors na CSP — risco de clickjacking mitigado por X-Frame-Options, mas CSP é o mecanismo moderno (recomenda-se definir também, ex.: frame-ancestors 'self')", 'LOW');
        } else {
          push("Falta frame-ancestors na CSP e X-Frame-Options também está ausente — qualquer site pode carregar esta página num iframe (clickjacking)", 'MEDIUM');
        }
      }

      // 5) base-uri — sem essa diretiva, um <base href="https://evil.com/">
      //    injetado via XSS sequestra TODAS as URLs relativas da página
      //    (scripts, links, forms) para o domínio do atacante, mesmo com
      //    script-src restrito.
      if (!csp.has('base-uri')) {
        push("Falta base-uri na CSP — um <base> injetado via XSS pode sequestrar todas as URLs relativas (scripts, links, forms) para um domínio controlado pelo atacante", 'MEDIUM');
      }

      // 6) object-src — sem essa diretiva, <object>/<embed>/<applet> (plugins
      //    legados, ex.: Flash) podem ser usados para burlar restrições de
      //    script-src. Não é achado real se default-src já é 'none' — nesse
      //    caso object-src herda a restrição por padrão.
      if (!csp.has('object-src')) {
        const defaultSrc = csp.get('default-src');
        const coveredByDefaultNone = defaultSrc && defaultSrc.length === 1 && defaultSrc[0] === "'none'";
        if (!coveredByDefaultNone) {
          push("Falta object-src na CSP — permite <object>/<embed>/<applet> (plugins legados), que podem burlar restrições de script-src", 'LOW');
        }
      }

      // 7) form-action — sem essa diretiva, um formulário injetado via XSS
      //    pode submeter dados para um domínio externo controlado pelo
      //    atacante, mesmo sem conseguir rodar JS livremente.
      if (!csp.has('form-action')) {
        push("Falta form-action na CSP — um formulário injetado via XSS pode submeter dados para um domínio externo controlado pelo atacante", 'LOW');
      }

      // Severidade final = pior evidência real entre as issues encontradas
      // (não um HIGH fixo para qualquer desvio da CSP ideal).
      const RANK = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
      const severity = issues.reduce((max, i) => (RANK[i.severity] > RANK[max] ? i.severity : max), 'INFO');

      return { issues: issues.map(i => i.message), severity: issues.length ? severity : undefined };
    },
  },
  {
    name: 'Strict-Transport-Security',
    aliases: ['strict-transport-security'],
    severity: 'HIGH',
    description: 'Força HTTPS em todas as conexões futuras.',
    risk: 'Sem HSTS, usuário pode ser redirecionado para HTTP e sofrer Man-in-the-Middle (downgrade attack).',
    recommendation: 'Adicionar: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    // Host IP literal (ex.: o alvo real https://10.4.0.20:8443): navegadores
    // descartam HSTS para IPs, então cobrar o header como HIGH é inaplicável.
    applicability: (url) => isIpHost(url)
      ? {
          severity: 'INFO',
          note: 'Host é um endereço IP literal — navegadores NÃO aplicam HSTS a IPs (RFC 6797 §8.1.1). Enviar o header aqui não teria efeito; item apenas informativo.',
        }
      : {},
    checkValue: (value, url) => {
      const issues = [];
      const maxAge = value.match(/max-age=(\d+)/);
      if (maxAge && parseInt(maxAge[1]) < 31536000) {
        issues.push(`max-age muito baixo (${maxAge[1]}). Recomendado: 31536000 (1 ano)`);
      }
      // includeSubDomains não faz sentido para IP literal (IP não tem subdomínio).
      if (!value.includes('includeSubDomains') && !isIpHost(url)) {
        issues.push('Falta includeSubDomains — subdomínios não estão protegidos');
      }
      return issues;
    },
  },
  {
    name: 'X-Frame-Options',
    aliases: ['x-frame-options'],
    severity: 'MEDIUM',
    description: 'Previne que a página seja carregada em iframes.',
    risk: 'Sem X-Frame-Options, atacante pode embutir seu site em iframe e realizar clickjacking.',
    recommendation: 'Adicionar: X-Frame-Options: DENY (ou SAMEORIGIN se precisar de iframes internos).',
  },
  {
    name: 'X-Content-Type-Options',
    aliases: ['x-content-type-options'],
    severity: 'MEDIUM',
    description: 'Previne MIME-type sniffing.',
    risk: 'Navegador pode interpretar arquivos com MIME type errado, potencialmente executando código malicioso.',
    recommendation: 'Adicionar: X-Content-Type-Options: nosniff',
    checkValue: (value) => {
      if (value.toLowerCase() !== 'nosniff') {
        return [`Valor "${value}" inválido. Deve ser "nosniff".`];
      }
      return [];
    },
  },
  {
    name: 'Referrer-Policy',
    aliases: ['referrer-policy'],
    severity: 'LOW',
    description: 'Controla quais informações de referrer são enviadas.',
    risk: 'Sem Referrer-Policy, URLs com dados sensíveis (tokens em query string) podem vazar para sites externos via header Referer.',
    recommendation: 'Adicionar: Referrer-Policy: strict-origin-when-cross-origin (ou no-referrer para máxima privacidade).',
  },
  {
    name: 'Permissions-Policy',
    aliases: ['permissions-policy', 'feature-policy'],
    severity: 'LOW',
    description: 'Controla quais APIs do navegador podem ser usadas.',
    risk: 'Sem Permissions-Policy, scripts de terceiros podem acessar câmera, microfone, geolocalização, etc.',
    recommendation: 'Adicionar: Permissions-Policy: camera=(), microphone=(), geolocation=() (desabilitar o que não usar).',
  },
  {
    name: 'X-XSS-Protection',
    aliases: ['x-xss-protection'],
    severity: 'INFO',
    // Header DEPRECIADO e removido dos navegadores modernos. A recomendação atual
    // (OWASP Secure Headers / MDN) é `X-XSS-Protection: 0` — o modo `1; mode=block`
    // introduziu XS-Leaks (o filtro do Auditor podia ser abusado para inferir
    // conteúdo cross-origin). Por isso a AUSÊNCIA do header não é achado
    // (`onlyWhenPresent`); só reportamos quando ele está presente com o valor legado.
    onlyWhenPresent: true,
    description: 'Filtro XSS legado do navegador (depreciado e removido dos browsers atuais).',
    risk: 'O modo "1; mode=block" está associado a XS-Leaks. A proteção efetiva contra XSS hoje é CSP.',
    recommendation: 'Definir X-XSS-Protection: 0 (desabilitar o filtro legado) e confiar em Content-Security-Policy.',
    checkValue: (value) => {
      const v = value.trim().toLowerCase();
      if (v.startsWith('1')) {
        return ['Valor legado "1; mode=block" — o filtro XSS foi removido dos navegadores e a variante de bloqueio permitia XS-Leaks. O recomendado hoje é "0".'];
      }
      return [];
    },
  },
  {
    name: 'Cross-Origin-Opener-Policy',
    aliases: ['cross-origin-opener-policy'],
    // INFO, não LOW: COOP/COEP só importam para apps que precisam de
    // cross-origin isolation (SharedArrayBuffer, timers de alta resolução).
    // Emitir LOW para todo site era ruído puro em 100% das auditorias.
    severity: 'INFO',
    description: 'Isola a janela do navegador de outros contextos (pré-requisito de cross-origin isolation).',
    risk: 'Sem COOP, popups abertos pela página mantêm referência via window.opener. Relevante sobretudo se a app usa SharedArrayBuffer ou depende de isolamento de processo.',
    recommendation: 'Se a aplicação precisa de cross-origin isolation (SharedArrayBuffer/timers precisos), adicionar: Cross-Origin-Opener-Policy: same-origin.',
  },
  {
    name: 'Cross-Origin-Embedder-Policy',
    aliases: ['cross-origin-embedder-policy'],
    severity: 'INFO', // ver comentário do COOP acima
    description: 'Controla carregamento de recursos cross-origin (pré-requisito de cross-origin isolation).',
    risk: 'Sem COEP, recursos cross-origin são carregados sem opt-in explícito. Só é requisito real para apps que usam SharedArrayBuffer.',
    recommendation: 'Só necessário para cross-origin isolation: Cross-Origin-Embedder-Policy: require-corp. Habilitar sem revisar os recursos de terceiros pode quebrar a página.',
  },
];

const DANGEROUS_HEADERS = [
  {
    name: 'Server',
    severity: 'LOW',
    risk: 'Expõe tecnologia/versão do servidor (information disclosure). Atacante pode buscar vulnerabilidades conhecidas para aquela versão.',
    recommendation: 'Remover ou ofuscar header Server. No Nginx: server_tokens off;',
  },
  {
    name: 'X-Powered-By',
    severity: 'LOW',
    risk: 'Expõe framework/linguagem utilizada (ex: Express, PHP). Facilita ataques direcionados.',
    recommendation: 'Remover header X-Powered-By. No Express: app.disable("x-powered-by");',
  },
  {
    name: 'X-AspNet-Version',
    severity: 'LOW',
    risk: 'Expõe versão do ASP.NET. Facilita exploração de vulnerabilidades conhecidas.',
    recommendation: 'Remover via web.config: <httpRuntime enableVersionHeader="false" />',
  },
];

/**
 * Analisa headers HTTP de segurança de uma response
 */
export function analyzeHeaders(responseHeaders, url) {
  const findings = [];
  const headerMap = {};

  // Normalizar headers para lowercase
  for (const [key, value] of Object.entries(responseHeaders)) {
    headerMap[key.toLowerCase()] = value;
  }

  // Verificar headers de segurança ausentes
  for (const rule of SECURITY_HEADERS) {
    const headerValue = rule.aliases.reduce((found, alias) => found || headerMap[alias], null);

    // Ajuste contextual (ex.: HSTS em host IP literal): pode pular ou rebaixar.
    const ctx = rule.applicability ? rule.applicability(url) : {};
    if (ctx.skip) continue;
    const severity = ctx.severity || rule.severity;

    if (!headerValue) {
      // Headers depreciados (X-XSS-Protection) só são reportados quando presentes:
      // a ausência deles é o estado correto, não uma falha.
      if (rule.onlyWhenPresent) continue;
      findings.push({
        type: 'missing_security_header',
        severity,
        header: rule.name,
        description: rule.description,
        url,
        risk: rule.risk,
        recommendation: rule.recommendation,
        ...(ctx.note ? { note: ctx.note } : {}),
      });
    } else if (rule.checkValue) {
      // Contrato do checkValue: pode devolver `string[]` (issues, severidade fixa
      // da regra — HSTS, X-XSS-Protection) ou `{ issues, severity }` quando a
      // própria regra precisa escalar a severidade com base na evidência
      // encontrada (CSP — ver comentário em SECURITY_HEADERS acima).
      const result = rule.checkValue(headerValue, url, headerMap);
      const issues = Array.isArray(result) ? result : result.issues;
      const effectiveSeverity = Array.isArray(result) ? severity : (result.severity || severity);
      if (issues.length > 0) {
        findings.push({
          type: 'weak_security_header',
          severity: effectiveSeverity,
          header: rule.name,
          currentValue: headerValue,
          issues,
          url,
          risk: `Header ${rule.name} está presente mas com configuração fraca.`,
          recommendation: rule.recommendation,
          ...(ctx.note ? { note: ctx.note } : {}),
        });
      }
    }
  }

  // Verificar headers que expõem informações
  for (const rule of DANGEROUS_HEADERS) {
    const headerValue = headerMap[rule.name.toLowerCase()];
    if (headerValue) {
      findings.push({
        type: 'information_disclosure_header',
        severity: rule.severity,
        header: rule.name,
        value: headerValue,
        url,
        risk: rule.risk,
        recommendation: rule.recommendation,
      });
    }
  }

  // Verificar CORS permissivo
  const corsOrigin = headerMap['access-control-allow-origin'];
  if (corsOrigin === '*') {
    findings.push({
      type: 'cors_wildcard',
      severity: 'HIGH',
      header: 'Access-Control-Allow-Origin',
      value: '*',
      url,
      risk: 'CORS com wildcard (*) permite que QUALQUER site faça requisições para sua API. Atacante pode criar página maliciosa que rouba dados do seu backend usando o navegador da vítima.',
      recommendation: 'Restringir CORS para domínios específicos: Access-Control-Allow-Origin: https://seu-dominio.com',
    });
  }

  const corsCredentials = headerMap['access-control-allow-credentials'];
  if (corsCredentials === 'true' && corsOrigin && corsOrigin !== 'null') {
    findings.push({
      type: 'cors_credentials',
      severity: 'MEDIUM',
      header: 'Access-Control-Allow-Credentials',
      value: 'true',
      corsOrigin,
      url,
      risk: 'CORS permite envio de credenciais (cookies). Se combinado com origem permissiva, atacante pode fazer requisições autenticadas em nome da vítima.',
      recommendation: 'Usar Access-Control-Allow-Credentials: true APENAS com origens explícitas e confiáveis (nunca com *).',
    });
  }

  return findings;
}

/**
 * Verifica se a conexão é HTTPS
 */
export function analyzeProtocol(url) {
  const findings = [];

  // Comparação por hostname, não por substring: `url.includes('localhost')`
  // casava `https://exemplo.com/?redirect=localhost` e silenciava um HTTP real.
  if (url.startsWith('http://') && !isPrivateOrLoopbackHost(url)) {
    findings.push({
      type: 'no_https',
      severity: 'CRITICAL',
      url,
      risk: 'Site servido via HTTP (sem criptografia). TODOS os dados trafegam em texto puro: senhas, tokens, dados pessoais. Qualquer pessoa na mesma rede pode interceptar (Man-in-the-Middle).',
      recommendation: 'Migrar para HTTPS com certificado TLS válido. Usar Let\'s Encrypt (gratuito). Configurar redirecionamento HTTP→HTTPS.',
    });
  }

  return findings;
}
