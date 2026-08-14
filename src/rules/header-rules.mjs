/**
 * Regras de detecção para headers HTTP de segurança
 * Verifica se o servidor envia os headers de proteção necessários
 */

const SECURITY_HEADERS = [
  {
    name: 'Content-Security-Policy',
    aliases: ['content-security-policy'],
    severity: 'HIGH',
    description: 'Controla quais recursos podem ser carregados na página.',
    risk: 'Sem CSP, qualquer script/estilo/iframe pode ser injetado na página via XSS.',
    recommendation: "Implementar CSP restritivo. Mínimo: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;",
    checkValue: (value) => {
      const issues = [];
      if (value.includes("'unsafe-inline'") && value.includes('script-src')) {
        issues.push("script-src contém 'unsafe-inline' — permite execução de scripts inline (XSS)");
      }
      if (value.includes("'unsafe-eval'")) {
        issues.push("Contém 'unsafe-eval' — permite eval() (execução de código arbitrário)");
      }
      if (value.includes('*')) {
        issues.push("Contém wildcard '*' — permite carregamento de recursos de qualquer origem");
      }
      return issues;
    },
  },
  {
    name: 'Strict-Transport-Security',
    aliases: ['strict-transport-security'],
    severity: 'HIGH',
    description: 'Força HTTPS em todas as conexões futuras.',
    risk: 'Sem HSTS, usuário pode ser redirecionado para HTTP e sofrer Man-in-the-Middle (downgrade attack).',
    recommendation: 'Adicionar: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    checkValue: (value) => {
      const issues = [];
      const maxAge = value.match(/max-age=(\d+)/);
      if (maxAge && parseInt(maxAge[1]) < 31536000) {
        issues.push(`max-age muito baixo (${maxAge[1]}). Recomendado: 31536000 (1 ano)`);
      }
      if (!value.includes('includeSubDomains')) {
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
    severity: 'LOW',
    description: 'Filtro XSS do navegador (legado, mas ainda útil).',
    risk: 'Sem este header, navegadores antigos não ativam filtro XSS interno.',
    recommendation: 'Adicionar: X-XSS-Protection: 1; mode=block. Nota: CSP é mais eficaz, mas este header é complementar.',
  },
  {
    name: 'Cross-Origin-Opener-Policy',
    aliases: ['cross-origin-opener-policy'],
    severity: 'LOW',
    description: 'Isola a janela do navegador de outros contextos.',
    risk: 'Sem COOP, scripts de outras janelas/popups podem interagir com sua página.',
    recommendation: 'Adicionar: Cross-Origin-Opener-Policy: same-origin',
  },
  {
    name: 'Cross-Origin-Embedder-Policy',
    aliases: ['cross-origin-embedder-policy'],
    severity: 'LOW',
    description: 'Controla carregamento de recursos cross-origin.',
    risk: 'Sem COEP, recursos cross-origin podem ser carregados sem opt-in explícito.',
    recommendation: 'Adicionar: Cross-Origin-Embedder-Policy: require-corp (necessário para SharedArrayBuffer e alta resolução de timers).',
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

    if (!headerValue) {
      findings.push({
        type: 'missing_security_header',
        severity: rule.severity,
        header: rule.name,
        description: rule.description,
        url,
        risk: rule.risk,
        recommendation: rule.recommendation,
      });
    } else if (rule.checkValue) {
      const issues = rule.checkValue(headerValue);
      if (issues.length > 0) {
        findings.push({
          type: 'weak_security_header',
          severity: rule.severity,
          header: rule.name,
          currentValue: headerValue,
          issues,
          url,
          risk: `Header ${rule.name} está presente mas com configuração fraca.`,
          recommendation: rule.recommendation,
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

  if (url.startsWith('http://') && !url.includes('localhost') && !url.includes('127.0.0.1')) {
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
