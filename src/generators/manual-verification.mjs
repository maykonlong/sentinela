/**
 * Manual Verification Generator — Instruções "Como Verificar Manualmente"
 * 
 * Para cada tipo de achado, gera instruções passo-a-passo de como
 * o profissional/empresa pode verificar manualmente o problema.
 */

const VERIFICATION_MAP = {
  // ── Headers de Segurança ──
  missing_security_header: (f) => ({
    title: `Verificar header "${f.header}"`,
    steps: [
      `Abrir o terminal e executar:`,
      `\`curl -I "${f.url || 'https://seu-site.com'}"\``,
      `Procurar pelo header \`${f.header}\` na resposta.`,
      `Se não aparecer, o header está ausente.`,
    ],
    devtools: `DevTools → Network → clicar na requisição do documento → aba Headers → procurar "${f.header}" em Response Headers.`,
    automated: `curl -sI "${f.url || 'https://seu-site.com'}" | grep -i "${f.header}"`,
  }),

  weak_security_header: (f) => ({
    title: `Verificar valor do header "${f.header}"`,
    steps: [
      `Executar: \`curl -I "${f.url || 'https://seu-site.com'}"\``,
      `Localizar o header \`${f.header}\` e verificar se o valor é adequado.`,
      `Valor atual: \`${f.currentValue || '?'}\``,
    ],
    devtools: `DevTools → Network → clicar no documento → Headers → verificar valor de "${f.header}".`,
    automated: `curl -sI "${f.url || 'https://seu-site.com'}" | grep -i "${f.header}"`,
  }),

  information_disclosure_header: (f) => ({
    title: `Verificar se o header "${f.header}" expõe informações`,
    steps: [
      `Executar: \`curl -I "${f.url || 'https://seu-site.com'}"\``,
      `Verificar se o header \`${f.header}\` revela tecnologia/versão do servidor.`,
    ],
    devtools: `DevTools → Network → clicar no documento → Headers → verificar "${f.header}".`,
    automated: `curl -sI "${f.url || 'https://seu-site.com'}" | grep -i "server\\|x-powered"`,
  }),

  // ── Cookies ──
  cookie_insecure_flags: (f) => ({
    title: `Verificar flags do cookie "${f.cookieName}"`,
    steps: [
      `Abrir DevTools (F12) → aba Application → Cookies → selecionar o domínio.`,
      `Localizar o cookie \`${f.cookieName}\`.`,
      `Verificar as colunas: HttpOnly, Secure, SameSite.`,
      `Todos devem estar marcados para cookies de sessão/autenticação.`,
    ],
    devtools: `DevTools → Application → Cookies → ${f.domain || 'domínio'} → localizar "${f.cookieName}" → verificar colunas HttpOnly, Secure, SameSite.`,
    automated: `curl -sI "${f.url || 'https://seu-site.com'}" | grep -i "set-cookie.*${f.cookieName}"`,
  }),

  // ── Storage ──
  storage_sensitive_data: (f) => ({
    title: `Verificar dado sensível no ${f.storage}`,
    steps: [
      `Abrir DevTools (F12) → Application → ${f.storage}.`,
      `Localizar a chave \`${f.key}\`.`,
      `Verificar se o valor contém dados sensíveis (tokens, emails, senhas).`,
    ],
    devtools: `DevTools → Application → ${f.storage} → localizar chave "${f.key}".`,
    automated: `No console do DevTools: \`${f.storage}.getItem("${f.key}")\``,
  }),

  storage_jwt_exposed: (f) => ({
    title: `Verificar JWT exposto no ${f.storage}`,
    steps: [
      `Abrir DevTools (F12) → Application → ${f.storage}.`,
      `Localizar a chave \`${f.key}\`.`,
      `Copiar o valor e colar em https://jwt.io para decodificar.`,
      `Verificar se contém dados sensíveis no payload.`,
    ],
    devtools: `DevTools → Application → ${f.storage} → copiar valor de "${f.key}" → decodificar em jwt.io`,
    automated: `No console: \`JSON.parse(atob(${f.storage}.getItem("${f.key}").split('.')[1]))\``,
  }),

  // ── Código ──
  exposed_key: (f) => ({
    title: `Verificar segredo/API key no código-fonte`,
    steps: [
      `Abrir DevTools (F12) → Sources → localizar o arquivo.`,
      `Usar Ctrl+F para buscar pelo padrão encontrado.`,
      `Verificar se é uma chave real ou placeholder.`,
    ],
    devtools: `DevTools → Sources → Ctrl+Shift+F (busca global) → buscar "${(f.match || '').substring(0, 20)}..."`,
    automated: `curl -s "${f.url || ''}" | grep -oP "${(f.match || '').substring(0, 15)}[^\\s\"']*"`,
  }),

  dangerous_code: (f) => ({
    title: `Verificar uso perigoso de ${f.match || 'código'}`,
    steps: [
      `Abrir DevTools (F12) → Sources → localizar o arquivo: ${f.url || '?'}`,
      `Buscar por: \`${f.match || 'innerHTML/eval'}\``,
      `Verificar se o input é sanitizado antes de ser usado.`,
    ],
    devtools: `DevTools → Sources → Ctrl+Shift+F → buscar "${f.match || 'innerHTML'}"`,
  }),

  missing_sri: (f) => ({
    title: `Verificar SRI (Subresource Integrity) no script externo`,
    steps: [
      `Abrir o código-fonte da página (Ctrl+U).`,
      `Localizar a tag \`<script src="${f.src || f.url || '...'}">\`.`,
      `Verificar se tem o atributo \`integrity="sha256-..."\`.`,
      `Se não tiver, o script está sem proteção contra tampering.`,
    ],
    devtools: `DevTools → Elements → Ctrl+F → buscar o src do script → verificar se tem atributo integrity.`,
  }),

  // ── TLS ──
  weak_tls: (f) => ({
    title: `Verificar protocolo TLS`,
    steps: [
      `Executar: \`nmap --script ssl-enum-ciphers -p 443 ${f.url ? new URL(f.url).hostname : 'hostname'}\``,
      `Ou usar o SSL Labs: https://www.ssllabs.com/ssltest/`,
      `Verificar se TLS 1.0/1.1 estão habilitados (devem estar desabilitados).`,
    ],
    automated: `curl -v --tlsv1.0 "${f.url || 'https://seu-site.com'}" 2>&1 | grep "SSL connection"`,
  }),

  cert_expired: (f) => ({
    title: `Verificar certificado TLS`,
    steps: [
      `Clicar no cadeado na barra do navegador → "Connection is secure" → "Certificate".`,
      `Verificar a data de expiração.`,
      `Ou executar: \`echo | openssl s_client -connect ${f.url ? new URL(f.url).hostname : 'hostname'}:443 2>/dev/null | openssl x509 -dates\``,
    ],
    automated: `echo | openssl s_client -connect ${f.url ? new URL(f.url).hostname : 'hostname'}:443 2>/dev/null | openssl x509 -enddate -noout`,
  }),

  cert_expiring: (f) => ({
    title: `Verificar validade do certificado TLS`,
    steps: [
      `Clicar no cadeado na barra do navegador → verificar data de expiração.`,
      `Certificado expira em breve — agendar renovação.`,
    ],
    automated: `echo | openssl s_client -connect ${f.url ? new URL(f.url).hostname : 'hostname'}:443 2>/dev/null | openssl x509 -enddate -noout`,
  }),

  // ── Portas ──
  exposed_port: (f) => ({
    title: `Verificar porta ${f.port} (${f.service})`,
    steps: [
      `Executar: \`telnet ${f.url ? new URL(f.url).hostname : 'hostname'} ${f.port}\``,
      `Se conectar, a porta está aberta publicamente.`,
      `Verificar no firewall se a porta deve estar acessível pela internet.`,
    ],
    automated: `nc -zv ${f.url ? new URL(f.url).hostname : 'hostname'} ${f.port} 2>&1`,
  }),

  // ── CORS ──
  cors_wildcard: (f) => ({
    title: `Verificar CORS wildcard`,
    steps: [
      `Executar: \`curl -H "Origin: https://evil.com" -I "${f.url || 'https://seu-site.com'}"\``,
      `Verificar se o header Access-Control-Allow-Origin retorna \`*\` ou reflete a origin enviada.`,
    ],
    automated: `curl -sI -H "Origin: https://evil.com" "${f.url || 'https://seu-site.com'}" | grep -i "access-control"`,
  }),

  // ── IP/Reputação ──
  ip_blacklisted: (f) => ({
    title: `Verificar reputação do IP`,
    steps: [
      `Acessar https://mxtoolbox.com/blacklists.aspx`,
      `Inserir o IP: ${f.ip || '?'}`,
      `Verificar em quais blacklists está listado.`,
      `Para cada blacklist, seguir o processo de delisting.`,
    ],
    automated: `nslookup ${f.ip ? f.ip.split('.').reverse().join('.') : '?'}.zen.spamhaus.org`,
  }),

  // ── Login ──
  login_form_get: (f) => ({
    title: `Verificar method do formulário de login`,
    steps: [
      `Abrir a página de login.`,
      `DevTools → Elements → localizar a tag \`<form>\`.`,
      `Verificar o atributo \`method\`. Deve ser "POST", nunca "GET".`,
    ],
    devtools: `DevTools → Elements → buscar "form" → verificar atributo method.`,
  }),

  login_form_http: (f) => ({
    title: `Verificar se o login usa HTTPS`,
    steps: [
      `Verificar a URL na barra do navegador — deve começar com https://.`,
      `Verificar o action do formulário — deve apontar para https://.`,
    ],
    devtools: `DevTools → Elements → buscar "form" → verificar atributo action.`,
  }),

  session_fixation: (f) => ({
    title: `Verificar regeneração de sessão após login`,
    steps: [
      `Abrir DevTools → Application → Cookies ANTES de fazer login.`,
      `Anotar o valor do cookie "${f.cookieName || 'session'}".`,
      `Fazer login.`,
      `Verificar se o valor do cookie mudou. Se for o MESMO, há session fixation.`,
    ],
    devtools: `DevTools → Application → Cookies → comparar valor de "${f.cookieName || 'session'}" antes e depois do login.`,
  }),

  // ── Formulários ──
  form_no_csrf: (f) => ({
    title: `Verificar token CSRF no formulário`,
    steps: [
      `Abrir DevTools → Elements → localizar o \`<form>\`.`,
      `Buscar por \`<input type="hidden">\` com name contendo "csrf", "_token", "authenticity_token".`,
      `Se não existir, verificar se o backend valida CSRF via header custom ou double-submit cookie.`,
    ],
    devtools: `DevTools → Elements → Ctrl+F → buscar "csrf" ou "_token".`,
  }),

  // ── Rede ──
  mixed_content: (f) => ({
    title: `Verificar mixed content`,
    steps: [
      `Abrir DevTools → Console → verificar avisos de "Mixed Content".`,
      `Ou: DevTools → Network → filtrar por "mixed-content" no badge.`,
      `Todos os recursos devem ser carregados via HTTPS.`,
    ],
    devtools: `DevTools → Console → filtrar por "Mixed Content".`,
  }),

  // ── Console ──
  console_error: (f) => ({
    title: `Verificar erros de JavaScript`,
    steps: [
      `Abrir DevTools (F12) → Console.`,
      `Verificar mensagens vermelhas (erros).`,
      `Investigar cada erro e corrigir.`,
    ],
    devtools: `DevTools → Console → filtrar por "Errors".`,
  }),

  // ── Bibliotecas ──
  vulnerable_library: (f) => ({
    title: `Verificar versão da biblioteca ${f.library || '?'}`,
    steps: [
      `Abrir DevTools → Sources → localizar o arquivo da biblioteca.`,
      `Verificar a versão no cabeçalho do arquivo ou via: \`${f.library}.version\` no console.`,
      `Comparar com a versão corrigida: ${f.fixedIn || '(não informada)'}.`,
      `Atualizar para a versão mais recente.`,
    ],
    devtools: `DevTools → Console → digitar "${f.library}" e verificar .version ou .VERSION.`,
  }),
};

// Fallback genérico
const GENERIC_VERIFICATION = (f) => ({
  title: `Verificar: ${f.label || f.type}`,
  steps: [
    `Abrir DevTools (F12) no navegador.`,
    `Investigar o achado "${f.label || f.type}" conforme a descrição.`,
    f.url ? `URL afetada: ${f.url}` : null,
    f.recommendation ? `Correção sugerida: ${f.recommendation}` : null,
  ].filter(Boolean),
  devtools: `DevTools → verificar conforme a descrição do achado.`,
});

/**
 * Gera instrução de verificação manual para um finding.
 * @param {object} finding - Achado do Sentinela
 * @returns {object} Instruções de verificação { title, steps[], devtools, automated? }
 */
export function getManualVerification(finding) {
  const generator = VERIFICATION_MAP[finding.type];
  if (generator) {
    try { return generator(finding); } catch { /* fallback */ }
  }
  return GENERIC_VERIFICATION(finding);
}

/**
 * Enriquece uma lista de findings com instruções de verificação.
 * @param {object[]} findings - Lista de achados
 * @returns {object[]} Findings com campo `manualVerification` adicionado
 */
export function enrichWithVerification(findings) {
  return findings.map(f => ({
    ...f,
    manualVerification: getManualVerification(f),
  }));
}
