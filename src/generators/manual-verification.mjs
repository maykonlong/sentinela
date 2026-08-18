/**
 * Manual Verification Generator — Prova Real e Validação Multi-Cenário
 *
 * Para cada achado, gera um plano de validação completo com PROVA REAL:
 *  1. Teste Focado: Busca exatamente a vulnerabilidade.
 *  2. Prova Real (Dump/Baseline): Exibe todos os cabeçalhos/dados para garantir que o resultado não é falso negativo por erro de filtro.
 *  3. DevTools / GUI: Passo a passo visual no navegador.
 *  4. Ferramenta Online / Alternativa: Segunda opinião externa.
 */

function sanitizeUrl(rawUrl, fallbackUrl = '') {
  const target = rawUrl || fallbackUrl || 'https://10.4.0.20:8443';
  // Se contiver anotação entre parênteses (ex: "https://site.com/page (inline script #1)"), extrair a URL limpa
  return target.split(' ')[0].trim();
}

function hostname(f, fallbackUrl = '') {
  if (f.host) return f.host;
  const cleanUrl = sanitizeUrl(f.url, fallbackUrl);
  try { return new URL(cleanUrl).hostname; } catch { return cleanUrl; }
}

function hostAndPort(f, defaultPort = 443, fallbackUrl = '') {
  const cleanUrl = sanitizeUrl(f.url, fallbackUrl);
  try {
    const u = new URL(cleanUrl);
    const port = u.port || (u.protocol === 'https:' ? '443' : '80');
    return `${u.hostname}:${port}`;
  } catch { /* fallback */ }

  if (f.host) {
    return `${f.host}:${f.port || defaultPort}`;
  }
  return `10.4.0.20:${defaultPort}`;
}

const VERIFICATION_MAP = {

  // ════════════════════════════════════════════════════
  // HEADERS DE SEGURANÇA
  // ════════════════════════════════════════════════════

  missing_security_header: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Header "${f.header}"`,
      steps: [
        `1. Teste focado: Execute o comando filtrado. Se não retornar nada, o header está ausente.`,
        `2. PROVA REAL (Dump Completo): Execute o comando sem grep para listar TODOS os cabeçalhos retornados pelo servidor.`,
        `   → Se o comando 2 trouxer cabeçalhos mas o comando 1 não trouxer "${f.header}", a AUSÊNCIA É REAL E CONFIRMADA.`,
        `   → Se o comando 2 der erro ou voltar vazio, há um problema de conexão/firewall (não um erro de header).`,
      ],
      devtools: `F12 → Network → selecionar primeira requisição → Headers → Response Headers (verificar lista completa).`,
      automated: `curl -skD - "${url}" -o /dev/null | grep -i "${f.header}"`,
      proofOfWork: `curl -skD - "${url}" -o /dev/null`,
      online: `https://securityheaders.com/?q=${encodeURIComponent(url)}&followRedirects=on`,
    };
  },

  weak_security_header: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Header "${f.header}"`,
      steps: [
        `1. Teste focado: Buscar o header "${f.header}". Valor atual capturado: "${f.currentValue || 'N/A'}"`,
        `2. PROVA REAL: Listar todos os cabeçalhos da resposta para inspecionar a diretiva completa.`,
      ],
      devtools: `F12 → Network → clique no documento → Response Headers → conferir valor de "${f.header}".`,
      automated: `curl -skD - "${url}" -o /dev/null | grep -i "${f.header}"`,
      proofOfWork: `curl -skD - "${url}" -o /dev/null`,
      online: `https://securityheaders.com/?q=${encodeURIComponent(url)}`,
    };
  },

  information_disclosure_header: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Exposição em Header "${f.header}"`,
      steps: [
        `1. Teste focado: Buscar assinaturas de servidor e tecnologia.`,
        `2. PROVA REAL: Listar todos os cabeçalhos para verificar se há vazamentos secundários (X-Powered-By, Server, Via).`,
      ],
      devtools: `F12 → Network → Response Headers → inspecionar campos de servidor.`,
      automated: `curl -skD - "${url}" -o /dev/null | grep -iE "server|x-powered|x-generator|via|x-aspnet"`,
      proofOfWork: `curl -skD - "${url}" -o /dev/null`,
    };
  },

  // ════════════════════════════════════════════════════
  // COOKIES
  // ════════════════════════════════════════════════════

  cookie_insecure_flags: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Cookie "${f.cookieName}"`,
      steps: [
        `1. Teste focado (HTTP): Filtrar o header Set-Cookie específico no terminal.`,
        `2. PROVA REAL (Navegador): Abrir F12 → Application → Cookies e inspecionar visualmente as colunas HttpOnly, Secure e SameSite.`,
      ],
      devtools: `F12 → Application → Storage → Cookies → ${f.domain || 'domínio'} → linha "${f.cookieName}".`,
      automated: `curl -skD - "${url}" -o /dev/null | grep -i "Set-Cookie.*${f.cookieName}"`,
      proofOfWork: `curl -skD - "${url}" -o /dev/null | grep -i "Set-Cookie"`,
    };
  },

  cookie_sensitive_no_httponly: (f) => ({
    title: `Validação & Prova Real para HttpOnly no Cookie "${f.cookieName}"`,
    steps: [
      `1. Teste via Console: Executar \`document.cookie\` no Console do navegador.`,
      `   → PROVA REAL: Se o cookie "${f.cookieName}" aparecer na string impressa, ele NÃO TEM HttpOnly (Vulnerável).`,
      `   → Se não aparecer, o cookie está protegido com HttpOnly.`,
    ],
    devtools: `F12 → Application → Cookies → "${f.cookieName}" → coluna HttpOnly.`,
    automated: `document.cookie.includes("${f.cookieName}")`,
    proofOfWork: `console.log(document.cookie)`,
  }),

  // ════════════════════════════════════════════════════
  // STORAGE
  // ════════════════════════════════════════════════════

  storage_sensitive_data: (f) => ({
    title: `Validação & Prova Real para Dados Sensíveis no ${f.storage || 'localStorage'}`,
    steps: [
      `1. Teste focado: Inspecionar o item específico "${f.key}".`,
      `2. PROVA REAL: Imprimir o armazenamento completo no Console para verificar se há outros dados vazados.`,
    ],
    devtools: `F12 → Application → ${f.storage || 'Local Storage'} → inspecionar tabela.`,
    automated: `${f.storage === 'sessionStorage' ? 'sessionStorage' : 'localStorage'}.getItem("${f.key}")`,
    proofOfWork: `console.table(Object.entries(${f.storage === 'sessionStorage' ? 'sessionStorage' : 'localStorage'}))`,
  }),

  storage_jwt_exposed: (f) => ({
    title: `Validação & Prova Real para JWT no ${f.storage || 'localStorage'}`,
    steps: [
      `1. Teste focado: Ler o token da chave "${f.key}".`,
      `2. PROVA REAL: Decodificar o payload Base64 do JWT e imprimir as claims diretamente.`,
    ],
    devtools: `F12 → Application → ${f.storage || 'Local Storage'} → "${f.key}" → copiar token e colar em jwt.io.`,
    automated: `JSON.parse(atob(localStorage.getItem("${f.key}").split('.')[1]))`,
    proofOfWork: `console.log(JSON.parse(atob(localStorage.getItem("${f.key}").split('.')[1])))`,
    online: `https://jwt.io`,
  }),

  // ════════════════════════════════════════════════════
  // CÓDIGO-FONTE
  // ════════════════════════════════════════════════════

  exposed_key: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Segredo no Código`,
      steps: [
        `1. Teste focado: Baixar o script e buscar o padrão.`,
        `2. PROVA REAL: Abrir o arquivo no DevTools (Sources) e verificar o contexto da linha.`,
      ],
      devtools: `F12 → Sources → Ctrl+Shift+F → buscar o trecho da chave.`,
      automated: `curl -sk "${url}" | grep -oE "[A-Za-z0-9_\\-]{20,}"`,
      proofOfWork: `curl -sk "${url}" | grep -n -C 3 -oE "[A-Za-z0-9_\\-]{20,}"`,
    };
  },

  dangerous_code: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para "${f.match || 'innerHTML'}"`,
      steps: [
        `1. Teste focado: Localizar o uso de ${f.match || 'innerHTML'} no arquivo ${f.url || url}.`,
        `2. PROVA REAL: Exibir as linhas com contexto (-C 3) para validar a falta de sanitização antes da atribuição.`,
      ],
      devtools: `F12 → Sources → Ctrl+Shift+F → buscar "${f.match || 'innerHTML'}".`,
      automated: `curl -sk "${url}" | grep -n "${f.match || 'innerHTML'}"`,
      proofOfWork: `curl -sk "${url}" | grep -n -C 3 "${f.match || 'innerHTML'}"`,
    };
  },

  missing_sri: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para SRI`,
      steps: [
        `1. Teste focado: Buscar a tag script no HTML.`,
        `2. PROVA REAL: Imprimir todas as tags script externas e verificar quais possuem o atributo \`integrity\`.`,
      ],
      devtools: `F12 → Elements → Ctrl+F → buscar o arquivo script.`,
      automated: `curl -sk "${url}" | grep -i "${f.src || 'script'}"`,
      proofOfWork: `curl -sk "${url}" | grep -iE "<script"`,
      online: `https://www.srihash.org/`,
    };
  },

  global_variable_sensitive: (f) => ({
    title: `Validação & Prova Real para Variável Global`,
    steps: [
      `1. Teste focado: Imprimir o valor de "${f.variable || 'window'}".`,
      `2. PROVA REAL: Inspecionar no Console todas as propriedades de \`window\` ou estado global.`,
    ],
    devtools: `F12 → Console → digitar o nome da variável.`,
    automated: `${f.variable || 'window'}`,
    proofOfWork: `console.dir(${f.variable || 'window'})`,
  }),

  frontend_role_definition: (f) => ({
    title: `Validação & Prova Real para Controle de Acesso no Frontend`,
    steps: [
      `1. Teste focado: Modificar o papel localmente.`,
      `2. PROVA REAL: Tentar efetuar uma ação privilegiada e verificar se o backend bloqueia com HTTP 401/403.`,
    ],
    devtools: `F12 → Console → alterar role → acionar botão administrativo.`,
  }),

  // ════════════════════════════════════════════════════
  // TLS / CERTIFICADO
  // ════════════════════════════════════════════════════

  weak_tls: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    const hostPort = hostAndPort(f, 443, targetUrl);
    return {
      title: `Validação & Prova Real para Protocolo TLS`,
      steps: [
        `1. Teste focado: Forçar handshake TLS 1.0.`,
        `2. PROVA REAL: Conectar e exibir todos os ciphers suportados pelo servidor.`,
      ],
      devtools: `F12 → Security → aba Connection.`,
      automated: `curl -v --tlsv1.0 --tls-max 1.0 "${url}" 2>&1 | grep "SSL connection"`,
      proofOfWork: `echo | openssl s_client -connect ${hostPort} -tls1 2>&1`,
      online: `https://www.ssllabs.com/ssltest/analyze.html?d=${hostname(f, targetUrl)}`,
    };
  },

  cert_expired: (f, targetUrl) => {
    const hostPort = hostAndPort(f, 443, targetUrl);
    return {
      title: `Validação & Prova Real para Certificado Expirado`,
      steps: [
        `1. Teste focado: Verificar data de expiração na porta real (${hostPort}).`,
        `2. PROVA REAL: Dump completo dos detalhes e emissor do certificado x509.`,
      ],
      devtools: `F12 → Security → View certificate.`,
      automated: `echo | openssl s_client -connect ${hostPort} 2>/dev/null | openssl x509 -enddate -noout`,
      proofOfWork: `echo | openssl s_client -connect ${hostPort} 2>/dev/null | openssl x509 -text -noout | grep -E "Not Before|Not After|Issuer|Subject"`,
      online: `https://www.sslshopper.com/ssl-checker.html#hostname=${hostname(f, targetUrl)}`,
    };
  },

  cert_expiring: (f, targetUrl) => {
    const hostPort = hostAndPort(f, 443, targetUrl);
    return {
      title: `Validação & Prova Real para Vencimento de Certificado`,
      steps: [
        `1. Teste focado: Consultar notAfter na porta real (${hostPort}).`,
        `2. PROVA REAL: Exibir o período completo de validade (Not Before e Not After).`,
      ],
      devtools: `F12 → Security → View certificate.`,
      automated: `echo | openssl s_client -connect ${hostPort} 2>/dev/null | openssl x509 -enddate -noout`,
      proofOfWork: `echo | openssl s_client -connect ${hostPort} 2>/dev/null | openssl x509 -dates -noout`,
    };
  },

  no_https: (f, targetUrl) => {
    const host = hostname(f, targetUrl);
    return {
      title: `Validação & Prova Real para Redirecionamento HTTPS`,
      steps: [
        `1. Teste focado: Verificar header Location na requisição HTTP.`,
        `2. PROVA REAL: Fazer requisição completa seguindo redirects (-L) e observar a cadeia de status codes.`,
      ],
      devtools: `F12 → Network → acessar HTTP → verificar status 301/302.`,
      automated: `curl -skD - "http://${host}" -o /dev/null | grep -iE "location|strict"`,
      proofOfWork: `curl -skD - -L "http://${host}" -o /dev/null`,
    };
  },

  // ════════════════════════════════════════════════════
  // REGISTROS DNS DE SEGURANÇA
  // ════════════════════════════════════════════════════

  missing_spf_record: (f, targetUrl) => {
    const host = f.host || hostname(f, targetUrl);
    return {
      title: `Validação & Prova Real para Registro SPF no DNS`,
      steps: [
        `1. Teste focado: Consultar registros TXT do domínio ${host} e buscar "v=spf1".`,
        `2. PROVA REAL: Listar TODOS os registros TXT do domínio para confirmar a ausência da política SPF.`,
      ],
      devtools: `Terminal / CLI (nslookup / dig / PowerShell).`,
      automated: `nslookup -type=TXT ${host} | grep -i "v=spf1"`,
      proofOfWork: `powershell -NoProfile -Command "Resolve-DnsName ${host} -Type TXT | ConvertTo-Json"`,
      online: `https://mxtoolbox.com/spf.aspx?domain=${host}`,
    };
  },

  missing_dmarc_record: (f, targetUrl) => {
    const host = f.host || hostname(f, targetUrl);
    return {
      title: `Validação & Prova Real para Registro DMARC no DNS`,
      steps: [
        `1. Teste focado: Consultar registro TXT em _dmarc.${host}.`,
        `2. PROVA REAL: Exibir todos os registros retornado em _dmarc.${host} e confirmar a ausência da política "v=DMARC1".`,
      ],
      devtools: `Terminal / CLI (nslookup / dig / PowerShell).`,
      automated: `nslookup -type=TXT _dmarc.${host} | grep -i "v=DMARC1"`,
      proofOfWork: `powershell -NoProfile -Command "Resolve-DnsName _dmarc.${host} -Type TXT | ConvertTo-Json"`,
      online: `https://mxtoolbox.com/dmarc.aspx?domain=${host}`,
    };
  },

  missing_caa_record: (f, targetUrl) => {
    const host = f.host || hostname(f, targetUrl);
    return {
      title: `Validação & Prova Real para Registro CAA no DNS`,
      steps: [
        `1. Teste focado: Consultar registros CAA do domínio ${host}.`,
        `2. PROVA REAL: Listar todas as respostas CAA. Se a lista retornar vazia, a ausência de restrição de CAs está confirmada.`,
      ],
      devtools: `Terminal / CLI (nslookup / dig / PowerShell).`,
      automated: `powershell -NoProfile -Command "Resolve-DnsName ${host} -Type CAA"`,
      proofOfWork: `powershell -NoProfile -Command "Resolve-DnsName ${host} -Type CAA -Server 8.8.8.8 | ConvertTo-Json"`,
      online: `https://sslmate.com/caa/check/${host}`,
    };
  },

  // ════════════════════════════════════════════════════
  // PORTAS TCP
  // ════════════════════════════════════════════════════

  exposed_port: (f, targetUrl) => {
    const host = f.host || hostname(f, targetUrl);
    return {
      title: `Validação & Prova Real para Porta ${f.port} (${f.service})`,
      steps: [
        `1. Teste focado: Tentar handshake TCP com netcat/nc.`,
        `2. PROVA REAL: Teste de banner grab / resposta de protocolo. Se conectar e responder banner, a exposição é 100% CONFIRMADA.`,
      ],
      devtools: `Terminal / CLI.`,
      automated: `nc -zv ${host} ${f.port} 2>&1`,
      proofOfWork: `nc -vv -w 3 ${host} ${f.port} 2>&1`,
      online: `https://www.yougetsignal.com/tools/open-ports/ (inserir IP ${host} e porta ${f.port})`,
    };
  },

  // ════════════════════════════════════════════════════
  // CORS
  // ════════════════════════════════════════════════════

  cors_wildcard: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para CORS Wildcard`,
      steps: [
        `1. Teste focado: Enviar Origin "https://evil.com".`,
        `2. PROVA REAL: Enviar preflight OPTIONS request e verificar se autoriza métodos e origens arbitrárias.`,
      ],
      devtools: `F12 → Console → testar fetch cross-origin.`,
      automated: `curl -skD - -H "Origin: https://evil.com" "${url}" -o /dev/null | grep -i "access-control"`,
      proofOfWork: `curl -skD - -X OPTIONS -H "Origin: https://evil.com" -H "Access-Control-Request-Method: POST" "${url}" -o /dev/null`,
    };
  },

  cors_credentials: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para CORS Credentials`,
      steps: [
        `1. Teste focado: Checar se ACAO reflete a Origin e ACAC é true.`,
        `2. PROVA REAL: Dump completo dos cabeçalhos Access-Control-*.`,
      ],
      devtools: `F12 → Network → Response Headers.`,
      automated: `curl -skD - -H "Origin: https://evil.com" "${url}" -o /dev/null | grep -i "access-control"`,
      proofOfWork: `curl -skD - -H "Origin: https://evil.com" "${url}" -o /dev/null | grep -iE "access-control-allow-origin|access-control-allow-credentials"`,
    };
  },

  // ════════════════════════════════════════════════════
  // RECON / EXPOSIÇÃO
  // ════════════════════════════════════════════════════

  swagger_exposed: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para OpenAPI/Swagger Público`,
      steps: [
        `1. Teste focado: Verificar status HTTP 200 do JSON de documentação.`,
        `2. PROVA REAL: Baixar o arquivo JSON e validar se contém a chave "paths" com os endpoints expostos.`,
      ],
      devtools: `Janela InPrivate → acessar a URL sem login.`,
      automated: `curl -skD - "${url}" -o /dev/null | head -n 5`,
      proofOfWork: `curl -sk "${url}" | grep -o '"paths":{[^}]*' | head -c 200`,
    };
  },

  graphql_exposed: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para GraphQL Introspection`,
      steps: [
        `1. Teste focado: Executar query de __schema.`,
        `2. PROVA REAL: Imprimir o catálogo de tipos retornado pela API.`,
      ],
      devtools: `F12 → Console → testar query GraphQL.`,
      automated: `curl -sk -X POST -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}' "${url}"`,
      proofOfWork: `curl -sk -X POST -H "Content-Type: application/json" -d '{"query":"{__schema{queryType{name}mutationType{name}}}"}' "${url}"`,
    };
  },

  robots_sensitive_paths: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para robots.txt`,
      steps: [
        `1. Teste focado: Baixar robots.txt.`,
        `2. PROVA REAL: Exibir todas as linhas "Disallow:" e testar o acesso HTTP em cada uma delas.`,
      ],
      devtools: `Acessar robots.txt no navegador.`,
      automated: `curl -sk "${url}"`,
      proofOfWork: `curl -sk "${url}" | grep -i "Disallow:"`,
    };
  },

  error_verbose: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Erro Verboso`,
      steps: [
        `1. Teste focado: Requisitar rota inexistente.`,
        `2. PROVA REAL: Exibir o corpo da resposta e buscar por assinaturas de stack trace (at / Exception / Traceback / Line).`,
      ],
      devtools: `F12 → Network → Response do erro.`,
      automated: `curl -sk "${url}"`,
      proofOfWork: `curl -sk "${url}" | grep -iE "exception|stacktrace|traceback|line [0-9]+"`,
    };
  },

  // ════════════════════════════════════════════════════
  // REPUTAÇÃO / IP
  // ════════════════════════════════════════════════════

  ip_blacklisted: (f) => ({
    title: `Validação & Prova Real para Blacklist IP`,
    steps: [
      `1. Teste focado: Consulta DNSBL.`,
      `2. PROVA REAL: Consultar os principais provedores de blacklist (Spamhaus, Sorbs, Barracuda) individualmente.`,
    ],
    devtools: `Consulta via CLI/MXToolbox.`,
    automated: `host ${f.ip ? f.ip.split('.').reverse().join('.') : '?'}.zen.spamhaus.org`,
    proofOfWork: `nslookup ${f.ip ? f.ip.split('.').reverse().join('.') : '?'}.bl.spamcop.net`,
    online: `https://mxtoolbox.com/blacklists.aspx?q=${f.ip || ''}`,
  }),

  // ════════════════════════════════════════════════════
  // LOGIN / AUTENTICAÇÃO
  // ════════════════════════════════════════════════════

  login_no_csrf: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para CSRF no Login`,
      steps: [
        `1. Teste focado: Buscar tags <input> ocultas no formulário.`,
        `2. PROVA REAL: Inspecionar o HTML completo da tag <form> até seu fechamento </form>.`,
      ],
      devtools: `F12 → Elements → buscar <form>.`,
      automated: `curl -sk "${url}" | grep -iE "csrf|_token|nonce"`,
      proofOfWork: `curl -sk "${url}" | grep -n -C 5 -i "<form"`,
    };
  },

  login_form_get: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Login via GET`,
      steps: [
        `1. Teste focado: Inspecionar o atributo method.`,
        `2. PROVA REAL: Imprimir a tag <form> da página de login.`,
      ],
      devtools: `F12 → Elements → inspecionar <form>.`,
      automated: `curl -sk "${url}" | grep -i "<form"`,
      proofOfWork: `curl -sk "${url}" | grep -oE '<form[^>]*>'`,
    };
  },

  login_credentials_http: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Credenciais em HTTP`,
      steps: [
        `1. Teste focado: Inspecionar action do formulário.`,
        `2. PROVA REAL: Exibir o atributo action exato retornado no HTML.`,
      ],
      devtools: `F12 → Elements → verificar action no form.`,
      automated: `curl -sk "${url}" | grep -i "action"`,
      proofOfWork: `curl -sk "${url}" | grep -oE 'action="[^"]*"'`,
    };
  },

  session_fixation: (f) => ({
    title: `Validação & Prova Real para Session Fixation`,
    steps: [
      `1. Teste focado: Comparar o cookie antes e depois de logar.`,
      `2. PROVA REAL: Enviar o cookie anônimo no cabeçalho Cookie: e verificar se a sessão autenticada é mantida sob o mesmo identificador.`,
    ],
    devtools: `F12 → Application → Cookies (anotar antes e depois).`,
    automated: `Comparar cookies de sessão antes e depois do login.`,
  }),

  // ════════════════════════════════════════════════════
  // FORMULÁRIOS
  // ════════════════════════════════════════════════════

  form_no_csrf: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para CSRF em Formulário`,
      steps: [
        `1. Teste focado: Buscar tokens ocultos no formulário.`,
        `2. PROVA REAL: Tentar submeter o formulário via POST sem enviar token/cookie CSRF e verificar se o servidor aceita a ação (HTTP 200/302).`,
      ],
      devtools: `F12 → Elements → inspecionar o formulário.`,
      automated: `curl -sk "${url}" | grep -iE "csrf|_token|nonce"`,
      proofOfWork: `curl -sk "${url}" | grep -n -C 5 -i "<form"`,
    };
  },

  // ════════════════════════════════════════════════════
  // REDE / MISCELÂNEA
  // ════════════════════════════════════════════════════

  mixed_content: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Mixed Content`,
      steps: [
        `1. Teste focado: Buscar tags com src/href usando http:// em página HTTPS.`,
        `2. PROVA REAL: Listar todas as URLs de recursos externos e filtrar apenas as que usam o esquema http://.`,
      ],
      devtools: `F12 → Console → filtro "Mixed Content".`,
      automated: `curl -sk "${url}" | grep -oE 'src="http://[^"]+"|href="http://[^"]+"'`,
      proofOfWork: `curl -sk "${url}" | grep -n -E 'http://'`,
    };
  },

  login_token_in_url: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Token na URL`,
      steps: [
        `1. Teste focado: Buscar query string com parâmetros sensíveis.`,
        `2. PROVA REAL: Inspecionar os cabeçalhos de redirecionamento (Location/Referer).`,
      ],
      devtools: `F12 → Network → verificar URL do GET pós-login.`,
      automated: `curl -skD - "${url}" -o /dev/null | grep -iE "location|referer"`,
    };
  },

  missing_security_txt: (f, targetUrl) => {
    const cleanUrl = sanitizeUrl(f.url, targetUrl);
    let origin = 'https://10.4.0.20:8443';
    try { origin = new URL(cleanUrl).origin; } catch { /* ignore */ }
    return {
      title: `Validação & Prova Real para security.txt`,
      steps: [
        `1. Teste focado: Requisitar /.well-known/security.txt.`,
        `2. PROVA REAL: Verificar se o status é 404/403 e se a resposta não contém as chaves "Contact:" ou "Expires:".`,
      ],
      devtools: `Navegar até /.well-known/security.txt`,
      automated: `curl -skD - "${origin}/.well-known/security.txt" -o /dev/null`,
      proofOfWork: `curl -sk "${origin}/.well-known/security.txt" | head -n 10`,
      online: `https://securitytxt.org/`,
    };
  },

  idor: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para IDOR`,
      steps: [
        `1. Teste focado: Substituir o ID na rota pelo ID de outro usuário.`,
        `2. PROVA REAL: Fazer a requisição com o token/cookie da Conta B acessando os dados da Conta A e comparar os hashes do payload retornado.`,
      ],
      devtools: `F12 → Network → re-executar requisição trocando ID.`,
      automated: `curl -sk -H "Cookie: SESSION_USUARIO_B" "${url}"`,
    };
  },

  open_redirect: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Open Redirect`,
      steps: [
        `1. Teste focado: Injetar URL externa no parâmetro.`,
        `2. PROVA REAL: Exibir o header Location retornado pelo servidor confirmando o redirecionamento para o domínio externo.`,
      ],
      devtools: `F12 → Network → checar Location header.`,
      automated: `curl -skD - "${url}?next=https://evil.com" -o /dev/null | grep -i "location"`,
      proofOfWork: `curl -skD - "${url}?redirect=https://example.com" -o /dev/null | grep -i "location"`,
    };
  },

  backup_file: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Arquivo de Backup Exposto`,
      steps: [
        `1. Teste focado: Checar se o arquivo .bak/.old responde com HTTP 200.`,
        `2. PROVA REAL: Baixar o arquivo (primeiros 50 bytes) e verificar o número de linhas ou tipo de arquivo.`,
      ],
      devtools: `Acessar URL do arquivo de backup.`,
      automated: `curl -skD - "${url}" -o /dev/null`,
      proofOfWork: `curl -sk "${url}" | head -c 100`,
    };
  },

  http_method: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Métodos HTTP Inseguros`,
      steps: [
        `1. Teste focado: Testar se o método responde 200 OK.`,
        `2. PROVA REAL: Executar o método TRACE/OPTIONS e exibir os métodos permitidos retornados no header \`Allow:\`.`,
      ],
      devtools: `F12 → Console → fetch com método customizado.`,
      automated: `curl -skD - -X ${f.method || 'TRACE'} "${url}" -o /dev/null`,
      proofOfWork: `curl -skD - -X OPTIONS "${url}" -o /dev/null | grep -i "allow"`,
    };
  },

  // ════════════════════════════════════════════════════
  // CONSOLE / JS
  // ════════════════════════════════════════════════════

  console_error: (f) => ({
    title: `Validação & Prova Real para Erros JS`,
    steps: [
      `1. Teste focado: Inspecionar o console.`,
      `2. PROVA REAL: Abrir a aba Console do DevTools e filtrar por "Errors".`,
    ],
    devtools: `F12 → Console → filtro "Errors".`,
  }),

  // ════════════════════════════════════════════════════
  // BIBLIOTECAS VULNERÁVEIS
  // ════════════════════════════════════════════════════

  vulnerable_library: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Biblioteca Vulnerável`,
      steps: [
        `1. Teste focado: Consultar a versão no Console.`,
        `2. PROVA REAL: Extrair a versão diretamente do cabeçalho do arquivo .js carregado na aba Sources.`,
      ],
      devtools: `F12 → Console → verificar versão.`,
      automated: `curl -sk "${url}" | grep -oP "${f.library || 'jquery'}\\/[0-9]+\\.[0-9]+\\.[0-9]+"`,
      online: `https://snyk.io/vuln/?q=${encodeURIComponent(f.library || '')}`,
    };
  },

  // ════════════════════════════════════════════════════
  // GENÉRICO
  // ════════════════════════════════════════════════════

  browser_issue: (f) => ({
    title: `Validação & Prova Real para Issue do Navegador`,
    steps: [
      `1. Teste focado: Checar no DevTools ▸ Issues.`,
      `2. PROVA REAL: Inspecionar a aba Issues no F12 para ver a diretiva violada.`,
    ],
    devtools: `F12 → Issues → localizar "${f.code || f.label}".`,
  }),
};

// ── Fallback genérico ───────────────────────────────────────

const GENERIC_VERIFICATION = (f, targetUrl) => {
  const url = sanitizeUrl(f.url, targetUrl);
  return {
    title: `Validação & Prova Real: ${f.label || f.type}`,
    steps: [
      `1. Teste focado: ${f.type}`,
      `2. PROVA REAL: ${f.risk || 'Inspecionar na página auditada'}`,
    ],
    devtools: `F12 → verificar conforme a descrição.`,
    automated: url ? `curl -skD - "${url}" -o /dev/null` : null,
    proofOfWork: url ? `curl -skD - "${url}" -o /dev/null` : null,
  };
};

VERIFICATION_MAP['login_no_csrf'] = VERIFICATION_MAP['login_no_csrf'] || VERIFICATION_MAP['form_no_csrf'];
VERIFICATION_MAP['api_exposed']   = VERIFICATION_MAP['swagger_exposed'];
VERIFICATION_MAP['cors_any']      = VERIFICATION_MAP['cors_wildcard'];

export function getManualVerification(finding, targetUrl = '') {
  const generator = VERIFICATION_MAP[finding.type];
  if (generator) {
    try { return generator(finding, targetUrl); } catch { /* fallback */ }
  }
  return GENERIC_VERIFICATION(finding, targetUrl);
}

export function enrichWithVerification(findings, targetUrl = '') {
  return findings.map(f => ({
    ...f,
    manualVerification: getManualVerification(f, targetUrl),
  }));
}
