/**
 * Manual Verification Generator — Prova Real e Validação Multi-Cenário
 *
 * Para cada achado, gera um plano de validação completo com PROVA REAL:
 *  1. Teste Focado: Busca exatamente a vulnerabilidade.
 *  2. Prova Real (Dump/Baseline): Exibe todos os cabeçalhos/dados para garantir que o resultado não é falso negativo por erro de filtro.
 *  3. DevTools / GUI: Passo a passo visual no navegador.
 *  4. Ferramenta Online / Alternativa: Segunda opinião externa.
 */

function hostname(f) {
  if (f.host) return f.host;
  if (f.url) { try { return new URL(f.url).hostname; } catch { return f.url; } }
  return 'SEU-HOST';
}

function hostAndPort(f, defaultPort = 443) {
  if (f.url) {
    try {
      const u = new URL(f.url);
      const port = u.port || (u.protocol === 'https:' ? '443' : '80');
      return `${u.hostname}:${port}`;
    } catch { /* fallback */ }
  }
  if (f.host) {
    return `${f.host}:${f.port || defaultPort}`;
  }
  return `SEU-HOST:${defaultPort}`;
}

const VERIFICATION_MAP = {

  // ════════════════════════════════════════════════════
  // HEADERS DE SEGURANÇA
  // ════════════════════════════════════════════════════

  missing_security_header: (f) => ({
    title: `Validação & Prova Real para Header "${f.header}"`,
    steps: [
      `1. Teste focado: Execute o comando filtrado. Se não retornar nada, o header está ausente.`,
      `2. PROVA REAL (Dump Completo): Execute o comando sem grep para listar TODOS os cabeçalhos retornados pelo servidor.`,
      `   → Se o comando 2 trouxer cabeçalhos mas o comando 1 não trouxer "${f.header}", a AUSÊNCIA É REAL E CONFIRMADA.`,
      `   → Se o comando 2 der erro ou voltar vazio, há um problema de conexão/firewall (não um erro de header).`,
    ],
    devtools: `F12 → Network → selecionar primeira requisição → Headers → Response Headers (verificar lista completa).`,
    automated: `curl -skD - "${f.url || 'https://SEU-SITE.com'}" -o /dev/null | grep -i "${f.header}"`,
    proofOfWork: `curl -skD - "${f.url || 'https://SEU-SITE.com'}" -o /dev/null`,
    online: `https://securityheaders.com/?q=${encodeURIComponent(f.url || '')}&followRedirects=on`,
  }),

  weak_security_header: (f) => ({
    title: `Validação & Prova Real para Header "${f.header}"`,
    steps: [
      `1. Teste focado: Buscar o header "${f.header}". Valor atual capturado: "${f.currentValue || 'N/A'}"`,
      `2. PROVA REAL: Listar todos os cabeçalhos da resposta para inspecionar a diretiva completa.`,
    ],
    devtools: `F12 → Network → clique no documento → Response Headers → conferir valor de "${f.header}".`,
    automated: `curl -skD - "${f.url || 'https://SEU-SITE.com'}" -o /dev/null | grep -i "${f.header}"`,
    proofOfWork: `curl -skD - "${f.url || 'https://SEU-SITE.com'}" -o /dev/null`,
    online: `https://securityheaders.com/?q=${encodeURIComponent(f.url || '')}`,
  }),

  information_disclosure_header: (f) => ({
    title: `Validação & Prova Real para Exposição em Header "${f.header}"`,
    steps: [
      `1. Teste focado: Buscar assinaturas de servidor e tecnologia.`,
      `2. PROVA REAL: Listar todos os cabeçalhos para verificar se há vazamentos secundários (X-Powered-By, Server, Via).`,
    ],
    devtools: `F12 → Network → Response Headers → inspecionar campos de servidor.`,
    automated: `curl -skD - "${f.url || 'https://SEU-SITE.com'}" -o /dev/null | grep -iE "server|x-powered|x-generator|via|x-aspnet"`,
    proofOfWork: `curl -skD - "${f.url || 'https://SEU-SITE.com'}" -o /dev/null`,
  }),

  // ════════════════════════════════════════════════════
  // COOKIES
  // ════════════════════════════════════════════════════

  cookie_insecure_flags: (f) => ({
    title: `Validação & Prova Real para Cookie "${f.cookieName}"`,
    steps: [
      `1. Teste focado (HTTP): Filtrar o header Set-Cookie específico no terminal.`,
      `2. PROVA REAL (Navegador): Abrir F12 → Application → Cookies e inspecionar visualmente as colunas HttpOnly, Secure e SameSite.`,
    ],
    devtools: `F12 → Application → Storage → Cookies → ${f.domain || 'domínio'} → linha "${f.cookieName}".`,
    automated: `curl -skD - "${f.url || 'https://SEU-SITE.com'}" -o /dev/null | grep -i "Set-Cookie.*${f.cookieName}"`,
    proofOfWork: `curl -skD - "${f.url || 'https://SEU-SITE.com'}" -o /dev/null | grep -i "Set-Cookie"`,
  }),

  cookie_sensitive_no_httponly: (f) => ({
    title: `Validação & Prova Real para HttpOnly no Cookie "${f.cookieName}"`,
    steps: [
      `1. Teste via Console: Executar \`document.cookie\` no Console do navegador.`,
      `   → PROVA REAL: Se o cookie "${f.cookieName}" aparecer na string impressa, ele NÃO TEM HttpOnly (Vulnerável).`,
      `   → Se não aparecer, o cookie está protegido com HttpOnly.`,
    ],
    devtools: `F12 → Console → digitar "document.cookie" → Enter.`,
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
    devtools: `F12 → Application → ${f.storage || 'Local Storage'} → copiar token e colar em jwt.io.`,
    automated: `JSON.parse(atob(localStorage.getItem("${f.key}").split('.')[1]))`,
    proofOfWork: `console.log(JSON.parse(atob(localStorage.getItem("${f.key}").split('.')[1])))`,
    online: `https://jwt.io`,
  }),

  // ════════════════════════════════════════════════════
  // CÓDIGO-FONTE
  // ════════════════════════════════════════════════════

  exposed_key: (f) => ({
    title: `Validação & Prova Real para Segredo no Código`,
    steps: [
      `1. Teste focado: Baixar o script e buscar o padrão.`,
      `2. PROVA REAL: Abrir o arquivo no DevTools (Sources) e verificar o contexto da linha.`,
    ],
    devtools: `F12 → Sources → Ctrl+Shift+F → buscar o trecho da chave.`,
    automated: `curl -sk "${f.url || ''}" | grep -oE "[A-Za-z0-9_\\-]{20,}"`,
    proofOfWork: `curl -sk "${f.url || ''}" | grep -n -C 3 -oE "[A-Za-z0-9_\\-]{20,}"`,
  }),

  dangerous_code: (f) => ({
    title: `Validação & Prova Real para "${f.match || 'innerHTML'}"`,
    steps: [
      `1. Teste focado: Localizar o uso de ${f.match || 'innerHTML'} no arquivo ${f.url || 'JS'}.`,
      `2. PROVA REAL: Exibir as linhas com contexto (-C 3) para validar a falta de sanitização antes da atribuição.`,
    ],
    devtools: `F12 → Sources → Ctrl+Shift+F → buscar "${f.match || 'innerHTML'}".`,
    automated: `curl -sk "${f.url || ''}" | grep -n "${f.match || 'innerHTML'}"`,
    proofOfWork: `curl -sk "${f.url || ''}" | grep -n -C 3 "${f.match || 'innerHTML'}"`,
  }),

  missing_sri: (f) => ({
    title: `Validação & Prova Real para SRI`,
    steps: [
      `1. Teste focado: Buscar a tag script no HTML.`,
      `2. PROVA REAL: Imprimir todas as tags script externas e verificar quais possuem o atributo \`integrity\`.`,
    ],
    devtools: `F12 → Elements → Ctrl+F → buscar o arquivo script.`,
    automated: `curl -sk "${f.url || ''}" | grep -i "${f.src || 'script'}"`,
    proofOfWork: `curl -sk "${f.url || ''}" | grep -iE "<script"`,
    online: `https://www.srihash.org/`,
  }),

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

  weak_tls: (f) => ({
    title: `Validação & Prova Real para Protocolo TLS`,
    steps: [
      `1. Teste focado: Forçar handshake TLS 1.0.`,
      `2. PROVA REAL: Conectar e exibir todos os ciphers suportados pelo servidor.`,
    ],
    devtools: `F12 → Security → aba Connection.`,
    automated: `curl -v --tlsv1.0 --tls-max 1.0 "${f.url || 'https://SEU-SITE.com'}" 2>&1 | grep "SSL connection"`,
    proofOfWork: `echo | openssl s_client -connect ${hostAndPort(f)} -tls1 2>&1`,
    online: `https://www.ssllabs.com/ssltest/analyze.html?d=${hostname(f)}`,
  }),

  cert_expired: (f) => ({
    title: `Validação & Prova Real para Certificado Expirado`,
    steps: [
      `1. Teste focado: Verificar data de expiração na porta real (${hostAndPort(f)}).`,
      `2. PROVA REAL: Dump completo dos detalhes e emissor do certificado x509.`,
    ],
    devtools: `F12 → Security → View certificate.`,
    automated: `echo | openssl s_client -connect ${hostAndPort(f)} 2>/dev/null | openssl x509 -enddate -noout`,
    proofOfWork: `echo | openssl s_client -connect ${hostAndPort(f)} 2>/dev/null | openssl x509 -text -noout | grep -E "Not Before|Not After|Issuer|Subject"`,
    online: `https://www.sslshopper.com/ssl-checker.html#hostname=${hostname(f)}`,
  }),

  cert_expiring: (f) => ({
    title: `Validação & Prova Real para Vencimento de Certificado`,
    steps: [
      `1. Teste focado: Consultar notAfter na porta real (${hostAndPort(f)}).`,
      `2. PROVA REAL: Exibir o período completo de validade (Not Before e Not After).`,
    ],
    devtools: `F12 → Security → View certificate.`,
    automated: `echo | openssl s_client -connect ${hostAndPort(f)} 2>/dev/null | openssl x509 -enddate -noout`,
    proofOfWork: `echo | openssl s_client -connect ${hostAndPort(f)} 2>/dev/null | openssl x509 -dates -noout`,
  }),

  no_https: (f) => ({
    title: `Validação & Prova Real para Redirecionamento HTTPS`,
    steps: [
      `1. Teste focado: Verificar header Location na requisição HTTP.`,
      `2. PROVA REAL: Fazer requisição completa seguindo redirects (-L) e observar a cadeia de status codes.`,
    ],
    devtools: `F12 → Network → acessar HTTP → verificar status 301/302.`,
    automated: `curl -skD - "http://${hostname(f)}" -o /dev/null | grep -iE "location|strict"`,
    proofOfWork: `curl -skD - -L "http://${hostname(f)}" -o /dev/null`,
  }),

  // ════════════════════════════════════════════════════
  // PORTAS TCP
  // ════════════════════════════════════════════════════

  exposed_port: (f) => {
    const host = f.host || hostname(f);
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

  cors_wildcard: (f) => ({
    title: `Validação & Prova Real para CORS Wildcard`,
    steps: [
      `1. Teste focado: Enviar Origin "https://evil.com".`,
      `2. PROVA REAL: Enviar preflight OPTIONS request e verificar se autoriza métodos e origens arbitrárias.`,
    ],
    devtools: `F12 → Console → testar fetch cross-origin.`,
    automated: `curl -skD - -H "Origin: https://evil.com" "${f.url || 'https://SEU-SITE.com'}" -o /dev/null | grep -i "access-control"`,
    proofOfWork: `curl -skD - -X OPTIONS -H "Origin: https://evil.com" -H "Access-Control-Request-Method: POST" "${f.url || 'https://SEU-SITE.com'}" -o /dev/null`,
  }),

  cors_credentials: (f) => ({
    title: `Validação & Prova Real para CORS Credentials`,
    steps: [
      `1. Teste focado: Checar se ACAO reflete a Origin e ACAC é true.`,
      `2. PROVA REAL: Dump completo dos cabeçalhos Access-Control-*.`,
    ],
    devtools: `F12 → Network → Response Headers.`,
    automated: `curl -skD - -H "Origin: https://evil.com" "${f.url || 'https://SEU-SITE.com'}" -o /dev/null | grep -i "access-control"`,
    proofOfWork: `curl -skD - -H "Origin: https://evil.com" "${f.url || 'https://SEU-SITE.com'}" -o /dev/null | grep -iE "access-control-allow-origin|access-control-allow-credentials"`,
  }),

  // ════════════════════════════════════════════════════
  // RECON / EXPOSIÇÃO
  // ════════════════════════════════════════════════════

  swagger_exposed: (f) => ({
    title: `Validação & Prova Real para OpenAPI/Swagger Público`,
    steps: [
      `1. Teste focado: Verificar status HTTP 200 do JSON de documentação.`,
      `2. PROVA REAL: Baixar o arquivo JSON e validar se contém a chave "paths" com os endpoints expostos.`,
    ],
    devtools: `Janela InPrivate → acessar a URL sem login.`,
    automated: `curl -skD - "${f.url || 'https://SEU-SITE.com/openapi.json'}" -o /dev/null | head -n 5`,
    proofOfWork: `curl -sk "${f.url || 'https://SEU-SITE.com/openapi.json'}" | grep -o '"paths":{[^}]*' | head -c 200`,
  }),

  graphql_exposed: (f) => ({
    title: `Validação & Prova Real para GraphQL Introspection`,
    steps: [
      `1. Teste focado: Executar query de __schema.`,
      `2. PROVA REAL: Imprimir o catálogo de tipos retornado pela API.`,
    ],
    devtools: `F12 → Console → testar query GraphQL.`,
    automated: `curl -sk -X POST -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}' "${f.url || 'https://SEU-SITE.com/graphql'}"`,
    proofOfWork: `curl -sk -X POST -H "Content-Type: application/json" -d '{"query":"{__schema{queryType{name}mutationType{name}}}"}' "${f.url || 'https://SEU-SITE.com/graphql'}"`,
  }),

  robots_sensitive_paths: (f) => ({
    title: `Validação & Prova Real para robots.txt`,
    steps: [
      `1. Teste focado: Baixar robots.txt.`,
      `2. PROVA REAL: Exibir todas as linhas "Disallow:" e testar o acesso HTTP em cada uma delas.`,
    ],
    devtools: `Acessar robots.txt no navegador.`,
    automated: `curl -sk "${f.url || 'https://SEU-SITE.com/robots.txt'}"`,
    proofOfWork: `curl -sk "${f.url || 'https://SEU-SITE.com/robots.txt'}" | grep -i "Disallow:"`,
  }),

  error_verbose: (f) => ({
    title: `Validação & Prova Real para Erro Verboso`,
    steps: [
      `1. Teste focado: Requisitar rota inexistente.`,
      `2. PROVA REAL: Exibir o corpo da resposta e buscar por assinaturas de stack trace (at / Exception / Traceback / Line).`,
    ],
    devtools: `F12 → Network → Response do erro.`,
    automated: `curl -sk "${f.url || 'https://SEU-SITE.com/pagina-inexistente-12345'}"`,
    proofOfWork: `curl -sk "${f.url || 'https://SEU-SITE.com/pagina-inexistente-12345'}" | grep -iE "exception|stacktrace|traceback|line [0-9]+"`,
  }),

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

  login_no_csrf: (f) => ({
    title: `Validação & Prova Real para CSRF no Login`,
    steps: [
      `1. Teste focado: Buscar tags <input> ocultas no formulário.`,
      `2. PROVA REAL: Inspecionar o HTML completo da tag <form> até seu fechamento </form>.`,
    ],
    devtools: `F12 → Elements → buscar <form>.`,
    automated: `curl -sk "${f.url || 'https://SEU-SITE.com/login'}" | grep -iE "csrf|_token|nonce"`,
    proofOfWork: `curl -sk "${f.url || 'https://SEU-SITE.com/login'}" | grep -n -C 5 -i "<form"`,
  }),

  login_form_get: (f) => ({
    title: `Validação & Prova Real para Login via GET`,
    steps: [
      `1. Teste focado: Inspecionar o atributo method.`,
      `2. PROVA REAL: Imprimir a tag <form> da página de login.`,
    ],
    devtools: `F12 → Elements → inspecionar <form>.`,
    automated: `curl -sk "${f.url || 'https://SEU-SITE.com/login'}" | grep -i "<form"`,
    proofOfWork: `curl -sk "${f.url || 'https://SEU-SITE.com/login'}" | grep -oE '<form[^>]*>'`,
  }),

  login_credentials_http: (f) => ({
    title: `Validação & Prova Real para Credenciais em HTTP`,
    steps: [
      `1. Teste focado: Inspecionar action do formulário.`,
      `2. PROVA REAL: Exibir o atributo action exato retornado no HTML.`,
    ],
    devtools: `F12 → Elements → verificar action no form.`,
    automated: `curl -sk "${f.url || 'https://SEU-SITE.com/login'}" | grep -i "action"`,
    proofOfWork: `curl -sk "${f.url || 'https://SEU-SITE.com/login'}" | grep -oE 'action="[^"]*"'`,
  }),

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

  form_no_csrf: (f) => ({
    title: `Validação & Prova Real para CSRF em Formulário`,
    steps: [
      `1. Teste focado: Buscar tokens ocultos no formulário.`,
      `2. PROVA REAL: Tentar submeter o formulário via POST sem enviar token/cookie CSRF e verificar se o servidor aceita a ação (HTTP 200/302).`,
    ],
    devtools: `F12 → Elements → inspecionar o formulário.`,
    automated: `curl -sk "${f.url || 'https://SEU-SITE.com'}" | grep -iE "csrf|_token|nonce"`,
  }),

  // ════════════════════════════════════════════════════
  // REDE / MISCELÂNEA
  // ════════════════════════════════════════════════════

  mixed_content: (f) => ({
    title: `Validação & Prova Real para Mixed Content`,
    steps: [
      `1. Teste focado: Buscar tags com src/href usando http:// em página HTTPS.`,
      `2. PROVA REAL: Listar todas as URLs de recursos externos e filtrar apenas as que usam o esquema http://.`,
    ],
    devtools: `F12 → Console → filtro "Mixed Content".`,
    automated: `curl -sk "${f.url || 'https://SEU-SITE.com'}" | grep -oE 'src="http://[^"]+"|href="http://[^"]+"'`,
    proofOfWork: `curl -sk "${f.url || 'https://SEU-SITE.com'}" | grep -n -E 'http://'`,
  }),

  login_token_in_url: (f) => ({
    title: `Validação & Prova Real para Token na URL`,
    steps: [
      `1. Teste focado: Buscar query string com parâmetros sensíveis.`,
      `2. PROVA REAL: Inspecionar os cabeçalhos de redirecionamento (Location/Referer).`,
    ],
    devtools: `F12 → Network → verificar URL do GET pós-login.`,
    automated: `curl -skD - "${f.url || ''}" -o /dev/null | grep -iE "location|referer"`,
  }),

  missing_security_txt: (f) => ({
    title: `Validação & Prova Real para security.txt`,
    steps: [
      `1. Teste focado: Requisitar /.well-known/security.txt.`,
      `2. PROVA REAL: Verificar se o status é 404/403 e se a resposta não contém as chaves "Contact:" ou "Expires:".`,
    ],
    devtools: `Navegar até /.well-known/security.txt`,
    automated: `curl -skD - "${f.url ? new URL(f.url).origin : 'https://SEU-SITE.com'}/.well-known/security.txt" -o /dev/null`,
    proofOfWork: `curl -sk "${f.url ? new URL(f.url).origin : 'https://SEU-SITE.com'}/.well-known/security.txt" | head -n 10`,
    online: `https://securitytxt.org/`,
  }),

  idor: (f) => ({
    title: `Validação & Prova Real para IDOR`,
    steps: [
      `1. Teste focado: Substituir o ID na rota pelo ID de outro usuário.`,
      `2. PROVA REAL: Fazer a requisição com o token/cookie da Conta B acessando os dados da Conta A e comparar os hashes do payload retornado.`,
    ],
    devtools: `F12 → Network → re-executar requisição trocando ID.`,
    automated: `curl -sk -H "Cookie: SESSION_USUARIO_B" "${f.url || 'https://SEU-SITE.com/api/recurso/ID_USUARIO_A'}"`,
  }),

  open_redirect: (f) => ({
    title: `Validação & Prova Real para Open Redirect`,
    steps: [
      `1. Teste focado: Injetar URL externa no parâmetro.`,
      `2. PROVA REAL: Exibir o header Location retornado pelo servidor confirmando o redirecionamento para o domínio externo.`,
    ],
    devtools: `F12 → Network → checar Location header.`,
    automated: `curl -skD - "${(f.url || 'https://SEU-SITE.com') + '?next=https://evil.com'}" -o /dev/null | grep -i "location"`,
    proofOfWork: `curl -skD - "${(f.url || 'https://SEU-SITE.com') + '?redirect=https://example.com'}" -o /dev/null | grep -i "location"`,
  }),

  backup_file: (f) => ({
    title: `Validação & Prova Real para Arquivo de Backup Exposto`,
    steps: [
      `1. Teste focado: Checar se o arquivo .bak/.old responde com HTTP 200.`,
      `2. PROVA REAL: Baixar o arquivo (primeiros 50 bytes) e verificar o número de linhas ou tipo de arquivo.`,
    ],
    devtools: `Acessar URL do arquivo de backup.`,
    automated: `curl -skD - "${f.url || 'https://SEU-SITE.com/arquivo.bak'}" -o /dev/null`,
    proofOfWork: `curl -sk "${f.url || 'https://SEU-SITE.com/arquivo.bak'}" | head -c 100`,
  }),

  http_method: (f) => ({
    title: `Validação & Prova Real para Métodos HTTP Inseguros`,
    steps: [
      `1. Teste focado: Testar se o método responde 200 OK.`,
      `2. PROVA REAL: Executar o método TRACE/OPTIONS e exibir os métodos permitidos retornados no header \`Allow:\`.`,
    ],
    devtools: `F12 → Console → fetch com método customizado.`,
    automated: `curl -skD - -X ${f.method || 'TRACE'} "${f.url || 'https://SEU-SITE.com'}" -o /dev/null`,
    proofOfWork: `curl -skD - -X OPTIONS "${f.url || 'https://SEU-SITE.com'}" -o /dev/null | grep -i "allow"`,
  }),

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

  vulnerable_library: (f) => ({
    title: `Validação & Prova Real para Biblioteca Vulnerável`,
    steps: [
      `1. Teste focado: Consultar a versão no Console.`,
      `2. PROVA REAL: Extrair a versão diretamente do cabeçalho do arquivo .js carregado na aba Sources.`,
    ],
    devtools: `F12 → Console → verificar versão.`,
    automated: `curl -sk "${f.url || ''}" | grep -oP "${f.library || 'jquery'}\\/[0-9]+\\.[0-9]+\\.[0-9]+"`,
    online: `https://snyk.io/vuln/?q=${encodeURIComponent(f.library || '')}`,
  }),

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

const GENERIC_VERIFICATION = (f) => ({
  title: `Validação & Prova Real: ${f.label || f.type}`,
  steps: [
    `1. Teste focado: ${f.type}`,
    `2. PROVA REAL: ${f.risk || 'Inspecionar na página auditada'}`,
  ],
  devtools: `F12 → verificar conforme a descrição.`,
  automated: f.url ? `curl -skD - "${f.url}" -o /dev/null` : null,
  proofOfWork: f.url ? `curl -skD - "${f.url}" -o /dev/null` : null,
});

VERIFICATION_MAP['login_no_csrf'] = VERIFICATION_MAP['login_no_csrf'] || VERIFICATION_MAP['form_no_csrf'];
VERIFICATION_MAP['api_exposed']   = VERIFICATION_MAP['swagger_exposed'];
VERIFICATION_MAP['cors_any']      = VERIFICATION_MAP['cors_wildcard'];

export function getManualVerification(finding) {
  const generator = VERIFICATION_MAP[finding.type];
  if (generator) {
    try { return generator(finding); } catch { /* fallback */ }
  }
  return GENERIC_VERIFICATION(finding);
}

export function enrichWithVerification(findings) {
  return findings.map(f => ({
    ...f,
    manualVerification: getManualVerification(f),
  }));
}
