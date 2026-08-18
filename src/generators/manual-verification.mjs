/**
 * Manual Verification Generator — Instruções "Como Verificar Manualmente"
 *
 * Para cada tipo de achado, gera instruções passo-a-passo detalhadas de como
 * um profissional/empresa pode confirmar o problema sem depender do Sentinela.
 *
 * Princípios de Resiliência Universal:
 *  1. `curl -skD - "$URL" -o /dev/null` para headers:
 *     - `-k`: ignora erros de SSL/certificados auto-assinados ou IPs
 *     - `-s`: modo silencioso sem barra de progresso
 *     - `-D -`: imprime os Response Headers no stdout
 *     - `-o /dev/null`: descarta o corpo (evita poluição no terminal)
 *     - Usa GET por padrão (evita erros 405 Method Not Allowed do HEAD/curl -I em servidores como Caddy/FastAPI/Express)
 *  2. `curl -sk "$URL"` para inspeção de conteúdo/HTML/código
 *  3. `hostAndPort(f)` preserva a porta real do serviço (ex: :8443, :8080)
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
    title: `Confirmar ausência do header "${f.header}"`,
    steps: [
      `Abrir o terminal e executar o comando abaixo.`,
      `Se o header "${f.header}" NÃO aparecer na saída, a ausência está confirmada.`,
      `Se o header aparecer, ele já foi configurado — problema corrigido.`,
      `Nota: O comando faz uma requisição GET real enviando os cabeçalhos diretamente para stdout.`,
    ],
    devtools: `F12 → Network → clique na requisição do documento (primeira linha) → aba "Headers" → seção "Response Headers" → procurar "${f.header}".`,
    automated: `curl -skD - "${f.url || 'https://SEU-SITE.com'}" -o /dev/null | grep -i "${f.header}"`,
    online: `https://securityheaders.com/?q=${encodeURIComponent(f.url || '')}&followRedirects=on`,
  }),

  weak_security_header: (f) => ({
    title: `Confirmar valor inadequado do header "${f.header}"`,
    steps: [
      `Executar o comando abaixo para ver o valor atual retornado pelo servidor.`,
      `Valor atual capturado: "${f.currentValue || '(não informado)'}"`,
      `Comparar com a configuração recomendada na seção de correção do relatório.`,
    ],
    devtools: `F12 → Network → clique no documento → Headers → Response Headers → localizar "${f.header}".`,
    automated: `curl -skD - "${f.url || 'https://SEU-SITE.com'}" -o /dev/null | grep -i "${f.header}"`,
    online: `https://securityheaders.com/?q=${encodeURIComponent(f.url || '')}`,
  }),

  information_disclosure_header: (f) => ({
    title: `Confirmar exposição de informação no header "${f.header}"`,
    steps: [
      `Executar o comando abaixo e verificar a resposta do servidor.`,
      `Se o header revelar tecnologia ou versão (ex: "nginx/1.18.0", "PHP/8.1", "Caddy"), está confirmado.`,
    ],
    devtools: `F12 → Network → documento principal → Headers → Response Headers → verificar "${f.header}".`,
    automated: `curl -skD - "${f.url || 'https://SEU-SITE.com'}" -o /dev/null | grep -iE "server|x-powered|x-generator|via|x-aspnet"`,
  }),

  // ════════════════════════════════════════════════════
  // COOKIES
  // ════════════════════════════════════════════════════

  cookie_insecure_flags: (f) => ({
    title: `Confirmar flags inseguras no cookie "${f.cookieName}"`,
    steps: [
      `Abrir o navegador na página autenticada do site.`,
      `F12 → Application → Cookies → selecionar o domínio na lateral.`,
      `Localizar o cookie "${f.cookieName}" na tabela.`,
      `Verificar as colunas: "HttpOnly" (deve estar ✓), "Secure" (deve estar ✓), "SameSite" (deve ser Lax ou Strict).`,
    ],
    devtools: `F12 → Application → Storage → Cookies → ${f.domain || 'domínio'} → linha "${f.cookieName}".`,
    automated: `curl -skD - "${f.url || 'https://SEU-SITE.com'}" -o /dev/null | grep -i "Set-Cookie.*${f.cookieName}"`,
  }),

  cookie_sensitive_no_httponly: (f) => ({
    title: `Confirmar que cookie sensível "${f.cookieName}" está sem HttpOnly`,
    steps: [
      `F12 → Application → Cookies → localizar "${f.cookieName}".`,
      `Verificar a coluna "HttpOnly" — se estiver desmarcada, o cookie pode ser lido por JavaScript (vulnerável a roubo via XSS).`,
      `Testar via Console digitando o comando abaixo.`,
    ],
    devtools: `F12 → Application → Cookies → "${f.cookieName}" → coluna HttpOnly.`,
    automated: `document.cookie.includes("${f.cookieName}")`,
  }),

  // ════════════════════════════════════════════════════
  // STORAGE
  // ════════════════════════════════════════════════════

  storage_sensitive_data: (f) => ({
    title: `Confirmar dado sensível no ${f.storage || 'localStorage'}`,
    steps: [
      `Abrir a página autenticada do site.`,
      `F12 → Application → ${f.storage || 'Local Storage'} → selecionar o domínio.`,
      `Localizar a chave "${f.key}" na tabela.`,
      `Verificar se o valor contém email, senha, token, CPF ou outros dados sensíveis.`,
    ],
    devtools: `F12 → Application → ${f.storage || 'Local Storage'} → localizar chave "${f.key}".`,
    automated: `${f.storage === 'sessionStorage' ? 'sessionStorage' : 'localStorage'}.getItem("${f.key}")`,
  }),

  storage_jwt_exposed: (f) => ({
    title: `Confirmar JWT exposto no ${f.storage || 'localStorage'}`,
    steps: [
      `F12 → Application → ${f.storage || 'Local Storage'} → localizar chave "${f.key}".`,
      `Copiar o valor do token e colar em https://jwt.io para decodificar.`,
      `Verificar se o payload contém dados sensíveis sem criptografia.`,
    ],
    devtools: `F12 → Application → ${f.storage || 'Local Storage'} → "${f.key}" → decodificar em jwt.io.`,
    automated: `JSON.stringify(JSON.parse(atob(localStorage.getItem("${f.key}").split('.')[1])))`,
    online: `https://jwt.io`,
  }),

  // ════════════════════════════════════════════════════
  // CÓDIGO-FONTE
  // ════════════════════════════════════════════════════

  exposed_key: (f) => ({
    title: `Confirmar segredo/chave de API exposto no código`,
    steps: [
      `Abrir o arquivo: ${f.url || '(URL)'}.`,
      `F12 → Sources → localizar o arquivo.`,
      `Usar Ctrl+F para buscar por: ${(f.match || '').substring(0, 30)}`,
      `Verificar se é uma chave real.`,
    ],
    devtools: `F12 → Sources → Ctrl+Shift+F → buscar chave.`,
    automated: `curl -sk "${f.url || ''}" | grep -oE "[A-Za-z0-9_\\-]{20,}"`,
  }),

  dangerous_code: (f) => ({
    title: `Confirmar uso de "${f.match || 'código perigoso'}" sem sanitização`,
    steps: [
      `Abrir o arquivo: ${f.url || '?'}`,
      `F12 → Sources → Ctrl+F → buscar "${f.match || 'innerHTML'}"`,
      `Verificar se a variável atribuída vem de entrada do usuário ou API externa sem sanitização.`,
    ],
    devtools: `F12 → Sources → Ctrl+Shift+F → buscar "${f.match || 'innerHTML'}"`,
    automated: `curl -sk "${f.url || ''}" | grep -n "${f.match || 'innerHTML'}"`,
  }),

  missing_sri: (f) => ({
    title: `Confirmar ausência de SRI no script externo`,
    steps: [
      `Abrir o código-fonte da página: Ctrl+U (ou F12 → Elements).`,
      `Buscar pela tag: <script src="${f.src || f.url || '?'}">`,
      `Verificar se possui o atributo integrity="sha256-..."`,
    ],
    devtools: `F12 → Elements → Ctrl+F → buscar "${(f.src || '').substring(0, 30)}"`,
    online: `https://www.srihash.org/`,
  }),

  global_variable_sensitive: (f) => ({
    title: `Confirmar dado sensível em variável global JS`,
    steps: [
      `F12 → Console → digitar o nome da variável e pressionar Enter.`,
      `Se retornar dados sensíveis, está confirmado.`,
    ],
    devtools: `F12 → Console → digitar: ${f.variable || 'window.userData'}`,
    automated: `${f.variable || 'JSON.stringify(window.__state)'}`,
  }),

  frontend_role_definition: (f) => ({
    title: `Confirmar definição de roles/permissões no frontend`,
    steps: [
      `F12 → Sources → Ctrl+Shift+F → buscar por "admin", "role", "permission".`,
      `Verificar se o controle de acesso é baseado apenas no cliente.`,
    ],
    devtools: `F12 → Console → testar alteração de permissão local.`,
  }),

  // ════════════════════════════════════════════════════
  // TLS / CERTIFICADO
  // ════════════════════════════════════════════════════

  weak_tls: (f) => ({
    title: `Confirmar protocolo TLS inseguro`,
    steps: [
      `Clicar no cadeado no navegador → "Connection is secure" → "Certificate".`,
      `Ou executar o comando abaixo apontando para o servidor e porta real.`,
    ],
    devtools: `F12 → Security → verificar versão TLS.`,
    automated: `curl -v --tlsv1.0 --tls-max 1.0 "${f.url || 'https://SEU-SITE.com'}" 2>&1 | grep "SSL connection"`,
    online: `https://www.ssllabs.com/ssltest/analyze.html?d=${hostname(f)}`,
  }),

  cert_expired: (f) => ({
    title: `Confirmar certificado TLS expirado`,
    steps: [
      `Clicar no cadeado na barra do navegador ➔ "Certificate" ➔ "Valid until".`,
      `Ou executar o comando abaixo conectando na porta real do serviço (${hostAndPort(f)}).`,
    ],
    devtools: `F12 → Security → "View certificate".`,
    automated: `echo | openssl s_client -connect ${hostAndPort(f)} 2>/dev/null | openssl x509 -enddate -noout`,
    online: `https://www.sslshopper.com/ssl-checker.html#hostname=${hostname(f)}`,
  }),

  cert_expiring: (f) => ({
    title: `Confirmar que o certificado TLS vence em breve`,
    steps: [
      `Clicar no cadeado ➔ "Certificate" ➔ verificar a data "Valid until".`,
      `Ou executar o comando abaixo conectando na porta real do serviço (${hostAndPort(f)}).`,
    ],
    devtools: `F12 → Security → "View certificate".`,
    automated: `echo | openssl s_client -connect ${hostAndPort(f)} 2>/dev/null | openssl x509 -enddate -noout`,
  }),

  no_https: (f) => ({
    title: `Confirmar se o site redireciona para HTTPS`,
    steps: [
      `Acessar a versão HTTP do site: http://${hostname(f)}`,
      `Verificar se ocorre o redirecionamento automático (301/302) para HTTPS.`,
    ],
    devtools: `F12 → Network → acessar http://${hostname(f)} → verificar status 301/302.`,
    automated: `curl -skD - "http://${hostname(f)}" -o /dev/null | grep -iE "location|strict"`,
  }),

  // ════════════════════════════════════════════════════
  // PORTAS TCP
  // ════════════════════════════════════════════════════

  exposed_port: (f) => {
    const host = f.host || hostname(f);
    return {
      title: `Confirmar porta ${f.port} (${f.service}) aberta`,
      steps: [
        `Executar o comando de verificação de porta via terminal.`,
        `Se retornar "succeeded" ou conectar, a porta está exposta — confirmado.`,
        `Se der "Connection refused" ou timeout, a porta está fechada/filtrada.`,
      ],
      devtools: `Não aplicável — verificação via terminal ou netcat/nmap.`,
      automated: `nc -zv ${host} ${f.port} 2>&1`,
      online: `https://www.yougetsignal.com/tools/open-ports/ (inserir IP ${host} e porta ${f.port})`,
    };
  },

  // ════════════════════════════════════════════════════
  // CORS
  // ════════════════════════════════════════════════════

  cors_wildcard: (f) => ({
    title: `Confirmar CORS com wildcard (*)`,
    steps: [
      `Executar o comando abaixo enviando um cabeçalho Origin malicioso.`,
      `Verificar se a resposta contém Access-Control-Allow-Origin: *.`,
    ],
    devtools: `F12 → Network → requisição da API → Response Headers → verificar CORS.`,
    automated: `curl -skD - -H "Origin: https://evil.com" "${f.url || 'https://SEU-SITE.com'}" -o /dev/null | grep -i "access-control"`,
  }),

  cors_credentials: (f) => ({
    title: `Confirmar CORS com credentials e wildcard`,
    steps: [
      `Executar o comando enviando Origin customizado.`,
      `Verificar se o servidor retorna Access-Control-Allow-Credentials: true.`,
    ],
    devtools: `F12 → Network → Response Headers → verificar Access-Control-Allow-Credentials.`,
    automated: `curl -skD - -H "Origin: https://evil.com" "${f.url || 'https://SEU-SITE.com'}" -o /dev/null | grep -i "access-control"`,
  }),

  // ════════════════════════════════════════════════════
  // RECON / EXPOSIÇÃO
  // ════════════════════════════════════════════════════

  swagger_exposed: (f) => ({
    title: `Confirmar que o Swagger/OpenAPI está público`,
    steps: [
      `Acessar a URL em modo anônimo (InPrivate/Incognito).`,
      `Se abrir sem pedir autenticação, está confirmado.`,
    ],
    devtools: `Navegador em aba InPrivate → acessar: ${f.url || '/openapi.json'}`,
    automated: `curl -skD - "${f.url || 'https://SEU-SITE.com/openapi.json'}" -o /dev/null | head -n 5`,
  }),

  graphql_exposed: (f) => ({
    title: `Confirmar que o endpoint GraphQL está público`,
    steps: [
      `Executar o teste de Introspection GraphQL abaixo.`,
    ],
    devtools: `F12 → Console → testar consulta introspection.`,
    automated: `curl -sk -X POST -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}' "${f.url || 'https://SEU-SITE.com/graphql'}"`,
  }),

  robots_sensitive_paths: (f) => ({
    title: `Confirmar paths sensíveis expostos no robots.txt`,
    steps: [
      `Acessar a URL do robots.txt.`,
    ],
    devtools: `Acessar ${f.url || 'https://SEU-SITE.com/robots.txt'} no navegador.`,
    automated: `curl -sk "${f.url || 'https://SEU-SITE.com/robots.txt'}"`,
  }),

  error_verbose: (f) => ({
    title: `Confirmar que erros expõem informações internas`,
    steps: [
      `Causar um erro intencional acessando uma URL inexistente.`,
    ],
    devtools: `F12 → Network → requisição com erro → Response.`,
    automated: `curl -sk "${f.url || 'https://SEU-SITE.com/pagina-inexistente-12345'}"`,
  }),

  // ════════════════════════════════════════════════════
  // REPUTAÇÃO / IP
  // ════════════════════════════════════════════════════

  ip_blacklisted: (f) => ({
    title: `Confirmar que o IP está em blacklists`,
    steps: [
      `Acessar o MXToolbox para checar o IP: ${f.ip || '?'}`,
    ],
    devtools: `Não aplicável — verificação via ferramenta online.`,
    automated: `host ${f.ip ? f.ip.split('.').reverse().join('.') : '?'}.zen.spamhaus.org`,
    online: `https://mxtoolbox.com/blacklists.aspx?q=${f.ip || ''}`,
  }),

  // ════════════════════════════════════════════════════
  // LOGIN / AUTENTICAÇÃO
  // ════════════════════════════════════════════════════

  login_no_csrf: (f) => ({
    title: `Confirmar ausência de CSRF token no formulário de login`,
    steps: [
      `Abrir o formulário de login e inspecionar o código HTML.`,
    ],
    devtools: `F12 → Elements → buscar por "csrf" ou "_token" na tag <form>.`,
    automated: `curl -sk "${f.url || 'https://SEU-SITE.com/login'}" | grep -iE "csrf|_token|nonce"`,
  }),

  login_form_get: (f) => ({
    title: `Confirmar que o formulário de login usa GET (inseguro)`,
    steps: [
      `Verificar o atributo method da tag <form>.`,
    ],
    devtools: `F12 → Elements → buscar "<form" → verificar método.`,
    automated: `curl -sk "${f.url || 'https://SEU-SITE.com/login'}" | grep -i "<form"`,
  }),

  login_credentials_http: (f) => ({
    title: `Confirmar envio de credenciais por HTTP`,
    steps: [
      `F12 → Network → verificar ação de envio do login.`,
    ],
    devtools: `F12 → Network → verificar URL do POST.`,
    automated: `curl -sk "${f.url || 'https://SEU-SITE.com/login'}" | grep -i "action"`,
  }),

  session_fixation: (f) => ({
    title: `Confirmar session fixation`,
    steps: [
      `Comparar o valor do cookie de sessão antes e depois do login.`,
    ],
    devtools: `F12 → Application → Cookies → comparar valor do cookie antes/depois do login.`,
    automated: `Comparar cookies de sessão antes e depois do login.`,
  }),

  // ════════════════════════════════════════════════════
  // FORMULÁRIOS
  // ════════════════════════════════════════════════════

  form_no_csrf: (f) => ({
    title: `Confirmar ausência de CSRF token no formulário`,
    steps: [
      `Inspecionar o formulário e verificar os campos ocultos.`,
    ],
    devtools: `F12 → Elements → Ctrl+F → buscar "csrf" ou "_token".`,
    automated: `curl -sk "${f.url || 'https://SEU-SITE.com'}" | grep -iE "csrf|_token|nonce"`,
  }),

  // ════════════════════════════════════════════════════
  // REDE / MISCELÂNEA
  // ════════════════════════════════════════════════════

  mixed_content: (f) => ({
    title: `Confirmar Mixed Content`,
    steps: [
      `Verificar avisos de Mixed Content no console do navegador.`,
    ],
    devtools: `F12 → Console → filtrar por "Mixed Content".`,
    automated: `curl -sk "${f.url || 'https://SEU-SITE.com'}" | grep -oE 'src="http://[^"]+"|href="http://[^"]+"'`,
  }),

  login_token_in_url: (f) => ({
    title: `Confirmar token/código sensível na URL`,
    steps: [
      `Verificar parâmetros da URL durante ou após o login.`,
    ],
    devtools: `F12 → Network → verificar parâmetros da URL.`,
    automated: `curl -skD - "${f.url || ''}" -o /dev/null | grep -iE "location|referer"`,
  }),

  missing_security_txt: (f) => ({
    title: `Confirmar ausência do security.txt`,
    steps: [
      `Acessar a URL /.well-known/security.txt no navegador.`,
    ],
    devtools: `Abrir: ${f.url ? new URL(f.url).origin : 'https://SEU-SITE.com'}/.well-known/security.txt`,
    automated: `curl -skD - "${f.url ? new URL(f.url).origin : 'https://SEU-SITE.com'}/.well-known/security.txt" -o /dev/null`,
    online: `https://securitytxt.org/`,
  }),

  idor: (f) => ({
    title: `Confirmar IDOR`,
    steps: [
      `Trocar o ID na requisição autenticada e verificar se acessa recurso de outro usuário.`,
    ],
    devtools: `F12 → Network → testar troca de ID na URL/parâmetros.`,
    automated: `curl -sk -H "Cookie: SESSION_USUARIO_B" "${f.url || 'https://SEU-SITE.com/api/recurso/ID_USUARIO_A'}"`,
  }),

  open_redirect: (f) => ({
    title: `Confirmar Open Redirect`,
    steps: [
      `Testar parâmetro de redirecionamento para site externo.`,
    ],
    devtools: `F12 → Network → verificar header Location.`,
    automated: `curl -skD - "${(f.url || 'https://SEU-SITE.com') + '?next=https://evil.com'}" -o /dev/null | grep -i "location"`,
  }),

  backup_file: (f) => ({
    title: `Confirmar arquivo de backup exposto`,
    steps: [
      `Acessar a URL do arquivo de backup em modo anônimo.`,
    ],
    devtools: `Abrir em aba InPrivate: ${f.url || 'URL do arquivo'}`,
    automated: `curl -skD - "${f.url || 'https://SEU-SITE.com/arquivo.bak'}" -o /dev/null`,
  }),

  http_method: (f) => ({
    title: `Confirmar método HTTP ${f.method || 'inseguro'} habilitado`,
    steps: [
      `Testar envio do método HTTP especificado.`,
    ],
    devtools: `F12 → Console → fetch com método customizado.`,
    automated: `curl -skD - -X ${f.method || 'TRACE'} "${f.url || 'https://SEU-SITE.com'}" -o /dev/null`,
  }),

  // ════════════════════════════════════════════════════
  // CONSOLE / JS
  // ════════════════════════════════════════════════════

  console_error: (f) => ({
    title: `Confirmar erros de JavaScript no console`,
    steps: [
      `F12 → Console → filtrar por erros em vermelho.`,
    ],
    devtools: `F12 → Console → filtro "Errors".`,
  }),

  // ════════════════════════════════════════════════════
  // BIBLIOTECAS VULNERÁVEIS
  // ════════════════════════════════════════════════════

  vulnerable_library: (f) => ({
    title: `Confirmar versão vulnerável da biblioteca ${f.library || '?'}`,
    steps: [
      `Verificar versão da biblioteca no console ou cabeçalho do código.`,
    ],
    devtools: `F12 → Console → verificar versão.`,
    automated: `curl -sk "${f.url || ''}" | grep -oP "${f.library || 'jquery'}\\/[0-9]+\\.[0-9]+\\.[0-9]+"`,
    online: `https://snyk.io/vuln/?q=${encodeURIComponent(f.library || '')}`,
  }),

  // ════════════════════════════════════════════════════
  // GENÉRICO
  // ════════════════════════════════════════════════════

  browser_issue: (f) => ({
    title: `Confirmar: ${f.label || f.code || 'issue do navegador'}`,
    steps: [
      `F12 → aba "Issues" → verificar detalhes.`,
    ],
    devtools: `F12 → Issues → localizar "${f.code || f.label}".`,
  }),
};

// ── Fallback genérico ───────────────────────────────────────

const GENERIC_VERIFICATION = (f) => ({
  title: `Verificar: ${f.label || f.type}`,
  steps: [
    `Tipo de achado: ${f.type}`,
    `Descrição: ${f.risk || '(ver acima)'}`,
    f.url ? `URL afetada: ${f.url}` : `Verificar na página auditada.`,
  ],
  devtools: `F12 → verificar conforme a descrição.`,
  automated: f.url ? `curl -skD - "${f.url}" -o /dev/null` : null,
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
