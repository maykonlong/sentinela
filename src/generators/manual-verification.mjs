/**
 * Manual Verification Generator — Instruções "Como Verificar Manualmente"
 *
 * Para cada tipo de achado, gera instruções passo-a-passo detalhadas de como
 * um profissional/empresa pode confirmar o problema sem depender do Sentinela.
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
      `Abrir terminal e executar o comando abaixo (substitua a URL se necessário).`,
      `Se o header "${f.header}" NÃO aparecer na saída, o problema está confirmado.`,
      `Se aparecer, o header já foi adicionado — problema corrigido.`,
      `Verifique também em HTTPS e em outras páginas do site (pode variar por rota).`,
    ],
    devtools: `F12 → Network → clique no documento principal (primeira linha) → aba "Headers" → seção "Response Headers" → procurar "${f.header}".`,
    automated: `curl -sI "${f.url || 'https://SEU-SITE.com'}" | grep -i "${f.header}"`,
    online: `https://securityheaders.com/?q=${encodeURIComponent(f.url || '')}&followRedirects=on`,
  }),

  weak_security_header: (f) => ({
    title: `Confirmar valor inadequado do header "${f.header}"`,
    steps: [
      `Executar o comando abaixo para ver o valor atual do header.`,
      `Valor atual encontrado: "${f.currentValue || '(não capturado)'}"`,
      `Comparar com a configuração recomendada (descrita na correção acima).`,
      `Após corrigir no servidor, re-executar o comando para confirmar.`,
    ],
    devtools: `F12 → Network → clique no documento → Headers → Response Headers → localizar "${f.header}" → anotar o valor.`,
    automated: `curl -sI "${f.url || 'https://SEU-SITE.com'}" | grep -i "${f.header}"`,
    online: `https://securityheaders.com/?q=${encodeURIComponent(f.url || '')}`,
  }),

  information_disclosure_header: (f) => ({
    title: `Confirmar exposição de informação no header "${f.header}"`,
    steps: [
      `Executar o comando abaixo e verificar o valor retornado no header "${f.header}".`,
      `Se o header revelar tecnologia, versão ou framework (ex: "nginx/1.18.0", "PHP/8.1"), está confirmado.`,
      `Após remover/obscurecer no servidor, re-executar para confirmar que sumiu.`,
    ],
    devtools: `F12 → Network → documento principal → Headers → Response Headers → verificar "${f.header}".`,
    automated: `curl -sI "${f.url || 'https://SEU-SITE.com'}" | grep -iE "server|x-powered|x-generator|x-aspnet"`,
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
      `Se alguma coluna estiver vazia/desmarcada, o problema está confirmado.`,
    ],
    devtools: `F12 → Application → Storage → Cookies → ${f.domain || 'domínio'} → linha "${f.cookieName}".`,
    automated: `curl -sI "${f.url || 'https://SEU-SITE.com'}" | grep -i "Set-Cookie.*${f.cookieName}"`,
  }),

  cookie_sensitive_no_httponly: (f) => ({
    title: `Confirmar que cookie sensível "${f.cookieName}" está sem HttpOnly`,
    steps: [
      `F12 → Application → Cookies → localizar "${f.cookieName}".`,
      `Verificar coluna "HttpOnly" — se estiver desmarcada, está confirmado.`,
      `Testar via console: digite abaixo no Console do DevTools. Se retornar o valor, está acessível a JS (problema confirmado).`,
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
      `Alternativa: digitar o comando abaixo no Console do DevTools.`,
    ],
    devtools: `F12 → Application → ${f.storage || 'Local Storage'} → localizar chave "${f.key}".`,
    automated: `${f.storage === 'sessionStorage' ? 'sessionStorage' : 'localStorage'}.getItem("${f.key}")`,
  }),

  storage_jwt_exposed: (f) => ({
    title: `Confirmar JWT exposto no ${f.storage || 'localStorage'}`,
    steps: [
      `F12 → Application → ${f.storage || 'Local Storage'} → localizar chave "${f.key}".`,
      `Copiar o valor (começa com "eyJ...").`,
      `Colar em https://jwt.io — o payload será decodificado sem precisar da chave secreta.`,
      `Verificar se o payload contém dados sensíveis (id, role, email, permissões).`,
      `Um atacante com XSS pode roubar esse token com uma linha de JS.`,
    ],
    devtools: `F12 → Application → ${f.storage || 'Local Storage'} → "${f.key}" → copiar valor → colar em jwt.io.`,
    automated: `JSON.stringify(JSON.parse(atob(localStorage.getItem("${f.key}").split('.')[1])))`,
    online: `https://jwt.io`,
  }),

  // ════════════════════════════════════════════════════
  // CÓDIGO-FONTE
  // ════════════════════════════════════════════════════

  exposed_key: (f) => ({
    title: `Confirmar segredo/chave de API exposto no código`,
    steps: [
      `Abrir o arquivo: ${f.url || '(URL não capturada)'}.`,
      `F12 → Sources → localizar o arquivo na árvore de arquivos.`,
      `Usar Ctrl+F para buscar por: ${(f.match || '').substring(0, 30)}`,
      `Verificar se é uma chave real (não placeholder como "YOUR_API_KEY").`,
      `Se for real, revogar a chave imediatamente e gerar uma nova.`,
    ],
    devtools: `F12 → Sources → Ctrl+Shift+F (busca global) → digitar parte da chave encontrada.`,
    automated: `curl -s "${f.url || ''}" | grep -oE "[A-Za-z0-9_\\-]{20,}"`,
  }),

  dangerous_code: (f) => ({
    title: `Confirmar uso de "${f.match || 'código perigoso'}" sem sanitização`,
    steps: [
      `Abrir o arquivo: ${f.url || '?'}`,
      `F12 → Sources → Ctrl+F → buscar "${f.match || 'innerHTML'}"`,
      `Verificar qual variável/valor é passado para o ${f.match || 'innerHTML'}.`,
      `Verificar se essa variável vem de input do usuário (req.body, URL params, API response).`,
      `Se sim, o problema está confirmado — XSS é possível.`,
    ],
    devtools: `F12 → Sources → Ctrl+Shift+F → buscar "${f.match || 'innerHTML'}" → verificar contexto.`,
    automated: `curl -s "${f.url || ''}" | grep -n "${f.match || 'innerHTML'}"`,
  }),

  missing_sri: (f) => ({
    title: `Confirmar ausência de SRI no script externo`,
    steps: [
      `Abrir o código-fonte da página: Ctrl+U (ou F12 → Elements).`,
      `Buscar pela tag: <script src="${f.src || f.url || '?'}">`,
      `Verificar se tem atributo integrity="sha256-..." ou integrity="sha384-..."`,
      `Se não tiver o atributo integrity, está confirmado.`,
      `Gerar o hash SRI em: https://www.srihash.org/`,
    ],
    devtools: `F12 → Elements → Ctrl+F → buscar "${(f.src || '').substring(0, 30)}" → verificar atributo integrity.`,
    online: `https://www.srihash.org/`,
  }),

  global_variable_sensitive: (f) => ({
    title: `Confirmar dado sensível em variável global JS`,
    steps: [
      `Abrir a página no navegador.`,
      `F12 → Console → digitar o nome da variável e pressionar Enter.`,
      `Se retornar um objeto com dados sensíveis (token, email, role), está confirmado.`,
    ],
    devtools: `F12 → Console → digitar: ${f.variable || 'window.userData'} → pressionar Enter.`,
    automated: `${f.variable || 'JSON.stringify(window.__state)'}`,
  }),

  frontend_role_definition: (f) => ({
    title: `Confirmar definição de roles/permissões no frontend`,
    steps: [
      `F12 → Sources → Ctrl+Shift+F → buscar por "admin", "role", "permission", "canAccess".`,
      `Verificar se as permissões são definidas/lidas do localStorage ou código JS.`,
      `Tentar alterar o valor no Console: ${f.variable || 'window.userRole'} = "admin" e recarregar.`,
      `Se o acesso mudar sem nova autenticação, as permissões são baseadas apenas no frontend.`,
    ],
    devtools: `F12 → Console → tentar: localStorage.setItem("role", "admin") → recarregar → verificar acesso.`,
  }),

  // ════════════════════════════════════════════════════
  // TLS / CERTIFICADO
  // ════════════════════════════════════════════════════

  weak_tls: (f) => ({
    title: `Confirmar protocolo TLS inseguro`,
    steps: [
      `Clicar no cadeado na barra do navegador → "Connection is secure" → "Certificate" → verificar "TLS version".`,
      `Ou usar o SSL Labs (ferramenta online) — avalia o servidor inteiro.`,
      `Ou executar o comando abaixo: se conectar com --tlsv1.0, TLS 1.0 está habilitado (deve ser recusado).`,
    ],
    devtools: `F12 → Security → "Connection" → verificar versão do protocolo TLS.`,
    automated: `curl -v --tlsv1.0 --tls-max 1.0 "${f.url || 'https://SEU-SITE.com'}" 2>&1 | grep "SSL connection"`,
    online: `https://www.ssllabs.com/ssltest/analyze.html?d=${hostname(f)}`,
  }),

  cert_expired: (f) => ({
    title: `Confirmar certificado TLS expirado`,
    steps: [
      `Clicar no cadeado na barra do navegador.`,
      `Ir em "Connection is secure" → "Certificate" → verificar "Valid until".`,
      `Ou executar o comando abaixo — "notAfter" mostrará a data de expiração da porta ${hostAndPort(f)}.`,
    ],
    devtools: `F12 → Security → "View certificate" → verificar "Valid until".`,
    automated: `echo | openssl s_client -connect ${hostAndPort(f)} 2>/dev/null | openssl x509 -enddate -noout`,
    online: `https://www.sslshopper.com/ssl-checker.html#hostname=${hostname(f)}`,
  }),

  cert_expiring: (f) => ({
    title: `Confirmar que o certificado TLS vence em breve`,
    steps: [
      `Clicar no cadeado → "Certificate" → verificar a data "Valid until".`,
      `Ou executar o comando abaixo apontando para o servidor/porta ${hostAndPort(f)}.`,
      `Configurar renovação automática (certbot renew --dry-run para testar).`,
    ],
    devtools: `F12 → Security → "View certificate" → verificar "Valid until".`,
    automated: `echo | openssl s_client -connect ${hostAndPort(f)} 2>/dev/null | openssl x509 -enddate -noout`,
  }),

  no_https: (f) => ({
    title: `Confirmar que o site serve HTTPS`,
    steps: [
      `Acessar a versão HTTP do site: http://${hostname(f)}`,
      `Verificar se é redirecionado automaticamente para https://.`,
      `Se não redirecionar, o problema está confirmado.`,
      `Verificar também se o HSTS está configurado (header Strict-Transport-Security).`,
    ],
    devtools: `F12 → Network → acessar http://${hostname(f)} → verificar se há um redirect 301/302 para https.`,
    automated: `curl -sI "http://${hostname(f)}" | grep -i "location\\|strict"`,
  }),

  // ════════════════════════════════════════════════════
  // PORTAS TCP
  // ════════════════════════════════════════════════════

  exposed_port: (f) => {
    const host = f.host || hostname(f);
    return {
      title: `Confirmar porta ${f.port} (${f.service}) aberta`,
      steps: [
        `Executar o comando abaixo a partir de uma máquina FORA da rede interna (ex: seu celular 4G ou VPS externo).`,
        `Se retornar "succeeded" ou se conectar, a porta está exposta externamente — confirmado.`,
        `Se retornar "Connection refused" ou timeout, a porta está fechada/filtrada — OK.`,
        `Verifique também no painel de firewall do servidor qual regra permite esse acesso.`,
        `Para PostgreSQL (5432): verifique postgresql.conf → listen_addresses (deve ser "localhost", não "*").`,
        `Para Redis (6379): verifique redis.conf → bind (deve ser "127.0.0.1").`,
      ],
      devtools: `Não aplicável — verificação de porta é feita via terminal ou ferramenta de port scan.`,
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
      `Executar o comando abaixo — envia uma requisição com Origin de um site malicioso.`,
      `Se Access-Control-Allow-Origin: * aparecer na resposta, está confirmado.`,
      `Se retornar o domínio específico do solicitante (reflete a origin), também é problemático.`,
      `Apenas origens explicitamente whitelistadas devem ser aceitas.`,
    ],
    devtools: `F12 → Console → fetch("${f.url || 'https://SEU-SITE.com/api'}", {headers: {Origin: "https://evil.com"}}).then(r => r.headers.get("Access-Control-Allow-Origin")).then(console.log)`,
    automated: `curl -sI -H "Origin: https://evil.com" "${f.url || 'https://SEU-SITE.com'}" | grep -i "access-control"`,
  }),

  cors_credentials: (f) => ({
    title: `Confirmar CORS com credentials e wildcard`,
    steps: [
      `Executar o comando abaixo com a origin de um site externo.`,
      `Se retornar Access-Control-Allow-Credentials: true junto com Allow-Origin *, está confirmado.`,
      `Essa combinação permite que um site externo faça requisições autenticadas em nome do usuário.`,
    ],
    devtools: `F12 → Network → requisição da API → Response Headers → verificar "Access-Control-Allow-Credentials" e "Access-Control-Allow-Origin".`,
    automated: `curl -sI -H "Origin: https://evil.com" "${f.url || 'https://SEU-SITE.com/api'}" | grep -i "access-control"`,
  }),

  // ════════════════════════════════════════════════════
  // RECON / EXPOSIÇÃO
  // ════════════════════════════════════════════════════

  swagger_exposed: (f) => ({
    title: `Confirmar que o Swagger/OpenAPI está público`,
    steps: [
      `Acessar as URLs abaixo em modo anônimo (aba InPrivate/Incognito — sem estar logado).`,
      `Se a página de documentação abrir sem pedir login, está confirmado.`,
      `Uma API pública expõe todos os endpoints, parâmetros e modelos para qualquer pessoa.`,
    ],
    devtools: `Abrir aba InPrivate → acessar: ${f.url || '/api/docs, /swagger, /swagger-ui, /api/swagger.json'}`,
    automated: `curl -sI "${f.url || 'https://SEU-SITE.com/api/docs'}" | grep "200\\|301\\|302"`,
  }),

  graphql_exposed: (f) => ({
    title: `Confirmar que o endpoint GraphQL está público`,
    steps: [
      `Executar o comando abaixo (introspection query).`,
      `Se retornar um JSON com "__schema" e a lista de tipos, está confirmado.`,
      `Introspection pública entrega toda a estrutura da API para um atacante.`,
    ],
    devtools: `F12 → Console → fetch("${f.url || '/graphql'}", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({query:"{__schema{types{name}}}"})}).then(r=>r.json()).then(console.log)`,
    automated: `curl -X POST -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}' "${f.url || 'https://SEU-SITE.com/graphql'}"`,
  }),

  robots_sensitive_paths: (f) => ({
    title: `Confirmar paths sensíveis expostos no robots.txt`,
    steps: [
      `Acessar: ${f.url || 'https://SEU-SITE.com/robots.txt'}`,
      `Verificar se há entradas "Disallow:" com caminhos administrativos ou sensíveis.`,
      `Tentar acessar esses caminhos diretamente no navegador (sem login).`,
      `Paradoxo do robots.txt: o que tenta esconder, lista publicamente para qualquer crawler.`,
    ],
    devtools: `Abrir aba InPrivate → acessar cada path Disallow: listado no robots.txt.`,
    automated: `curl -s "${f.url || 'https://SEU-SITE.com/robots.txt'}"`,
  }),

  error_verbose: (f) => ({
    title: `Confirmar que erros expõem informações internas`,
    steps: [
      `Tentar acessar uma URL que não existe (ex: /pagina-que-nao-existe-12345).`,
      `Ou tentar causar um erro intencional (URL malformada, parâmetro inválido).`,
      `Verificar se a resposta de erro mostra: stack trace, versão do framework, nomes de arquivos internos, queries SQL.`,
      `Se sim, está confirmado.`,
    ],
    devtools: `F12 → Network → requisição com erro → Response → verificar o body.`,
    automated: `curl -s "${f.url || 'https://SEU-SITE.com/pagina-invalida-12345'}"`,
  }),

  // ════════════════════════════════════════════════════
  // REPUTAÇÃO / IP
  // ════════════════════════════════════════════════════

  ip_blacklisted: (f) => ({
    title: `Confirmar que o IP está em blacklists`,
    steps: [
      `Acessar o MXToolbox (ferramenta online).`,
      `Inserir o IP: ${f.ip || '?'}`,
      `Verificar em quais blacklists o IP aparece.`,
      `Para cada blacklist, seguir o processo de delisting (geralmente um formulário no site da blacklist).`,
    ],
    devtools: `Não aplicável — verificação via terminal ou ferramenta online.`,
    automated: `host ${f.ip ? f.ip.split('.').reverse().join('.') : '?'}.zen.spamhaus.org`,
    online: `https://mxtoolbox.com/blacklists.aspx?q=${f.ip || ''}`,
  }),

  // ════════════════════════════════════════════════════
  // LOGIN / AUTENTICAÇÃO
  // ════════════════════════════════════════════════════

  login_no_csrf: (f) => ({
    title: `Confirmar ausência de CSRF token no formulário de login`,
    steps: [
      `Abrir a página de login.`,
      `F12 → Elements → localizar a tag <form>.`,
      `Procurar por <input type="hidden"> com name contendo "csrf", "_token", "authenticity_token", "nonce".`,
      `Se não existir nenhum campo oculto anti-CSRF, está confirmado.`,
      `Verificar também se o backend valida o header "X-Requested-With" ou um token duplo no cookie.`,
    ],
    devtools: `F12 → Elements → Ctrl+F → buscar "csrf" ou "_token" ou "hidden".`,
    automated: `curl -s "${f.url || 'https://SEU-SITE.com/login'}" | grep -i "csrf\\|_token\\|authenticity"`,
  }),

  login_form_get: (f) => ({
    title: `Confirmar que o formulário de login usa GET (inseguro)`,
    steps: [
      `Abrir a página de login.`,
      `F12 → Elements → localizar a tag <form>.`,
      `Verificar o atributo method — deve ser "post". Se for "get" ou ausente, está confirmado.`,
      `Login via GET expõe a senha na URL (visível no histórico, logs, Referer header).`,
    ],
    devtools: `F12 → Elements → buscar "<form" → verificar atributo method.`,
    automated: `curl -s "${f.url || 'https://SEU-SITE.com/login'}" | grep -i "<form"`,
  }),

  login_credentials_http: (f) => ({
    title: `Confirmar que credenciais são enviadas por HTTP (não HTTPS)`,
    steps: [
      `F12 → Network → fazer login na página.`,
      `Localizar a requisição POST de login.`,
      `Verificar se a URL começa com "http://" (sem S).`,
      `Verificar também o atributo action do formulário no HTML.`,
    ],
    devtools: `F12 → Network → fazer login → localizar POST → verificar URL (deve ser https://).`,
    automated: `curl -s "${f.url || 'https://SEU-SITE.com/login'}" | grep -i "action"`,
  }),

  session_fixation: (f) => ({
    title: `Confirmar session fixation (sessão não regenerada após login)`,
    steps: [
      `Abrir a página de login SEM estar logado.`,
      `F12 → Application → Cookies → anotar o valor do cookie "${f.cookieName || 'session_id'}".`,
      `Fazer o login normalmente.`,
      `F12 → Application → Cookies → verificar o valor do mesmo cookie.`,
      `Se o valor for EXATAMENTE O MESMO antes e depois do login, há session fixation — confirmado.`,
      `O valor DEVE mudar após login para invalidar a sessão anônima.`,
    ],
    devtools: `F12 → Application → Cookies → anotar "${f.cookieName || 'session'}" antes e depois do login.`,
    automated: `Comparar: curl -c antes.txt "${f.url || 'https://SEU-SITE.com/login'}" && curl -b antes.txt -c depois.txt -d "user=...&pass=..." "${f.url || 'https://SEU-SITE.com/login'}" && diff <(grep session antes.txt) <(grep session depois.txt)`,
  }),

  // ════════════════════════════════════════════════════
  // FORMULÁRIOS
  // ════════════════════════════════════════════════════

  form_no_csrf: (f) => ({
    title: `Confirmar ausência de CSRF token no formulário`,
    steps: [
      `Abrir DevTools → Elements → localizar o formulário suspeito.`,
      `Buscar por <input type="hidden"> com atributos name contendo "csrf", "_token", "nonce".`,
      `Se não existir, o formulário está sem proteção CSRF.`,
      `Verificar também se o backend valida um header custom (X-CSRF-Token, X-Requested-With).`,
    ],
    devtools: `F12 → Elements → Ctrl+F → buscar "csrf" → verificar inputs hidden.`,
    automated: `curl -s "${f.url || 'https://SEU-SITE.com'}" | grep -iE "csrf|_token|nonce"`,
  }),

  // ════════════════════════════════════════════════════
  // REDE / MISCELÂNEA
  // ════════════════════════════════════════════════════

  mixed_content: (f) => ({
    title: `Confirmar Mixed Content (recursos HTTP em página HTTPS)`,
    steps: [
      `Abrir a página HTTPS no Chrome/Edge.`,
      `F12 → Console → verificar mensagens amarelas/vermelhas "Mixed Content" ou "Blocked loading mixed-content".`,
      `F12 → Network → filtrar por "mixed-content" no seletor de tipo.`,
      `Identificar quais recursos (imagens, scripts, iframes) estão sendo carregados por HTTP.`,
    ],
    devtools: `F12 → Console → filtrar por "Mixed Content" → ou Network → filtrar tipo.`,
    automated: `curl -s "${f.url || 'https://SEU-SITE.com'}" | grep -oE 'src="http://[^"]+"|href="http://[^"]+"'`,
  }),

  login_token_in_url: (f) => ({
    title: `Confirmar token/código sensível exposto na URL`,
    steps: [
      `F12 → Network → localizar a requisição com a URL suspeita.`,
      `Verificar se a query string contém parâmetros como token=, access_token=, code=, session_id=.`,
      `Verificar também o Referer header das requisições subsequentes — pode vazar o token.`,
      `Verificar o histórico do navegador — token fica salvo.`,
    ],
    devtools: `F12 → Network → filtrar por URL com "token" ou "code" → verificar Request URL.`,
    automated: `curl -sI "${f.url || ''}" | grep -i "location\\|referer"`,
  }),

  missing_security_txt: (f) => ({
    title: `Confirmar ausência do security.txt`,
    steps: [
      `Acessar as URLs abaixo no navegador.`,
      `Se retornar 404 ou página de erro, o security.txt não existe — confirmado.`,
      `O security.txt deve conter: email de contato para reportar vulnerabilidades, política de disclosure.`,
    ],
    devtools: `Abrir: ${f.url ? new URL(f.url).origin : 'https://SEU-SITE.com'}/.well-known/security.txt`,
    automated: `curl -sI "${f.url ? new URL(f.url).origin : 'https://SEU-SITE.com'}/.well-known/security.txt"`,
    online: `https://securitytxt.org/`,
  }),

  idor: (f) => ({
    title: `Confirmar IDOR (acesso a recurso de outro usuário)`,
    steps: [
      `Fazer login com o Usuário A.`,
      `Acessar um recurso próprio: ${f.url || '/api/recurso/123'}`,
      `Anotar o ID numérico na URL ou no body da resposta.`,
      `Fazer login com o Usuário B (outra conta).`,
      `Tentar acessar o mesmo ID do Usuário A: substituir o número na URL.`,
      `Se o Usuário B conseguir ver/editar dados do Usuário A, IDOR está confirmado.`,
    ],
    devtools: `F12 → Network → localizar requisições com IDs numéricos → copiar URL → testar com outro usuário.`,
    automated: `curl -H "Cookie: SESSION_DO_USUARIO_B" "${f.url || 'https://SEU-SITE.com/api/recurso/ID_DO_USUARIO_A'}"`,
  }),

  open_redirect: (f) => ({
    title: `Confirmar Open Redirect`,
    steps: [
      `Executar o comando abaixo — tenta redirecionar para evil.com via parâmetro de redirect.`,
      `Se o Location header apontar para evil.com, está confirmado.`,
      `Um atacante usa isso para criar links phishing que parecem legítimos (domínio do site real, mas redireciona).`,
    ],
    devtools: `F12 → Network → verificar Location header na resposta de redirect.`,
    automated: `curl -sI "${(f.url || 'https://SEU-SITE.com') + '?next=https://evil.com'}" | grep -i "location"`,
  }),

  backup_file: (f) => ({
    title: `Confirmar arquivo de backup/fonte exposto`,
    steps: [
      `Acessar a URL abaixo no navegador em modo anônimo (sem login).`,
      `Se o arquivo baixar ou mostrar conteúdo, está confirmado.`,
      `Arquivos .bak, .old, .orig, .zip, ~arquivo podem conter código-fonte ou configurações.`,
    ],
    devtools: `Abrir aba InPrivate → acessar: ${f.url || 'URL do arquivo'}`,
    automated: `curl -sI "${f.url || 'https://SEU-SITE.com/arquivo.bak'}" | grep "200\\|Content-Length"`,
  }),

  http_method: (f) => ({
    title: `Confirmar método HTTP ${f.method || 'inseguro'} habilitado`,
    steps: [
      `Executar o comando abaixo — testa se o método ${f.method || 'TRACE/PUT/DELETE'} está habilitado.`,
      `Se retornar 200 ou 405 (Method Not Allowed é OK), verificar a resposta.`,
      `TRACE habilitado permite ataques XST (Cross-Site Tracing).`,
      `PUT habilitado pode permitir upload de arquivos maliciosos.`,
    ],
    devtools: `F12 → Console → fetch("${f.url || 'https://SEU-SITE.com'}", {method: "${f.method || 'TRACE'}"}).then(r => console.log(r.status))`,
    automated: `curl -sI -X ${f.method || 'TRACE'} "${f.url || 'https://SEU-SITE.com'}" | grep "HTTP/"`,
  }),

  // ════════════════════════════════════════════════════
  // CONSOLE / JS
  // ════════════════════════════════════════════════════

  console_error: (f) => ({
    title: `Confirmar erros de JavaScript no console`,
    steps: [
      `Abrir a página.`,
      `F12 → Console → filtrar por "Errors" (ícone de filtro no topo).`,
      `Verificar mensagens em vermelho.`,
      `Clicar em cada erro para ver o stack trace e o arquivo/linha responsável.`,
    ],
    devtools: `F12 → Console → botão "Errors" no filtro de nível.`,
  }),

  // ════════════════════════════════════════════════════
  // BIBLIOTECAS VULNERÁVEIS
  // ════════════════════════════════════════════════════

  vulnerable_library: (f) => ({
    title: `Confirmar versão vulnerável da biblioteca ${f.library || '?'}`,
    steps: [
      `F12 → Console → digitar: ${f.library || 'jQuery'}.fn.jquery ou ${f.library || 'biblioteca'}.version`,
      `Comparar a versão com a versão corrigida: ${f.fixedIn || '(consultar changelog)'}`,
      `Verificar os CVEs listados em: https://snyk.io/vuln/?q=${encodeURIComponent(f.library || '')}`,
    ],
    devtools: `F12 → Console → digitar "${f.library || 'jQuery'}.version" → comparar com versão corrigida.`,
    automated: `curl -s "${f.url || ''}" | grep -oP "${f.library || 'jquery'}\\/[0-9]+\\.[0-9]+\\.[0-9]+"`,
    online: `https://snyk.io/vuln/?q=${encodeURIComponent(f.library || '')}`,
  }),

  // ════════════════════════════════════════════════════
  // GENÉRICO (browser issues e achados sem tipo específico)
  // ════════════════════════════════════════════════════

  browser_issue: (f) => ({
    title: `Confirmar: ${f.label || f.code || 'issue do navegador'}`,
    steps: [
      `F12 → aba "Issues" (ao lado de Elements/Console).`,
      `Localizar o issue: "${f.label || f.code}".`,
      `Clicar no issue para ver detalhes, elemento afetado e link para documentação.`,
      f.currentValue ? `Evidência capturada: ${f.currentValue}` : null,
    ].filter(Boolean),
    devtools: `F12 → Issues (aba) → localizar "${f.code || f.label}".`,
  }),
};

// ── Fallback genérico ultra-detalhado ────────────────────────

const GENERIC_VERIFICATION = (f) => ({
  title: `Verificar: ${f.label || f.type}`,
  steps: [
    `Tipo de achado: ${f.type}`,
    `Descrição: ${f.risk || '(ver acima)'}`,
    f.url ? `URL afetada: ${f.url}` : `Verificar na página auditada.`,
    `Abrir DevTools (F12) e procurar evidências conforme a descrição do achado.`,
    f.recommendation ? `Correção: ${f.recommendation}` : null,
  ].filter(Boolean),
  devtools: `F12 → verificar conforme a descrição: ${f.label || f.type}`,
  automated: f.url ? `curl -sI "${f.url}"` : null,
});

// ── Aliases de tipos ──────────────────────────────────────────
VERIFICATION_MAP['login_no_csrf'] = VERIFICATION_MAP['login_no_csrf'] || VERIFICATION_MAP['form_no_csrf'];
VERIFICATION_MAP['api_exposed']   = VERIFICATION_MAP['swagger_exposed'];
VERIFICATION_MAP['cors_any']      = VERIFICATION_MAP['cors_wildcard'];

/**
 * Gera instrução de verificação manual para um finding.
 * @param {object} finding - Achado do Sentinela
 * @returns {object} Instruções { title, steps[], devtools, automated?, online? }
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
