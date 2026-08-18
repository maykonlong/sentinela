/**
 * Manual Verification Generator — Prova Real e Validação Multi-Cenário
 *
 * Para cada achado, gera um plano de validação completo com PROVA REAL:
 *  1. Teste Focado: Busca exatamente a vulnerabilidade.
 *  2. Prova Real (Dump/Baseline): Exibe todos os cabeçalhos/dados para garantir que o resultado não é falso negativo por erro de filtro.
 *  3. DevTools / GUI: Passo a passo visual no navegador.
 *  4. Ferramenta Online / Alternativa: Segunda opinião externa.
 */

/**
 * Cookies capturados nas fases LOGIN/PÓS-LOGIN foram criados pelo servidor
 * numa resposta específica (o callback OIDC, o POST de autenticação) — o
 * header Set-Cookie SÓ aparece NAQUELE momento. Repetir curl numa página
 * comum depois NUNCA reproduz o Set-Cookie, ainda que o problema seja real —
 * um usuário testando manualmente (como aconteceu de verdade nesta sessão)
 * vê saída vazia e acha que é falso positivo, quando é só limitação do teste.
 * Esta função gera a ressalva certa e mostra a evidência JÁ CAPTURADA ao vivo
 * (Playwright leu o cookie do navegador de verdade — não precisa reproduzir
 * nada pra confiar nisso).
 */
function cookieCaptureContext(f) {
  // Só se aplica a achado DE COOKIE — checar cookieName evita vazar esse aviso
  // pra achados de localStorage/sessionStorage (login_storage_*), que não têm
  // NENHUMA dessas limitações (dá pra ler o valor a qualquer momento via
  // console, sem depender de repetir o momento exato em que foi criado).
  if (!f.cookieName) return [];
  const lines = [];
  if (f.flags) {
    const { httpOnly, secure, sameSite, expires } = f.flags;
    lines.push(`Capturado AO VIVO no navegador durante a auditoria: httpOnly=${httpOnly}, secure=${secure}, sameSite=${sameSite || '(não definido)'}, expira=${expires || '?'}. Essa é a evidência — não precisa reproduzir nada pra confiar nela.`);
  }
  if (f.phase === 'LOGIN' || f.phase === 'PÓS-LOGIN') {
    lines.push(`ATENÇÃO com o teste via curl abaixo: Set-Cookie só é enviado pelo servidor no instante em que o cookie é CRIADO (aqui, durante o fluxo de login/callback) — repetir a requisição numa página comum depois NUNCA mostra esse Set-Cookie de novo, mesmo com o problema presente. Saída vazia aqui NÃO significa corrigido; é limitação física do teste. Use o DevTools/Console abaixo, que leem o cookie já salvo no navegador autenticado.`);
  }
  return lines;
}

/**
 * Mesmo problema dos cookies, para achados de CORPO de resposta autenticada
 * (token/senha/role no JSON de retorno de um endpoint logado). Um curl
 * anônimo pra essa URL não carrega a sessão — na melhor das hipóteses cai em
 * 401/redirect, na pior devolve uma resposta genérica que parece "corrigido".
 * A evidência de verdade já foi capturada ao vivo pelo Playwright (visível no
 * achado); reproduzir exige a MESMA sessão autenticada, via DevTools → Network
 * (a requisição original está no histórico) ou repetindo a chamada com um
 * header/cookie de sessão válido.
 */
function authenticatedResponseContext(f) {
  // Sem URL não há o que reproduzir via curl — não faz sentido citar
  // "endpoint autenticado" pra um achado sem endpoint algum (ex.: diff de
  // localStorage, que não tem `url`).
  if (!f.url) return [];
  const lines = [];
  const field = f.tokenField || f.field || (Array.isArray(f.fieldsExposed) ? f.fieldsExposed.join(', ') : null);
  if (field) lines.push(`Campo capturado ao vivo na resposta: "${field}".`);
  if (f.phase === 'LOGIN' || f.phase === 'PÓS-LOGIN' || /\/api\//.test(f.url)) {
    lines.push(`ATENÇÃO: esta é uma resposta de endpoint AUTENTICADO. Um curl anônimo (sem cookie/token de sessão) não reproduz o mesmo corpo — costuma cair em 401/redirect, o que NÃO significa que o problema foi corrigido. Para reproduzir de verdade: F12 → Network → repita a ação que chama esse endpoint → aba Response mostra o corpo exato capturado pelo auditor. Alternativa: curl com "-H 'Cookie: <cole sua sessão>'" ou "-H 'Authorization: Bearer <seu token>'".`);
  }
  return lines;
}

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

  duplicate_security_header: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Header "${f.header}" Duplicado`,
      steps: [
        `Evidência já capturada (valores distintos vistos na mesma resposta): ${f.currentValue || '(ver relatório)'}.`,
        `1. Teste focado: liste TODOS os headers da resposta — ao contrário de outros achados, aqui o curl reproduz fielmente, porque ele imprime cada linha de header como recebida (não colapsa duplicatas como o navegador/Playwright fazem internamente).`,
        `2. PROVA REAL: se "${f.header}" aparecer DUAS OU MAIS VEZES no dump abaixo com valores diferentes, o conflito está confirmado — normalmente sinal de duas camadas de proxy/CDN sobrepostas.`,
      ],
      devtools: `F12 → Network → clique no documento → Response Headers (o painel do DevTools também colapsa; use "view source" dos headers se disponível, ou confie no curl acima).`,
      automated: `curl -skD - "${url}" -o /dev/null | grep -ci "^${f.header}:"`,
      proofOfWork: `curl -skD - "${url}" -o /dev/null | grep -i "^${f.header}:"`,
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
        ...cookieCaptureContext(f),
        `1. Teste focado (HTTP): Filtrar o header Set-Cookie específico no terminal (só funciona se você repetir a AÇÃO que cria o cookie, não uma página qualquer).`,
        `2. PROVA REAL (Navegador): Abrir F12 → Application → Cookies e inspecionar visualmente as colunas HttpOnly, Secure e SameSite — funciona a qualquer momento, é a fonte confiável.`,
      ],
      devtools: `F12 → Application → Storage → Cookies → ${f.domain || 'domínio'} → linha "${f.cookieName}".`,
      automated: `curl -skD - "${url}" -o /dev/null | grep -i "Set-Cookie.*${f.cookieName}"`,
      proofOfWork: `curl -skD - "${url}" -o /dev/null | grep -i "Set-Cookie"`,
    };
  },

  cookie_sensitive_no_httponly: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para HttpOnly no Cookie "${f.cookieName}"`,
      steps: [
        ...cookieCaptureContext(f),
        `1. Teste via Console: Abrir F12 → Console (na aba já logada) e cole o snippet fornecido — funciona a qualquer momento, não depende de repetir o login.`,
        `2. PROVA REAL: Se o cookie "${f.cookieName}" for retornado, ele NÃO TEM a proteção HttpOnly (vazio se seguro).`,
      ],
      devtools: `F12 → Application → Cookies → "${f.cookieName}" → coluna HttpOnly.`,
      consoleSnippet: `document.cookie.split('; ').filter(c => c.startsWith('${f.cookieName}='))`,
      automated: `curl -skD - "${url}" -o /dev/null | grep -i "Set-Cookie.*${f.cookieName}"`,
      proofOfWork: `curl -skD - "${url}" -o /dev/null | grep -i "Set-Cookie"`,
    };
  },

  cookie_missing_secure_prefix: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Prefixo de Cookie em "${f.cookieName}"`,
      steps: [
        ...cookieCaptureContext(f),
        `1. Teste focado: ver o Set-Cookie do cookie e confirmar que o NOME não começa com __Host- ou __Secure-.`,
        `2. PROVA REAL: dump completo dos cookies — o browser REJEITA sozinho qualquer __Host-/__Secure- malformado, então a mera presença do prefixo já seria a prova de conformidade; a ausência é o que este achado sinaliza (hardening recomendado, não falha confirmada).`,
      ],
      devtools: `F12 → Application → Cookies → linha "${f.cookieName}" → coluna Name.`,
      automated: `curl -skD - "${url}" -o /dev/null | grep -i "Set-Cookie.*${f.cookieName}"`,
      proofOfWork: `curl -skD - "${url}" -o /dev/null | grep -i "Set-Cookie"`,
    };
  },

  // ════════════════════════════════════════════════════
  // STORAGE
  // ════════════════════════════════════════════════════

  // Diffs de storage capturados durante o login: não têm URL (não são uma
  // requisição, são um snapshot antes/depois) — o teste confiável é reler a
  // chave agora, via console, não tentar reproduzir via curl.
  login_storage_added: (f) => ({
    title: `Validação & Prova Real para Chave "${f.key}" Criada no Login (${f.storage || 'storage'})`,
    steps: [
      `1. Teste via Console: leia a chave "${f.key}" no ${f.storage || 'localStorage'} agora (após logar).`,
      `2. PROVA REAL: capturado ao vivo pela auditoria, valor: ${f.valuePreview || '(ver relatório)'}. Se a chave existir com um valor parecido, confirma o comportamento.`,
    ],
    devtools: `F12 → Application → ${f.storage === 'sessionStorage' ? 'Session Storage' : 'Local Storage'} → linha "${f.key}".`,
    consoleSnippet: `${f.storage === 'sessionStorage' ? 'sessionStorage' : 'localStorage'}.getItem("${f.key}")`,
  }),

  login_storage_changed: (f) => ({
    title: `Validação & Prova Real para Chave "${f.key}" Alterada no Login (${f.storage || 'storage'})`,
    steps: [
      `1. Teste via Console: leia a chave "${f.key}" no ${f.storage || 'localStorage'} agora.`,
      `2. PROVA REAL: capturado ao vivo — antes: ${f.beforePreview || '?'}, depois: ${f.afterPreview || '?'}.`,
    ],
    devtools: `F12 → Application → ${f.storage === 'sessionStorage' ? 'Session Storage' : 'Local Storage'} → linha "${f.key}".`,
    consoleSnippet: `${f.storage === 'sessionStorage' ? 'sessionStorage' : 'localStorage'}.getItem("${f.key}")`,
  }),

  login_storage_removed: (f) => ({
    title: `Validação & Prova Real para Chave "${f.key}" Removida no Login (${f.storage || 'storage'})`,
    steps: [
      `1. Teste via Console: a chave "${f.key}" NÃO deve mais existir no ${f.storage || 'localStorage'} após logar (retorna null).`,
      `2. PROVA REAL: ${f.note || 'capturado ao vivo pela auditoria — a chave existia antes do login e sumiu depois.'}`,
    ],
    devtools: `F12 → Application → ${f.storage === 'sessionStorage' ? 'Session Storage' : 'Local Storage'} → confirmar ausência de "${f.key}".`,
    consoleSnippet: `${f.storage === 'sessionStorage' ? 'sessionStorage' : 'localStorage'}.getItem("${f.key}") === null`,
  }),

  storage_sensitive_data: (f) => ({
    title: `Validação & Prova Real para Dados Sensíveis no ${f.storage || 'localStorage'}`,
    steps: [
      `1. Teste via Console: Abrir F12 → Console e executar o comando abaixo.`,
      `2. PROVA REAL: Imprime a tabela completa de chaves e valores armazenados no navegador.`,
    ],
    devtools: `F12 → Application → ${f.storage || 'Local Storage'} → inspecionar tabela.`,
    consoleSnippet: `console.table(Object.entries(${f.storage === 'sessionStorage' ? 'sessionStorage' : 'localStorage'}))`,
    automated: `${f.storage === 'sessionStorage' ? 'sessionStorage' : 'localStorage'}.getItem("${f.key}")`,
    proofOfWork: `console.table(Object.entries(${f.storage === 'sessionStorage' ? 'sessionStorage' : 'localStorage'}))`,
  }),

  storage_jwt_exposed: (f) => ({
    title: `Validação & Prova Real para JWT no ${f.storage || 'localStorage'}`,
    steps: [
      `1. Teste via Console: Abrir F12 → Console e cole o código para decodificar o token instantaneamente.`,
      `2. PROVA REAL: Exibe os dados internos do usuário (permissões, ID, expiração) extraídos do token sem precisar de senha.`,
    ],
    devtools: `F12 → Application → ${f.storage || 'Local Storage'} → "${f.key}" → copiar token e colar em jwt.io.`,
    consoleSnippet: `JSON.parse(atob((${f.storage === 'sessionStorage' ? 'sessionStorage' : 'localStorage'}.getItem("${f.key}") || '').split('.')[1]))`,
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
        `1. Teste via Console: Abrir F12 → Console e executar o snippet para verificar se scripts externos usam innerHTML sem sanitização.`,
        `2. PROVA REAL (Terminal): Baixar o script estático com cURL e confirmar as linhas exatas onde a atribuição direta a innerHTML ocorre.`,
      ],
      devtools: `F12 → Sources → Ctrl+Shift+F → buscar por "${f.match || 'innerHTML'}".`,
      consoleSnippet: `(() => { const res = []; performance.getEntriesByType('resource').filter(r => r.initiatorType === 'script' || r.name.endsWith('.js')).forEach(s => fetch(s.name).then(r => r.text()).then(t => { if (t.includes('innerHTML')) res.push({ script: s.name, ocorrencias: (t.match(/innerHTML/g) || []).length }); console.table(res); })); return '🔍 Verificando scripts carregados no DOM...'; })()`,
      automated: `curl -sk "${url}" | grep -n "${f.match || 'innerHTML'}"`,
      proofOfWork: `curl -sk "${url}" | grep -n -C 3 "${f.match || 'innerHTML'}"`,
    };
  },

  missing_sri: (f, targetUrl) => {
    // ATENÇÃO ao campo usado: neste achado `f.url` é o SCRIPT (o recurso sem
    // integrity), não a página. Para procurar a tag `<script>` é preciso baixar
    // o HTML da PÁGINA — daí o `f.pageUrl`. Usar `f.url` aqui faria o curl
    // baixar o próprio .js e o grep por "<script" nunca casar, dando a falsa
    // impressão de que o problema não existe.
    const pageUrl = sanitizeUrl(f.pageUrl || targetUrl, targetUrl);
    const scriptUrl = sanitizeUrl(f.url, targetUrl);
    const alvo = f.src || scriptUrl || 'script';
    return {
      title: `Validação & Prova Real para SRI`,
      steps: [
        `1. Teste focado: baixar o HTML da página e procurar a tag do script sem \`integrity\`.`,
        `2. PROVA REAL: listar TODAS as tags <script> da página — se elas aparecem mas nenhuma tem \`integrity\`, a ausência está confirmada.`,
        `   → Se o comando 2 voltar vazio ou der erro, é problema de conexão/URL, não ausência de SRI.`,
      ],
      devtools: `F12 → Elements → Ctrl+F → buscar o arquivo script.`,
      consoleSnippet: `Array.from(document.scripts).filter(s => s.src && !s.integrity).map(s => s.src)`,
      automated: `curl -sk "${pageUrl}" | grep -i "${alvo}"`,
      proofOfWork: `curl -sk "${pageUrl}" | grep -iE "<script"`,
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
    consoleSnippet: `console.dir(window.${f.variable || 'user'})`,
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

  api_docs_exposed: (f, targetUrl) => {
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

  graphql_introspection: (f, targetUrl) => {
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

  robots_disclosure: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para robots.txt`,
      steps: [
        `1. Teste focado: Baixar robots.txt.`,
        `2. PROVA REAL: Exibir todas as linhas "Disallow:" e testar o acesso HTTP em cada uma delas.`,
        f.sample?.length ? `Caminhos sensíveis já identificados: ${f.sample.join(', ')}.` : null,
      ].filter(Boolean),
      devtools: `Acessar robots.txt no navegador.`,
      automated: `curl -sk "${url}"`,
      proofOfWork: `curl -sk "${url}" | grep -i "Disallow:"`,
    };
  },

  verbose_error: (f, targetUrl) => {
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

  login_form_http: (f, targetUrl) => {
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

  no_rate_limit: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Ausência de Rate Limit no Login`,
      steps: [
        `Evidência já capturada: ${f.currentValue || '5 tentativas sequenciais com status/tempo idênticos'}.`,
        `1. Teste focado: repita o comando abaixo 5x seguidas (credenciais inválidas, nunca uma senha real) e compare o status HTTP e o tempo de cada uma.`,
        `2. PROVA REAL: se as 5 respostas tiverem o MESMO status e tempo parecido — sem HTTP 429, sem CAPTCHA, sem atraso crescente — a ausência de rate limit está confirmada. Qualquer uma dessas defesas aparecendo já invalidaria o achado.`,
      ],
      devtools: `F12 → Network → aba Timing, comparando a duração de cada tentativa.`,
      automated: `for i in 1 2 3 4 5; do curl -sk -o /dev/null -w "tentativa $i: HTTP %{http_code} em %{time_total}s\\n" -X POST "${url}" -d "user=teste$i@invalid&pass=errada$i"; done`,
      proofOfWork: `curl -skD - -X POST "${url}" -d "user=teste@invalid&pass=errada" -o /dev/null`,
    };
  },

  user_enumeration: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Enumeração de Usuário no Login`,
      steps: [
        `Evidência já capturada: ${f.currentValue || 'a resposta variou entre dois "usuários" igualmente inexistentes'}.`,
        `1. Teste focado: envie duas tentativas de login com e-mails inexistentes DIFERENTES (nunca um usuário real) e senha errada.`,
        `2. PROVA REAL: se o texto/tamanho/tempo da resposta mudar de forma consistente entre os dois, o sistema revela se o usuário existe (mensagem "não encontrado" vs "senha errada", ou diferença de tempo repetida).`,
      ],
      devtools: `F12 → Network → comparar o corpo da resposta das duas tentativas lado a lado.`,
      automated: `curl -sk -X POST "${url}" -d "user=sentinela-probe-1@test.invalid&pass=errada" ; echo "---" ; curl -sk -X POST "${url}" -d "user=sentinela-probe-2@test.invalid&pass=errada"`,
      proofOfWork: `curl -skD - -X POST "${url}" -d "user=sentinela-probe-1@test.invalid&pass=errada" -o /dev/null`,
    };
  },

  weak_password_policy: () => ({
    title: `Validação & Prova Real para Política de Senha Fraca/Ausente`,
    steps: [
      `1. Teste via Console: rode o snippet para listar os campos de senha e seus atributos (minlength, pattern).`,
      `2. PROVA REAL: se NENHUM campo tiver minlength≥8 nem pattern de complexidade nem texto de requisito próximo, a ausência de pista de política está confirmada NO FRONT-END.`,
      `   → Isso NÃO prova que o backend aceita senha fraca — é uma heurística de UI. Para confirmar de verdade, tente cadastrar/trocar para uma senha como "123456" e veja se o servidor rejeita.`,
    ],
    devtools: `F12 → Elements → inspecionar o <input type="password"> → aba Attributes (minlength, pattern).`,
    consoleSnippet: `Array.from(document.querySelectorAll('input[type="password"]')).map(i => ({ name: i.name || i.id, minlength: i.minLength > 0 ? i.minLength : '(ausente)', pattern: i.pattern || '(ausente)' }))`,
  }),

  idor_confirmed: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para IDOR/BOLA CONFIRMADO (2 contas)`,
      steps: [
        `Evidência já capturada: ${f.currentValue || 'a Conta B acessou com sucesso um objeto que pertence à Conta A'}.`,
        `1. Teste focado: com a sessão da CONTA B (diferente da conta original testada), repita a requisição ao objeto abaixo.`,
        `2. PROVA REAL: se retornar 200 com dado de verdade (não uma tela de erro/login), a Conta B está lendo um objeto que não é dela — IDOR confirmado, exatamente como capturado durante a auditoria.`,
      ],
      devtools: `F12 → Network → repita a requisição logado como Conta B → aba Response.`,
      automated: `curl -sk -H "Cookie: <cole aqui o cookie de sessão da CONTA B>" "${url}"`,
      proofOfWork: `curl -skD - -H "Cookie: <cole aqui o cookie de sessão da CONTA B>" "${url}" -o /dev/null`,
    };
  },

  // ════════════════════════════════════════════════════
  // SOURCE MAP (conteúdo real baixado)
  // ════════════════════════════════════════════════════

  source_map_content_exposed: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Source Map com Código-Fonte Exposto`,
      steps: [
        `1. Teste focado: baixar o .map (é um arquivo estático público — o mesmo comando abaixo já reproduz 100% do que o auditor viu).`,
        `2. PROVA REAL: procurar a chave "sourcesContent" no JSON — se vier preenchida com código legível (não minificado), o vazamento está confirmado.`,
        f.exampleFiles?.length ? `Arquivos de origem revelados: ${f.exampleFiles.slice(0, 5).join(', ')}${f.exampleFiles.length > 5 ? ', …' : ''}.` : null,
      ].filter(Boolean),
      devtools: `F12 → Sources → aba "Page" → procurar pelo arquivo .map (o DevTools já usa ele pra mostrar o código original).`,
      automated: `curl -sk "${url}" | grep -o '"sourcesContent"' | head -1`,
      proofOfWork: `curl -sk "${url}" | head -c 500`,
    };
  },

  source_map_internal_routes: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Rotas Internas Reveladas pelo Source Map`,
      steps: [
        `1. Teste focado: baixar o .map e listar o array "sources" — são os paths de arquivo do build original.`,
        `2. PROVA REAL: ${f.paths?.length ? `paths já identificados como sensíveis: ${f.paths.slice(0, 10).join(', ')}${f.paths.length > 10 ? ', …' : ''}.` : 'procurar paths contendo /api/, /internal/, /admin/ ou /routes/.'}`,
      ],
      devtools: `F12 → Sources → aba "Page" → árvore de arquivos do source map.`,
      automated: `curl -sk "${url}" | grep -oE '"sources":\\[[^]]*\\]' | head -c 500`,
      proofOfWork: `curl -sk "${url}" | head -c 500`,
    };
  },

  session_fixation: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Session Fixation`,
      steps: [
        `1. Teste focado: Capturar o valor do cookie "${f.cookieName}" ANTES de logar (execute o comando 1x), fazer login, e capturar de novo (execute 1x mais).`,
        `2. PROVA REAL: Se o comando 1 e o comando 2 imprimirem o MESMO valor de "${f.cookieName}", a fixação é REAL E CONFIRMADA. O comando de dump completo (sem filtro) confirma que a conexão/resposta está OK caso o filtro volte vazio.`,
        `   → Se o comando 2 (depois de logado) voltar vazio, não assuma que corrigiu: Set-Cookie só reaparece se o servidor REGENERAR o cookie no login — é exatamente isso que o achado testa. O jeito confiável de comparar é anotar o valor no DevTools antes e depois, não repetir curl anônimo.`,
      ],
      devtools: `F12 → Application → Cookies → anotar o valor de "${f.cookieName}" antes e depois do login.`,
      automated: `curl -skD - "${url}" -o /dev/null | grep -i "Set-Cookie.*${f.cookieName}"`,
      proofOfWork: `curl -skD - "${url}" -o /dev/null | grep -i "Set-Cookie"`,
    };
  },

  // ════════════════════════════════════════════════════
  // FORMULÁRIOS
  // ════════════════════════════════════════════════════

  form_no_csrf: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para CSRF em Formulário`,
      steps: [
        `1. Teste via Console: Executar o snippet no Console (F12) para listar os formulários e confirmar se faltam tokens de proteção (anti-CSRF).`,
        `2. PROVA REAL (Terminal): Baixar o HTML da página e buscar por campos ocultos do tipo token/nonce.`,
      ],
      devtools: `F12 → Elements → Ctrl+F → buscar por "<form" ou "input type=hidden".`,
      consoleSnippet: `(() => { const forms = Array.from(document.forms).map(f => { const csrf = Array.from(f.querySelectorAll('input[type="hidden"]')).filter(i => /csrf|token|nonce/i.test(i.name || i.id)); return { formAction: f.action || window.location.href, method: (f.method || 'GET').toUpperCase(), temProtecaoCsrf: csrf.length > 0 ? '✅ SIM' : '❌ AUSENTE (Vulnerável)' }; }); console.table(forms); return '🔍 Auditando proteção CSRF nos formulários...'; })()`,
      automated: `curl -sk "${url}" | grep -iE "csrf|_token|nonce"`,
      proofOfWork: `curl -sk "${url}" | grep -n -C 5 -i "<form"`,
    };
  },

  password_autocomplete: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Auto-preenchimento de Senha (autocomplete)`,
      steps: [
        `1. Teste via Console: Execute o snippet no Console para listar todas as tags de senha e seus atributos.`,
        `2. PROVA REAL (Executar comando): O comando de terminal busca a tag do campo de senha no HTML da página.`,
        `   → Se a saída mostrar '<input type="password">' SEM 'autocomplete="off"', A VULNERABILIDADE É REAL E CONFIRMADA (o navegador salvará/preencherá a senha automaticamente).`,
        `   → Se a saída mostrar 'autocomplete="off"' ou 'autocomplete="new-password"', o campo está devidamente protegido.`,
      ],
      devtools: `F12 → Elements → Ctrl+F → buscar "<input" e conferir se há tipo password sem autocomplete.`,
      consoleSnippet: `Array.from(document.querySelectorAll('input[type="password"]')).map(i => ({ name: i.name, id: i.id, autocomplete: i.getAttribute('autocomplete') || 'AUSENTE (Inseguro)' }))`,
      automated: `curl -sk "${url}" | grep -iE "<input.*password"`,
      proofOfWork: `curl -sk "${url}" | grep -n -C 3 -i "password"`,
    };
  },

  exposed_port: (f, targetUrl) => {
    const host = f.host || hostname(f, targetUrl);
    const port = f.port || 5432;
    const isWeb = [80, 443, 3000, 8000, 8080, 8443].includes(Number(port));
    const testCmd = isWeb 
      ? `curl -skD - "http://${host}:${port}" -o /dev/null`
      : `nc -vv -w 3 ${host} ${port}`;
    return {
      title: `Validação & Prova Real para Porta ${port} (${f.service || 'Serviço Exposto'})`,
      steps: [
        `1. Teste focado: Testar a abertura direta do socket TCP na porta ${port} do servidor ${host}.`,
        `2. PROVA REAL (Executar comando):`,
        `   → Se a saída retornar "succeeded!" ou HTTP 200/302, A PORTA ESTÁ ABERTA E EXPOSTA PARA A INTERNET INTEIRA.`,
        `   → Se retornar "Connection refused" ou "timed out", a porta está devidamente fechada/protegida pelo firewall.`,
      ],
      devtools: `Terminal / Prompt de Comando / WSL (nc ou curl).`,
      automated: testCmd,
      proofOfWork: testCmd,
    };
  },

  // ════════════════════════════════════════════════════
  // LGPD & COMPLIANCE DE PRIVACIDADE
  // ════════════════════════════════════════════════════

  pii_in_url: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Dado Pessoal (PII) na URL`,
      steps: [
        `1. Teste focado: Inspecionar os parâmetros da URL em busca de dados pessoais.`,
        `2. PROVA REAL: Verificar o histórico do navegador e os logs do servidor web onde a URL completa fica gravada em texto claro.`,
      ],
      devtools: `F12 → Console → window.location.search`,
      consoleSnippet: `new URLSearchParams(window.location.search).get('${f.paramKey || 'cpf'}') ? '⚠️ PII EXPOSTO NA URL' : '✅ Limpo'`,
      automated: `curl -skD - "${url}" -o /dev/null`,
      proofOfWork: `curl -skD - "${url}" -o /dev/null`,
    };
  },

  pii_in_storage: (f) => ({
    title: `Validação & Prova Real para PII no Storage`,
    steps: [
      `1. Teste via Console: Inspecionar o item "${f.key || 'cpf'}" no ${f.storeType || 'localStorage'}.`,
      `2. PROVA REAL: Imprimir o dado em texto claro provando que qualquer script 3ª parte consegue ler sem autorização.`,
    ],
    devtools: `F12 → Application → ${f.storeType || 'Local Storage'} → chave "${f.key}".`,
    consoleSnippet: `${f.storeType || 'localStorage'}.getItem("${f.key || 'cpf'}")`,
    automated: `${f.storeType || 'localStorage'}.getItem("${f.key || 'cpf'}")`,
    proofOfWork: `console.log("${f.key}:", ${f.storeType || 'localStorage'}.getItem("${f.key || 'cpf'}"))`,
  }),

  missing_privacy_policy: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Ausência de Política de Privacidade (LGPD)`,
      steps: [
        `1. Teste via Console: Executar o snippet no Console (F12) para buscar links de Política de Privacidade/LGPD no DOM.`,
        `2. PROVA REAL (Terminal): Baixar o HTML com cURL e confirmar a ausência de links de transparência (Art. 9º LGPD).`,
      ],
      devtools: `F12 → Elements → Ctrl+F → buscar por "privacidade" ou "privacy".`,
      consoleSnippet: `(() => { const links = Array.from(document.querySelectorAll('a[href]')).filter(a => /privacidade|privacy|lgpd/i.test(a.href + a.innerText)); if (links.length) { console.table(links.map(l => ({ texto: l.innerText.trim(), link: l.href }))); return '✅ Política de Privacidade ENCONTRADA no DOM!'; } return '❌ AUSENTE: Nenhum link de Política de Privacidade localizado (Violação LGPD Art. 9º)'; })()`,
      automated: `curl -sk "${url}" | grep -iE "privacidade|privacy|lgpd"`,
      proofOfWork: `curl -sk "${url}" | grep -n -i "href="`,
    };
  },

  missing_form_optin: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Opt-in em Formulário (LGPD)`,
      steps: [
        `1. Teste via Console: Executar o snippet no Console (F12) para checar se o formulário possui checkbox de aceite LGPD.`,
        `2. PROVA REAL (Terminal): Baixar o HTML da página e verificar as tags de input do tipo checkbox.`,
      ],
      devtools: `F12 → Elements → inspecionar os campos do formulário.`,
      consoleSnippet: `(() => { const res = Array.from(document.forms).map(f => ({ formAction: f.action || window.location.href, temCheckboxConsentimento: f.querySelector('input[type="checkbox"]') ? '✅ SIM' : '❌ AUSENTE (Sem opt-in explícito)' })); console.table(res); return '🔍 Verificando consentimento LGPD nos formulários...'; })()`,
      automated: `curl -sk "${url}" | grep -iE "<form|<input.*checkbox"`,
      proofOfWork: `curl -sk "${url}" | grep -n -C 5 -i "<form"`,
    };
  },

  cookie_consent_violation: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Disparo de Cookies Sem Consentimento`,
      steps: [
        `1. Teste via Console: Executar no Console (F12) para detectar se trackers (Analytics, Pixel, Hotjar) foram carregados sem autorização prévia.`,
        `2. PROVA REAL: Exibir os scripts de terceiros injetados antes da interação do usuário com o banner LGPD.`,
      ],
      devtools: `F12 → Network → filtrar "analytics", "pixel", "facebook" ou "hotjar".`,
      consoleSnippet: `(() => { const trackers = Array.from(document.scripts).map(s => s.src).filter(src => /google-analytics|facebook\.net|hotjar|tiktok|clarity/i.test(src)); if (trackers.length) { console.table(trackers.map(t => ({ tracker: t.split('/').slice(-2).join('/'), urlCompleta: t }))); return '⚠️ ATENÇÃO: Trackers disparados antes do consentimento do usuário!'; } return '✅ Limpo: Nenhum tracker de terceiros detectado no carregamento inicial.'; })()`,
      automated: `curl -sk "${url}" | grep -iE "google-analytics|facebook\.net|hotjar|tiktok|clarity"`,
      proofOfWork: `curl -sk "${url}" | grep -n -i "<script"`,
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
      proofOfWork: `curl -skD - "${url}" -o /dev/null`,
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

  idor_suspected: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para IDOR`,
      steps: [
        `1. Teste focado: Substituir o ID na rota pelo ID de outro usuário e comparar com a resposta.`,
        `2. PROVA REAL (Baseline): Rode o comando de dump com o SEU PRÓPRIO cookie contra a URL original — se der erro/vazio aqui, o problema é de conexão/URL, não do teste de IDOR. Compare o tamanho/conteúdo dessa resposta com a obtida no passo 1.`,
      ],
      devtools: `F12 → Network → re-executar requisição trocando ID.`,
      automated: `curl -sk -H "Cookie: SESSION_USUARIO_B" "${url}"`,
      proofOfWork: `curl -sk -H "Cookie: <cole aqui seu próprio cookie de sessão, copiado do DevTools>" "${url}"`,
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

  backup_file_exposed: (f, targetUrl) => {
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

  http_method_enabled: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    // f.allow tem os métodos REAIS reportados pelo servidor (ex.: "GET, POST,
    // TRACE, PUT") — testar com o primeiro deles em vez de sempre TRACE fixo.
    const firstMethod = (f.allow || '').split(',').map(s => s.trim()).find(Boolean) || 'TRACE';
    return {
      title: `Validação & Prova Real para Métodos HTTP Inseguros`,
      steps: [
        `Evidência já capturada: Allow: ${f.allow || '(ver relatório)'}.`,
        `1. Teste focado: Testar se o método responde 200 OK.`,
        `2. PROVA REAL: Executar OPTIONS e exibir os métodos permitidos retornados no header \`Allow:\` — deve bater com a evidência já capturada.`,
      ],
      devtools: `F12 → Console → fetch com método customizado.`,
      automated: `curl -skD - -X ${firstMethod} "${url}" -o /dev/null`,
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
        `   → Se o comando 2 baixar o arquivo mas o comando 1 não achar a versão, confirme visualmente no início do arquivo (headers de licença costumam citar a versão).`,
      ],
      devtools: `F12 → Console → verificar versão.`,
      automated: `curl -sk "${url}" | grep -oP "${f.library || 'jquery'}\\/[0-9]+\\.[0-9]+\\.[0-9]+"`,
      proofOfWork: `curl -sk "${url}" | head -c 300`,
      online: `https://snyk.io/vuln/?q=${encodeURIComponent(f.library || '')}`,
    };
  },

  vulnerable_library_osv: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    const ids = Array.isArray(f.osvIds) ? f.osvIds : (f.cve ? String(f.cve).split(';').map(s => s.trim()).filter(Boolean) : []);
    return {
      title: `Validação & Prova Real para CVE Catalogada (OSV.dev)`,
      steps: [
        `1. Teste focado: confirmar que a versão detectada (${f.version || '?'}) do ${f.library || 'pacote'} realmente está carregada no site.`,
        `2. PROVA REAL: abrir cada advisory do OSV.dev abaixo — eles trazem o CVSS, os commits/versões afetadas e, na maioria dos casos, um PoC público.`,
      ],
      devtools: `F12 → Sources → localizar o arquivo e conferir a versão no cabeçalho/comentário.`,
      automated: `curl -sk "${url}" | head -c 300`,
      proofOfWork: `curl -sk "${url}" | grep -oE "${(f.library || '').replace(/[.*+?^${}()|[\]\\]/g, '\\\\$&') || 'version'}[^\\"']{0,30}"`,
      online: ids.length ? `https://osv.dev/vulnerability/${ids[0]}` : `https://osv.dev/list?q=${encodeURIComponent(f.library || '')}`,
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

  // ════════════════════════════════════════════════════
  // RECON / EXPOSIÇÃO — URL pública, curl reproduz de verdade
  // ════════════════════════════════════════════════════

  exposed_sensitive_file: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para ${f.label || 'Arquivo Sensível Exposto'}`,
      steps: [
        `1. Teste focado: baixar o arquivo e conferir o status HTTP.`,
        `2. PROVA REAL: exibir os primeiros bytes — a assinatura do conteúdo (ex.: "ref: refs/" pro .git/HEAD, "KEY=" pro .env) confirma que não é uma página de erro genérica disfarçada de 200.`,
      ],
      devtools: `Acessar a URL diretamente numa aba anônima.`,
      automated: `curl -skD - "${url}" -o /dev/null`,
      proofOfWork: `curl -sk "${url}" | head -c 300`,
    };
  },

  sitemap_disclosure: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para sitemap.xml`,
      steps: [
        `1. Teste focado: baixar o sitemap.xml.`,
        `2. PROVA REAL: listar as tags <loc> — ${f.currentValue ? `já capturadas: ${String(f.currentValue).slice(0, 200)}` : 'confirmar se alguma revela área interna/sensível'}.`,
      ],
      devtools: `Acessar sitemap.xml no navegador.`,
      automated: `curl -sk "${url}" | grep -o '<loc>[^<]*</loc>'`,
      proofOfWork: `curl -sk "${url}"`,
    };
  },

  openid_config_exposed: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para OpenID Connect Configuration Exposta`,
      steps: [
        `1. Teste focado: baixar o documento .well-known/openid-configuration.`,
        `2. PROVA REAL: confirmar os endpoints revelados (authorization_endpoint, token_endpoint, etc.) — geralmente é intencional (OIDC exige isso ser público), o achado é informativo.`,
      ],
      devtools: `Acessar a URL diretamente.`,
      automated: `curl -sk "${url}" | head -c 300`,
      proofOfWork: `curl -sk "${url}"`,
    };
  },

  http_downgrade: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Downgrade HTTP (sem redirect)`,
      steps: [
        `1. Teste focado: acessar a versão HTTP e ver se responde 200 (deveria redirecionar 301/302 para HTTPS).`,
        `2. PROVA REAL: seguir o redirecionamento com -L e conferir a cadeia completa de status.`,
      ],
      devtools: `Digitar http:// na barra de endereço e observar se troca sozinho para https://.`,
      automated: `curl -skD - "${url}" -o /dev/null | grep -iE "^HTTP|location"`,
      proofOfWork: `curl -skD - -L "${url}" -o /dev/null`,
    };
  },

  auth_over_http: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Token Enviado via HTTP`,
      steps: [
        `1. Teste focado: confirmar que a URL da requisição é http:// (não https://).`,
        `2. PROVA REAL: dado sensível trafegando sem TLS é confirmado só de olhar o protocolo — se a URL abaixo é http://, está confirmado.`,
      ],
      devtools: `F12 → Network → filtrar por http:// → conferir se algum tem header Authorization.`,
      automated: `curl -skD - "${url}" -o /dev/null | grep -iE "^HTTP"`,
      proofOfWork: `curl -skD - "${url}" -o /dev/null`,
    };
  },

  cache_control_sensitive: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Cache-Control em Página Autenticada`,
      steps: [
        `Evidência já capturada: Cache-Control atual = "${f.currentValue || '(ausente)'}".`,
        `1. Teste focado: buscar o header Cache-Control na resposta.`,
        `2. PROVA REAL: se não contiver "no-store", confirme no DevTools se a página fica salva no cache do disco (Network → coluna Size mostrando "(disk cache)" numa nova visita).`,
      ],
      devtools: `F12 → Application → Cache Storage, ou Network → coluna Size numa revisita.`,
      automated: `curl -skD - "${url}" -o /dev/null | grep -i "cache-control"`,
      proofOfWork: `curl -skD - "${url}" -o /dev/null`,
    };
  },

  cert_self_signed: (f, targetUrl) => {
    const hostPort = hostAndPort(f, 443, targetUrl);
    return {
      title: `Validação & Prova Real para Certificado Auto-Assinado`,
      steps: [
        `1. Teste focado: verificar se o Issuer (emissor) do certificado é igual ao Subject (mesmo nome) — isso é o que caracteriza "auto-assinado".`,
        `2. PROVA REAL: dump completo do certificado com Issuer e Subject lado a lado.`,
      ],
      devtools: `F12 → Security → View certificate → comparar "Issued by" e "Issued to".`,
      automated: `echo | openssl s_client -connect ${hostPort} 2>/dev/null | openssl x509 -issuer -subject -noout`,
      proofOfWork: `echo | openssl s_client -connect ${hostPort} 2>/dev/null | openssl x509 -text -noout`,
    };
  },

  insecure_websocket: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para WebSocket Sem Criptografia (ws://)`,
      steps: [
        `1. Teste focado: confirmar que a conexão WebSocket usa "ws://" (não "wss://") numa página HTTPS.`,
        `2. PROVA REAL: F12 → Network → aba "WS" → conferir o protocolo da conexão e os frames trafegados em texto claro.`,
      ],
      devtools: `F12 → Network → filtro "WS" → clicar na conexão → aba Messages.`,
      consoleSnippet: `new WebSocket('${url}').onerror = e => console.log('conexão ws:// bloqueada ou com erro', e)`,
    };
  },

  missing_ptr_record: (f) => {
    const ip = f.ip || '';
    const reversed = ip ? ip.split('.').reverse().join('.') : '?';
    return {
      title: `Validação & Prova Real para Registro PTR (DNS Reverso) Ausente`,
      steps: [
        `1. Teste focado: consultar o PTR do IP ${ip || '(ver relatório)'}.`,
        `2. PROVA REAL: se a consulta não retornar nome nenhum, a ausência está confirmada.`,
      ],
      devtools: `Terminal / CLI (nslookup / dig / PowerShell).`,
      automated: `nslookup -type=PTR ${reversed}.in-addr.arpa`,
      proofOfWork: `powershell -NoProfile -Command "Resolve-DnsName -Name ${ip} -Type PTR -ErrorAction SilentlyContinue"`,
      online: ip ? `https://mxtoolbox.com/SuperTool.aspx?action=ptr%3a${ip}` : undefined,
    };
  },

  tech_fingerprint: (f) => ({
    title: `Validação & Prova Real para Stack Identificado por Cookie`,
    steps: [
      `Evidência já capturada: ${f.currentValue || f.label}.`,
      `1. Teste focado: listar os nomes de cookie da sessão — nomes como JSESSIONID/PHPSESSID/ASP.NET_SessionId identificam a stack por convenção.`,
      `2. PROVA REAL: cookies com esse nome confirmam a tecnologia; é informativo, não uma falha por si só.`,
    ],
    devtools: `F12 → Application → Cookies → conferir os nomes.`,
    consoleSnippet: `document.cookie.split('; ').map(c => c.split('=')[0])`,
  }),

  storage_inventory: (f) => ({
    title: `Validação & Prova Real para Inventário de ${f.storage || 'Storage'}`,
    steps: [
      `Evidência já capturada: ${f.note || `${(f.keys || []).length} chave(s)`}.`,
      `1. Teste via Console: listar todas as chaves e valores agora.`,
    ],
    devtools: `F12 → Application → ${f.storage === 'sessionStorage' ? 'Session Storage' : 'Local Storage'}.`,
    consoleSnippet: `console.table(Object.entries(${f.storage === 'sessionStorage' ? 'sessionStorage' : 'localStorage'}))`,
  }),

  cookie_inventory: () => ({
    title: `Validação & Prova Real para Inventário de Cookies`,
    steps: [
      `1. Teste via Console: listar todos os cookies legíveis por JS agora (cookies httpOnly não aparecem aqui — é o esperado).`,
      `2. PROVA REAL: comparar com a lista completa no DevTools (que mostra também os httpOnly).`,
    ],
    devtools: `F12 → Application → Cookies → domínio auditado.`,
    consoleSnippet: `document.cookie.split('; ')`,
  }),

  console_sensitive: (f) => ({
    title: `Validação & Prova Real para Dado Sensível no Console`,
    steps: [
      `Evidência já capturada ao vivo pela auditoria: "${f.currentValue || '(ver relatório)'}".`,
      `1. Teste focado: reproduzir a ação que gera esse log e abrir o Console.`,
      `2. PROVA REAL: se o mesmo tipo de dado (token/senha/segredo) aparecer no console, confirmado — consoles ficam expostos a qualquer extensão de navegador ou pessoa com acesso físico à máquina.`,
    ],
    devtools: `F12 → Console → reproduzir a ação e observar o log.`,
  }),

  auth_header_detected: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Authorization Header Detectado`,
      steps: [
        `Achado INFORMATIVO — não é falha por si só. Evidência: header "${f.scheme || 'Authorization'}" enviado via ${f.method || 'requisição'}.`,
        `1. Teste focado: confirmar que a requisição só acontece sobre HTTPS e que o token não é de vida longa (revisar expiração).`,
      ],
      devtools: `F12 → Network → localizar a requisição → Headers → Request Headers → Authorization.`,
      automated: `curl -skD - "${url}" -o /dev/null | grep -iE "^HTTP"`,
    };
  },

  form_get_sensitive: (f, targetUrl) => {
    const url = sanitizeUrl(f.action, targetUrl);
    return {
      title: `Validação & Prova Real para Formulário GET com Dado Sensível`,
      steps: [
        `Evidência já capturada: campo(s) ${f.sensitiveFields?.join(', ') || '(ver relatório)'} num form method=GET.`,
        `1. Teste focado: submeter o formulário e conferir se os valores aparecem na URL resultante/no histórico do navegador.`,
      ],
      devtools: `F12 → Elements → localizar o <form method="GET"> e os campos listados.`,
      automated: url ? `curl -sk "${url}" | grep -n -C 3 -i "<form"` : undefined,
    };
  },

  broken_access_control: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Broken Access Control`,
      steps: [
        `Evidência já capturada (sem estar logado): ${f.currentValue || '(ver relatório)'}.`,
        `1. Teste focado: acessar a URL SEM cookies/sessão (aba anônima nova, sem logar).`,
        `2. PROVA REAL: se responder 200 com conteúdo real (não a mesma página de "não encontrado" do resto do site), o acesso indevido está confirmado.`,
      ],
      devtools: `Aba InPrivate nova → colar a URL → conferir se pede login.`,
      automated: `curl -skD - "${url}" -o /dev/null`,
      proofOfWork: `curl -sk "${url}" | head -c 300`,
    };
  },

  privilege_escalation: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Possível Escalonamento de Privilégio`,
      steps: [
        `Evidência já capturada: ${f.currentValue || '(ver relatório)'}.`,
        `1. Teste focado: acessar a URL DESLOGADO (deve bloquear) e depois LOGADO com sua conta (se abrir, confirma que a rota respondeu à sua sessão).`,
        `2. PROVA REAL: se o seu usuário NÃO deveria ter esse papel/permissão e mesmo assim a página abriu com dados reais, o escalonamento está confirmado — verificar manualmente se o papel esperado é mesmo diferente do seu.`,
      ],
      devtools: `F12 → Network → repita a requisição logado → aba Response.`,
      automated: `curl -skD - "${url}" -o /dev/null`,
    };
  },

  cors_reflected: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para CORS Refletindo Origem Arbitrária`,
      steps: [
        `Evidência já capturada: ${f.currentValue || '(ver relatório)'}.`,
        `1. Teste focado: enviar um Origin forjado e conferir se o servidor o reflete de volta no Access-Control-Allow-Origin.`,
        `2. PROVA REAL: dump completo dos headers Access-Control-* da resposta.`,
      ],
      devtools: `F12 → Console → fetch cross-origin de outra aba/origem e inspecionar erro/sucesso.`,
      automated: `curl -skD - -H "Origin: https://evil-sentinela-test.example" "${url}" -o /dev/null | grep -i "access-control"`,
      proofOfWork: `curl -skD - -H "Origin: https://evil-sentinela-test.example" "${url}" -o /dev/null`,
    };
  },

  cross_origin_auth: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Credencial Enviada a Domínio Externo`,
      steps: [
        `Evidência já capturada: requisição ${f.method || ''} para "${f.targetHost || '(ver URL)'}", fora do domínio da aplicação.`,
        ...authenticatedResponseContext(f),
        `1. Teste focado: F12 → Network → localizar requisições para "${f.targetHost || 'o host externo'}" → conferir Request Headers (Authorization/Cookie).`,
      ],
      devtools: `F12 → Network → filtrar pelo host "${f.targetHost || ''}".`,
    };
  },

  excessive_data_exposure: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Exposição Excessiva de Dados`,
      steps: [
        ...authenticatedResponseContext(f),
        `1. Teste focado: repetir a chamada a essa listagem e conferir se os campos ${f.fieldsExposed?.join(', ') || 'sensíveis'} aparecem para TODOS os ${f.itemCount || 'N'} itens, mesmo os que não pertencem a você.`,
      ],
      devtools: `F12 → Network → localizar a resposta → aba Response → conferir os campos por item.`,
    };
  },

  // ════════════════════════════════════════════════════
  // CORPO DE RESPOSTA AUTENTICADA — mesma limitação dos cookies de login:
  // curl anônimo não reproduz. Ver authenticatedResponseContext().
  // ════════════════════════════════════════════════════

  login_password_in_response: (f) => ({
    title: `Validação & Prova Real para SENHA na Resposta de Login`,
    steps: [
      ...authenticatedResponseContext(f),
      `1. Teste focado: refazer o login e inspecionar o corpo da resposta do POST — se o campo de senha aparecer em texto claro, CONFIRMADO.`,
    ],
    devtools: `F12 → Network → requisição de login → aba Response.`,
  }),

  login_token_in_response: (f) => ({
    title: `Validação & Prova Real para Token "${f.tokenField || ''}" na Resposta de Login`,
    steps: [
      ...authenticatedResponseContext(f),
      `1. Teste focado: refazer o login e conferir se "${f.tokenField || 'o token'}" aparece no JSON de resposta — se sim, confirme se o front-end guarda em localStorage/sessionStorage (vulnerável a XSS) ou só em memória/cookie httpOnly (mais seguro).`,
    ],
    devtools: `F12 → Network → requisição de login → aba Response → procurar "${f.tokenField || ''}".`,
    consoleSnippet: `localStorage.getItem("${f.tokenField || 'accessToken'}") || sessionStorage.getItem("${f.tokenField || 'accessToken'}")`,
  }),

  login_role_in_response: (f) => ({
    title: `Validação & Prova Real para Role/Permissão "${f.field || ''}" na Resposta de Login`,
    steps: [
      ...authenticatedResponseContext(f),
      `1. Teste focado: refazer o login e localizar o campo "${f.field || ''}" no JSON — depois, tente alterar esse valor via DevTools (ex.: interceptar/reenviar) e ver se o front-end libera uma tela/botão administrativo com base nele.`,
      `2. PROVA REAL: só é achado CONFIRMADO de verdade se o FRONT-END usar esse valor pra decidir o que mostrar sem o BACKEND validar de novo no servidor.`,
    ],
    devtools: `F12 → Network → requisição de login → aba Response → procurar "${f.field || ''}".`,
  }),

  password_in_response: (f) => ({
    title: `Validação & Prova Real para Senha Retornada por API`,
    steps: [
      ...authenticatedResponseContext(f),
      `1. Teste focado: repetir a chamada que gerou esse achado e inspecionar o corpo — se a senha (ou hash) aparecer, CONFIRMADO. NUNCA deveria acontecer, mesmo hasheada.`,
    ],
    devtools: `F12 → Network → localizar a resposta → aba Response.`,
  }),

  token_in_non_auth_response: (f) => ({
    title: `Validação & Prova Real para Token em Endpoint Não-Auth`,
    steps: [
      ...authenticatedResponseContext(f),
      `1. Teste focado: confirmar que a URL abaixo NÃO é um endpoint de login/refresh, e mesmo assim o corpo retorna um token.`,
    ],
    devtools: `F12 → Network → localizar a resposta → aba Response.`,
  }),

  sensitive_in_body: (f, targetUrl) => ({
    title: `Validação & Prova Real para Dado Sensível no Corpo da Requisição`,
    steps: [
      `Achado INFORMATIVO — esperado em login/cadastro. Evidência: ${f.note || f.label}.`,
      `1. Teste focado: confirmar que a requisição (método ${f.method || 'POST'}) só acontece sobre HTTPS.`,
    ],
    devtools: `F12 → Network → localizar a requisição → aba Payload/Request.`,
  }),

  sensitive_in_url: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Dado Sensível na URL`,
      steps: [
        `1. Teste focado: a própria URL abaixo já contém o parâmetro sensível — confirme visualmente.`,
        `2. PROVA REAL: URLs com dado sensível ficam em browser history, logs de servidor/proxy e no header Referer enviado a terceiros — risco real independente de HTTPS.`,
      ],
      devtools: `F12 → Network → conferir a URL completa da requisição (método ${f.method || 'GET'}).`,
      automated: `curl -skD - "${url}" -o /dev/null | grep -iE "^HTTP"`,
    };
  },

  // ════════════════════════════════════════════════════
  // FORMULÁRIO DE LOGIN — observações de atributo, sem URL própria (a
  // evidência é o HTML/DOM da própria página de login já auditada).
  // ════════════════════════════════════════════════════

  login_form_action: (f, targetUrl) => {
    const url = sanitizeUrl(f.formAction, targetUrl);
    return {
      title: `Inventário: Action do Formulário de Login`,
      steps: [
        `Achado INFORMATIVO. Capturado ao vivo: ${f.note || `envia para ${f.formAction} via ${f.formMethod || 'POST'}`}.`,
      ],
      devtools: `F12 → Elements → localizar <form> → atributo action.`,
      automated: url ? `curl -skD - "${url}" -o /dev/null | grep -iE "^HTTP"` : undefined,
    };
  },

  login_no_form_tag: (f, targetUrl) => ({
    title: `Validação & Prova Real para Login Sem Tag <form>`,
    steps: [
      `1. Teste focado: confirmar que não existe <form> na página, mas há campo de senha (login via JS/fetch, comum em SPA).`,
      `2. PROVA REAL: F12 → Network → digitar credenciais de teste e observar qual requisição JS dispara o login.`,
    ],
    devtools: `F12 → Elements → Ctrl+F → buscar "<form" (deve dar 0 resultados) e "type=\\"password\\"".`,
  }),

  login_password_no_name: (f) => ({
    title: `Validação & Prova Real para Campo de Senha Sem name/id`,
    steps: [
      `1. Teste focado: inspecionar o <input type="password"> e conferir os atributos name e id.`,
    ],
    devtools: `F12 → Elements → clicar no campo de senha → aba Attributes.`,
    consoleSnippet: `Array.from(document.querySelectorAll('input[type="password"]')).map(i => ({ name: i.name || '(ausente)', id: i.id || '(ausente)' }))`,
  }),

  login_password_autocomplete: (f) => ({
    title: `Validação & Prova Real para Autocomplete no Campo de Senha`,
    steps: [
      `Evidência já capturada: campo "${f.inputName || ''}" com autocomplete="${f.autocompleteValue || '(não definido)'}".`,
      `1. Teste focado: inspecionar o atributo autocomplete do campo agora.`,
    ],
    devtools: `F12 → Elements → localizar o campo "${f.inputName || ''}" → atributo autocomplete.`,
    consoleSnippet: `document.querySelector('input[name="${f.inputName || ''}"], input[id="${f.inputName || ''}"]')?.autocomplete`,
  }),

  login_password_example_placeholder: (f) => ({
    title: `Validação & Prova Real para Placeholder com Exemplo de Senha Fraca`,
    steps: [
      `Evidência já capturada: placeholder = "${f.placeholder || ''}".`,
      `1. Teste focado: inspecionar o atributo placeholder do campo de senha.`,
    ],
    devtools: `F12 → Elements → localizar o campo de senha → atributo placeholder.`,
    consoleSnippet: `Array.from(document.querySelectorAll('input[type="password"]')).map(i => i.placeholder)`,
  }),

  login_password_maxlength: (f) => ({
    title: `Validação & Prova Real para maxlength Curto no Campo de Senha`,
    steps: [
      `1. Teste focado: inspecionar o atributo maxlength do campo de senha — evidência já no título do achado (${f.label || ''}).`,
    ],
    devtools: `F12 → Elements → localizar o campo de senha → atributo maxlength.`,
    consoleSnippet: `Array.from(document.querySelectorAll('input[type="password"]')).map(i => i.maxLength)`,
  }),

  login_password_visible: (f) => ({
    title: `Validação & Prova Real para Campo de Senha Visível (type="text")`,
    steps: [
      `Evidência já capturada: campo "${f.inputName || ''}" com type diferente de "password".`,
      `1. Teste focado: inspecionar o atributo type do campo — se não for "password", a senha fica visível na tela.`,
    ],
    devtools: `F12 → Elements → localizar o campo "${f.inputName || ''}" → atributo type.`,
    consoleSnippet: `document.querySelector('input[name="${f.inputName || ''}"], input[id="${f.inputName || ''}"]')?.type`,
  }),

  login_forgot_password_http: (f) => ({
    title: `Validação & Prova Real para Link de Recuperação de Senha via HTTP`,
    steps: [
      `Evidência já capturada: link = "${f.href || ''}".`,
      `1. Teste focado: confirmar que o link começa com "http://", não "https://".`,
    ],
    devtools: `F12 → Elements → localizar o link "Esqueci minha senha" → atributo href.`,
    automated: f.href ? `curl -skD - "${f.href}" -o /dev/null | grep -iE "^HTTP"` : undefined,
  }),

  // ════════════════════════════════════════════════════
  // FLUXO DE LOGIN AO VIVO — precisa refazer o login pra reproduzir
  // ════════════════════════════════════════════════════

  login_credentials_sent: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Transporte de Credenciais no Login`,
      steps: [
        `1. Teste focado: confirmar que a URL da requisição de login é https:// (evidência: ${f.label || ''}).`,
      ],
      devtools: `F12 → Network → requisição de login → conferir o protocolo.`,
      automated: `curl -skD - "${url}" -o /dev/null | grep -iE "^HTTP"`,
    };
  },

  login_password_in_url: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Senha na URL de Login`,
      steps: [
        `1. Teste focado: refazer o login e conferir se a URL da requisição contém a senha na query string.`,
        `2. PROVA REAL: F12 → Network → clicar na requisição de login → aba Headers → General → Request URL.`,
      ],
      devtools: `F12 → Network → requisição de login → Request URL.`,
    };
  },

  login_redirect_with_token: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Redirect de Login com Token na URL`,
      steps: [
        `Evidência já capturada: redirecionou para "${f.redirectTo || '(ver relatório)'}".`,
        `1. Teste focado: refazer o login e conferir o header Location da resposta de redirect.`,
      ],
      devtools: `F12 → Network → resposta 3xx do login → Headers → Location.`,
      automated: `curl -skD - "${url}" -o /dev/null | grep -i "location"`,
    };
  },

  login_cookie_added: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Cookie "${f.cookieName}" Criado no Login`,
      steps: [
        ...cookieCaptureContext(f),
        `1. Teste via Console: ler o cookie "${f.cookieName}" agora (após logar).`,
      ],
      devtools: `F12 → Application → Cookies → linha "${f.cookieName}".`,
      consoleSnippet: `document.cookie.split('; ').filter(c => c.startsWith('${f.cookieName}='))`,
    };
  },

  login_cookie_removed: (f) => ({
    title: `Validação & Prova Real para Cookie "${f.cookieName}" Removido no Login`,
    steps: [
      `1. Teste via Console: o cookie "${f.cookieName}" NÃO deve mais existir após o login (comum quando o servidor regenera a sessão corretamente — geralmente é um sinal BOM, não uma falha).`,
    ],
    devtools: `F12 → Application → Cookies → confirmar ausência de "${f.cookieName}".`,
    consoleSnippet: `document.cookie.split('; ').filter(c => c.startsWith('${f.cookieName}=')).length === 0`,
  }),

  pii_in_storage_value: (f) => ({
    title: `Validação & Prova Real para Documento Pessoal em ${f.storeType || 'Storage'}`,
    steps: [
      `1. Teste via Console: ler a chave "${f.key}" — se contiver um CPF/CNPJ com dígito verificador válido em texto claro, confirmado.`,
    ],
    devtools: `F12 → Application → ${f.storeType === 'sessionStorage' ? 'Session Storage' : 'Local Storage'} → linha "${f.key}".`,
    consoleSnippet: `${f.storeType === 'sessionStorage' ? 'sessionStorage' : 'localStorage'}.getItem("${f.key}")`,
  }),

  pii_in_url_value: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para Documento Pessoal na URL`,
      steps: [
        `1. Teste focado: o próprio parâmetro "${f.paramKey || ''}" na URL abaixo já é a evidência — confirmar visualmente o dígito verificador do documento.`,
        `2. PROVA REAL: URLs com CPF/CNPJ ficam em browser history, logs de servidor/proxy — risco de exposição de PII (LGPD Art. 46).`,
      ],
      devtools: `F12 → Console → window.location.search.`,
      consoleSnippet: `new URLSearchParams(window.location.search).get('${f.paramKey || ''}')`,
    };
  },

  target_blank_noopener: (f, targetUrl) => {
    const url = sanitizeUrl(f.url, targetUrl);
    return {
      title: `Validação & Prova Real para target="_blank" Sem rel="noopener"`,
      steps: [
        `Evidência já capturada: ${(f.sample || []).slice(0, 3).join(', ') || f.label}.`,
        `1. Teste focado: listar os links target="_blank" e conferir o atributo rel.`,
        `2. PROVA REAL: navegadores modernos já mitigam por padrão (noopener implícito), mas confirmar explicitamente reduz risco em navegadores antigos/embarcados.`,
      ],
      devtools: `F12 → Elements → Ctrl+F → buscar 'target="_blank"'.`,
      consoleSnippet: `Array.from(document.querySelectorAll('a[target="_blank"]')).filter(a => !/noopener/.test(a.rel)).map(a => a.href)`,
      automated: url ? `curl -sk "${url}" | grep -oE '<a[^>]*target="_blank"[^>]*>'` : undefined,
    };
  },

  source_map_exposed: (f, targetUrl) => {
    const mapUrl = sanitizeUrl(f.mapUrl || f.match, targetUrl);
    return {
      title: `Validação & Prova Real para Referência a Source Map`,
      steps: [
        `1. Teste focado: confirmar que o script referencia um .map externo (evidência: "${f.match || f.mapUrl || ''}").`,
        `2. PROVA REAL: tentar baixar o .map — se responder 200, use o achado "source_map_content_exposed" (gerado automaticamente quando acessível) para ver se o conteúdo original vazou.`,
      ],
      devtools: `F12 → Sources → o DevTools já resolve o .map automaticamente se acessível.`,
      automated: `curl -skD - "${mapUrl}" -o /dev/null | grep -iE "^HTTP"`,
      proofOfWork: `curl -sk "${mapUrl}" | head -c 200`,
    };
  },

  cloud_bucket_detected: (f, targetUrl) => ({
    title: `Validação & Prova Real para Bucket de Nuvem Referenciado (não testado)`,
    steps: [
      `Achado é INVENTÁRIO — bucket(s) referenciado(s): ${(f.buckets || []).join(', ') || f.currentValue || '(ver relatório)'}. O Sentinela NÃO testou a permissão.`,
      `1. Teste focado: tentar listar o bucket publicamente.`,
    ],
    devtools: `Abrir a URL do bucket direto no navegador.`,
    automated: (f.buckets || [])[0] ? `curl -sk "https://${(f.buckets || [])[0]}?list-type=2"` : undefined,
    online: `https://github.com/sa7mon/S3Scanner`,
  }),
};

// ── Fallback genérico ───────────────────────────────────────

// Fallback para types sem gerador dedicado. Usado como rede de segurança —
// mas "genérico" não pode significar "instrução vazia": nunca mostre o slug
// técnico cru como step, sempre dê ALGO reproduzível (dump do corpo, não só
// headers — a maioria dos types sem gerador dedicado depende de CONTEÚDO,
// não de headers), e avise quando a evidência exigir sessão autenticada.
function humanizeType(type) {
  return String(type || '').replace(/_/g, ' ').replace(/^./, c => c.toUpperCase());
}

const GENERIC_VERIFICATION = (f, targetUrl) => {
  const url = sanitizeUrl(f.url, targetUrl);
  const subject = f.label || f.note || humanizeType(f.type);
  const context = [...cookieCaptureContext(f), ...authenticatedResponseContext(f)];
  return {
    title: `Validação & Prova Real: ${subject}`,
    steps: [
      ...context,
      `1. Teste focado: ${f.risk || subject}`,
      `2. PROVA REAL: baixar o conteúdo completo (comando 2) e conferir manualmente — o comando 1 é só um recorte.`,
    ],
    devtools: context.some(l => /DevTools|Network|Application/.test(l))
      ? undefined // já orientado no contexto acima, não duplicar
      : `F12 → inspecionar conforme: ${subject}.`,
    automated: url ? `curl -sk "${url}" | head -c 500` : null,
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
