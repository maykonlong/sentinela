/**
 * Recon autônomo (roda sozinho, em paralelo, sem interação do usuário) e
 * teste de controle de acesso (anônimo vs autenticado).
 *
 * Usa o APIRequestContext do Playwright (context.request), que:
 *   - compartilha os cookies do contexto → pré-login = anônimo, pós-login = autenticado
 *   - permite headers arbitrários (ex.: Origin) → dá pra testar CORS refletido
 *   - respeita ignoreHTTPSErrors do contexto (bom p/ cert self-signed)
 *
 * Divisão de segurança:
 *   - Leituras de arquivos padrão (robots/sitemap/.well-known/api-docs) e testes
 *     não-intrusivos (CORS, erro verboso, downgrade) → SEMPRE (passivo).
 *   - Dicionário de paths, arquivos de backup e open-redirect ativo → só --active.
 */

const WELLKNOWN = ['/.well-known/security.txt', '/.well-known/openid-configuration', '/.well-known/change-password'];
const API_DOC_PATHS = ['/swagger.json', '/openapi.json', '/api-docs', '/v2/api-docs', '/v3/api-docs', '/api/swagger.json', '/swagger/v1/swagger.json'];
const COMMON_PATHS = ['/admin', '/administrator', '/manage', '/gerenciar', '/dashboard', '/config', '/configuracao', '/backup', '/backups', '/private', '/internal', '/interno', '/debug', '/test', '/teste', '/phpmyadmin', '/wp-admin', '/.git/config', '/.env', '/uploads', '/files', '/logs', '/console'];
const REDIRECT_PARAMS = ['redirect', 'redirect_url', 'redirecturl', 'redirect_uri', 'url', 'next', 'return', 'returnurl', 'return_url', 'dest', 'destination', 'continue', 'goto', 'target', 'callback'];
const BACKUP_SUFFIXES = ['.bak', '.old', '~', '.save', '.orig', '.copy', '.1', '.swp'];

const EVIL_ORIGIN = 'https://sentinela-cors-probe.example';
const EVIL_REDIRECT = 'https://sentinela-openredir.example/pwned';

const SENSITIVE_PATH_RE = /admin|manage|gerenc|config|backup|\.git|\.env|internal|intern|private|privad|debug|phpmyadmin|swagger|api-docs|console|dump|logs?\b|wp-admin/i;
const LOGIN_REDIRECT_RE = /login|signin|sign-in|auth|sso|entrar|acesso/i;

// Paths que, se realmente existissem, devolveriam texto/binário — NUNCA uma
// página HTML. Se o corpo começa com <html/<!doctype, o que voltou foi o app
// shell do catch-all, não o arquivo.
const TEXT_ONLY_PATH_RE = /\.git|\.env|\.svn|backup|dump|\.sql|\.bak|\.old|\.zip|\.tar|logs?\b/i;
const HTML_START_RE = /^\s*(?:<!doctype\s+html|<html\b|<\?xml[^>]*>\s*<html\b)/i;

// Baseline de "soft-404" do alvo: resposta de um path garantidamente inexistente.
// Vive em escopo de módulo porque `diffAccessControl` é chamado pelo auditor com
// assinatura fixa (anon, auth, pageOrigin) e não teria como recebê-lo por
// parâmetro. Preenchido por runRecon, consumido por diffAccessControl.
let soft404Baseline = null;

const BODY_START_LEN = 200;

/** Início normalizado do corpo — para comparar respostas sem ruído de espaços. */
function bodyStartOf(body) {
  return String(body || '').slice(0, BODY_START_LEN * 4).replace(/\s+/g, ' ').trim().slice(0, BODY_START_LEN);
}

/** Hash barato (FNV-1a) do corpo inteiro — detecta resposta byte-a-byte igual. */
function bodyHash(body) {
  const s = String(body || '');
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return (h >>> 0).toString(36);
}

const STACK_PATTERNS = [
  /Traceback \(most recent call last\)/,
  /\bat [\w.$<>[\]]+\([^)]*:\d+:\d+\)/,               // JS/Node/Java frame
  /\bin [\/\w.\-]+\.php(?: on line \d+|:\d+)/i,        // PHP
  /System\.[\w.]+Exception|Microsoft\.[\w.]+Exception/, // .NET
  /(?:org|java|javax|com)\.[\w.]+Exception/,           // Java
  /Warning: .+ in .+ on line \d+/i,                    // PHP warning
  /Symfony\\|Laravel|Whoops\\|Werkzeug|Rails\.application/, // frameworks
  /You have an error in your SQL syntax|Unclosed quotation|ORA-\d{5}|PG::\w+Error|SQLSTATE\[/i, // SQL error (também indício de SQLi)
];

// ─── HTTP helper ───────────────────────────────────────────

async function safeGet(request, url, extra = {}) {
  try {
    const res = await request.get(url, { maxRedirects: 0, timeout: 8000, failOnStatusCode: false, ...extra });
    let body = '';
    try { body = await res.text(); } catch { /* binário/sem corpo */ }
    const headers = res.headers();
    return { status: res.status(), headers, body, len: body.length, location: headers['location'] || '' };
  } catch {
    return null;
  }
}

// (safePost foi removido junto com a checagem duplicada de GraphQL — o único
//  consumidor. A checagem agora vive só em api-cloud-rules.mjs.)

// ─── Fingerprint ───────────────────────────────────────────

export function fingerprintFromCookies(cookies) {
  const map = [
    [/^JSESSIONID$/i, 'Java / Tomcat/JBoss'],
    [/^PHPSESSID$/i, 'PHP'],
    [/^(ASP\.NET_SessionId|\.ASPXAUTH|\.AspNetCore)/i, 'ASP.NET'],
    [/^(laravel_session|XSRF-TOKEN)$/i, 'Laravel (PHP)'],
    [/^connect\.sid$/i, 'Node.js / Express'],
    [/^(_rails|_session_id|_.*_session)$/i, 'Ruby on Rails'],
    [/^ci_session$/i, 'CodeIgniter (PHP)'],
    [/^symfony$/i, 'Symfony (PHP)'],
    [/^wordpress_|wp-settings/i, 'WordPress'],
    [/^django|csrftoken$/i, 'Django (Python)'],
  ];
  const found = new Set();
  for (const c of cookies || []) {
    for (const [re, tech] of map) if (re.test(c.name)) found.add(tech);
  }
  if (found.size === 0) return [];
  return [{
    type: 'tech_fingerprint', severity: 'INFO', thirdParty: false,
    label: `Stack identificado por cookie: ${[...found].join(', ')}`,
    currentValue: [...found].join(', '),
    risk: `Os cookies revelam a tecnologia do backend (${[...found].join(', ')}). Isso ajuda um atacante a buscar CVEs específicos daquela stack.`,
    recommendation: 'Renomear cookies de sessão para nomes neutros e manter o framework/servidor sempre atualizado.',
  }];
}

function fingerprintFromHeaders(headers) {
  const findings = [];
  const tech = [];
  const h = headers || {};
  if (h['server']) tech.push(`Server: ${h['server']}`);
  if (h['x-powered-by']) tech.push(`X-Powered-By: ${h['x-powered-by']}`);
  if (h['x-aspnet-version']) tech.push(`ASP.NET ${h['x-aspnet-version']}`);
  if (h['x-generator']) tech.push(`Generator: ${h['x-generator']}`);
  if (tech.length > 0) {
    findings.push({
      type: 'tech_fingerprint', severity: 'LOW', thirdParty: false,
      label: 'Tecnologia/versão exposta em headers',
      currentValue: tech.join(' | '),
      risk: `Headers revelam a stack (${tech.join(', ')}). Um atacante usa isso para buscar vulnerabilidades conhecidas (CVEs) da versão exata.`,
      recommendation: 'Remover/ofuscar Server, X-Powered-By, X-AspNet-Version. Manter tudo atualizado.',
    });
  }
  return findings;
}

// ─── Recon principal (autônomo) ───────────────────────────

export async function runRecon(request, pageOrigin, opts = {}) {
  const findings = [];
  const candidatePaths = new Set();
  const active = !!opts.active;

  // Headers da raiz (para fingerprint e base)
  const root = await safeGet(request, pageOrigin + '/');
  if (root) findings.push(...fingerprintFromHeaders(root.headers));

  // 0) BASELINE DE SOFT-404 — obrigatório ANTES de qualquer probe de path.
  // FP concreto evitado: em SPA com rota catch-all (rewrite do Next.js, nginx
  // `try_files ... /index.html`, S3+CloudFront), QUALQUER path devolve 200 com o
  // index.html do app. Sem baseline, os 24 paths de COMMON_PATHS viravam ~15
  // achados MEDIUM/HIGH de "Broken Access Control" de uma vez — incluindo
  // "/.git/config acessível sem login (HIGH)" quando o que voltou foi a home.
  // Requisitando um path que garantidamente não existe, sabemos exatamente com o
  // que se parece um "não encontrado" nesse alvo, e podemos descartar o resto.
  const baselinePath = `/sentinela-baseline-404-${Math.random().toString(36).slice(2, 10)}`;
  const baseRes = await safeGet(request, pageOrigin + baselinePath);
  soft404Baseline = {
    origin: pageOrigin,
    path: baselinePath,
    // Resposta do path inexistente. Se vier 200, o alvo TEM catch-all.
    miss: baseRes ? { status: baseRes.status, len: baseRes.len, bodyStart: bodyStartOf(baseRes.body), hash: bodyHash(baseRes.body) } : null,
    // A home também serve de referência: catch-all costuma devolver exatamente ela.
    root: root && root.status === 200 ? { status: root.status, len: root.len, bodyStart: bodyStartOf(root.body), hash: bodyHash(root.body) } : null,
  };

  // 1) robots.txt
  const robots = await safeGet(request, pageOrigin + '/robots.txt');
  if (robots && robots.status === 200 && /disallow|allow|sitemap/i.test(robots.body)) {
    const paths = [];
    for (const line of robots.body.split('\n')) {
      const m = line.match(/^\s*(?:dis)?allow\s*:\s*(\S+)/i);
      if (m && m[1] && m[1] !== '/' && m[1] !== '*') { paths.push(m[1]); candidatePaths.add(m[1].split('?')[0]); }
      const sm = line.match(/^\s*sitemap\s*:\s*(\S+)/i);
      if (sm) candidatePaths.add(sm[1]);
    }
    if (paths.length > 0) {
      const sensitive = paths.filter(p => SENSITIVE_PATH_RE.test(p));
      findings.push({
        type: 'robots_disclosure', severity: sensitive.length ? 'LOW' : 'INFO', thirdParty: false,
        label: `robots.txt expõe ${paths.length} caminho(s)`,
        url: pageOrigin + '/robots.txt',
        currentValue: paths.slice(0, 20).join('  '),
        sample: sensitive.slice(0, 8),
        risk: `O robots.txt lista caminhos que o site tenta esconder${sensitive.length ? ` (inclusive sensíveis: ${sensitive.slice(0, 6).join(', ')})` : ''}. Atacantes leem isso para achar áreas ocultas.`,
        recommendation: 'Não confiar no robots.txt para esconder áreas sensíveis — ele é público. Proteger com autenticação/autorização no servidor.',
      });
    }
  }

  // 2) sitemap.xml
  const sitemap = await safeGet(request, pageOrigin + '/sitemap.xml');
  if (sitemap && sitemap.status === 200 && /<urlset|<sitemapindex|<loc>/i.test(sitemap.body)) {
    const locs = [...sitemap.body.matchAll(/<loc>\s*([^<]+?)\s*<\/loc>/gi)].map(m => m[1]);
    for (const loc of locs) {
      try { const u = new URL(loc); if (u.origin === pageOrigin) candidatePaths.add(u.pathname); } catch { /* ignore */ }
    }
    if (locs.length > 0) {
      findings.push({
        type: 'sitemap_disclosure', severity: 'INFO', thirdParty: false,
        label: `sitemap.xml lista ${locs.length} URL(s)`,
        url: pageOrigin + '/sitemap.xml',
        currentValue: locs.slice(0, 10).join('  '),
        risk: 'O sitemap mapeia a superfície do app (útil pra recon). Verificar se não expõe páginas internas/sensíveis.',
        recommendation: 'Manter no sitemap apenas conteúdo público.',
      });
    }
  }

  // 3) .well-known
  for (const wk of WELLKNOWN) {
    const r = await safeGet(request, pageOrigin + wk);
    if (!r || r.status !== 200 || r.len < 3) continue;
    if (wk.includes('openid-configuration') && /issuer|authorization_endpoint/i.test(r.body)) {
      findings.push({
        type: 'openid_config_exposed', severity: 'INFO', thirdParty: false,
        label: 'OpenID Connect configuration exposta', url: pageOrigin + wk,
        risk: 'O endpoint OIDC revela endpoints de autenticação e escopos. Geralmente é intencional, mas confirma o provedor de identidade e a superfície de auth.',
        recommendation: 'Ok se for intencional; garantir que não vaze endpoints internos.',
      });
    }
  }

  // 4) API docs / Swagger / OpenAPI
  for (const ap of API_DOC_PATHS) {
    const r = await safeGet(request, pageOrigin + ap);
    if (r && r.status === 200 && /"swagger"|"openapi"|"paths"\s*:/i.test(r.body)) {
      findings.push({
        type: 'api_docs_exposed', severity: 'MEDIUM', thirdParty: false,
        label: 'Documentação de API (Swagger/OpenAPI) exposta', url: pageOrigin + ap,
        currentValue: `${r.len} bytes de schema`,
        risk: 'A especificação da API está pública — entrega TODOS os endpoints, parâmetros e modelos para um atacante mapear a superfície inteira.',
        recommendation: 'Restringir o acesso à documentação da API (apenas ambiente interno/autenticado).',
      });
      break;
    }
  }

  // 5) [REMOVIDO] GraphQL introspection — a checagem vivia aqui E em
  // api-cloud-rules.mjs (`checkGraphQlIntrospection`), com severidades
  // divergentes (MEDIUM aqui, HIGH lá). FP concreto evitado: o MESMO /graphql
  // saía DUAS vezes no relatório, com gravidades diferentes, e a versão daqui
  // aceitava um simples `/__schema|"types"/` no corpo — o que casa a resposta de
  // ERRO que ecoa a query enviada. Consolidado numa única implementação em
  // api-cloud-rules.mjs, que testa 4 endpoints e valida a ESTRUTURA da resposta.
  // O tipo emitido continua sendo `graphql_introspection` (o mapeado em owasp-map).

  // 6) CORS refletido — mando um Origin arbitrário e vejo se volta no ACAO
  const cors = await safeGet(request, pageOrigin + '/', { headers: { Origin: EVIL_ORIGIN } });
  if (cors) {
    const acao = cors.headers['access-control-allow-origin'] || '';
    const acac = (cors.headers['access-control-allow-credentials'] || '').toLowerCase() === 'true';
    if (acao === EVIL_ORIGIN || (acao === '*' && acac)) {
      findings.push({
        type: 'cors_reflected', severity: acao === EVIL_ORIGIN && acac ? 'HIGH' : 'MEDIUM', thirdParty: false,
        label: 'CORS reflete origem arbitrária', url: pageOrigin + '/',
        currentValue: `Origin enviado: ${EVIL_ORIGIN} → ACAO: ${acao}${acac ? ' + Allow-Credentials: true' : ''}`,
        risk: acac
          ? 'O servidor reflete QUALQUER origem no Access-Control-Allow-Origin E permite credenciais. Um site malicioso pode fazer requisições autenticadas em nome da vítima e ler as respostas.'
          : 'O servidor reflete a origem enviada. Combinado com credenciais, permitiria roubo de dados cross-origin.',
        recommendation: 'Nunca refletir o header Origin. Usar allowlist explícita de origens confiáveis; jamais combinar "*" com Allow-Credentials.',
      });
    }
  }

  // 7) Página de erro verbosa — path improvável → stack trace / tecnologia
  const probePath = '/sentinela-probe-nao-existe-9182734.aspx';
  const errRes = await safeGet(request, pageOrigin + probePath);
  if (errRes && errRes.body) {
    const hit = STACK_PATTERNS.find(re => re.test(errRes.body));
    if (hit) {
      const snippet = (errRes.body.match(hit) || [''])[0].slice(0, 140);
      findings.push({
        type: 'verbose_error', severity: 'MEDIUM', thirdParty: false,
        label: 'Página de erro vaza stack trace / tecnologia',
        // URL real e reproduzível — antes era um placeholder de exibição
        // ("/(path inexistente)"), impossível de testar de novo.
        url: pageOrigin + probePath,
        currentValue: snippet,
        risk: 'A aplicação retorna erros detalhados (stack trace, versão do framework, caminho de arquivos, erro de SQL). Isso entrega informação de infraestrutura e às vezes indica injeção.',
        recommendation: 'Em produção, usar páginas de erro genéricas (sem stack trace) e logar os detalhes só no servidor.',
      });
    }
  }

  // 8) Downgrade HTTP — HTTPS servindo também em HTTP sem redirect
  if (pageOrigin.startsWith('https://')) {
    const httpRes = await safeGet(request, pageOrigin.replace('https://', 'http://') + '/');
    if (httpRes && httpRes.status === 200 && httpRes.len > 200) {
      findings.push({
        type: 'http_downgrade', severity: 'MEDIUM', thirdParty: false,
        label: 'Conteúdo servido também via HTTP (sem redirect p/ HTTPS)',
        url: pageOrigin.replace('https://', 'http://') + '/',
        risk: 'A versão HTTP responde com conteúdo em vez de redirecionar para HTTPS. Permite interceptação/downgrade (Man-in-the-Middle).',
        recommendation: 'Forçar redirect 301 de HTTP→HTTPS e habilitar HSTS.',
      });
    }
  }

  // Dicionário de paths comuns (só ativo): entram como candidatos p/ o diff.
  if (active) {
    for (const p of COMMON_PATHS) candidatePaths.add(p);
  }

  // Probe anônimo dos candidatos (pré-login). O mesmo request pós-login será autenticado.
  const anonResults = await probePaths(request, pageOrigin, [...candidatePaths]);

  return { findings, candidatePaths: [...candidatePaths], anonResults };
}

// ─── Probe de paths (para o diff anon vs auth) ────────────

export async function probePaths(request, pageOrigin, paths) {
  const results = {};
  for (const p of (paths || []).slice(0, 40)) {
    const url = p.startsWith('http') ? p : pageOrigin + (p.startsWith('/') ? p : '/' + p);
    const r = await safeGet(request, url);
    if (!r) continue;
    // `bodyStart` e `hash` são a EVIDÊNCIA: sem eles, diffAccessControl só via
    // status+tamanho e não tinha como distinguir "o arquivo existe" de "o
    // catch-all devolveu o app shell". São ~200 bytes por path, custo desprezível.
    results[p] = {
      status: r.status, len: r.len, location: r.location,
      bodyStart: bodyStartOf(r.body), hash: bodyHash(r.body),
    };
  }
  return results;
}

// ─── Diff de controle de acesso (anônimo vs autenticado) ──

/**
 * A resposta `r` é indistinguível de um "não encontrado" desse alvo?
 * Compara contra o baseline de soft-404 e contra a home. Retorna o motivo do
 * descarte (string) ou null se a resposta é mesmo distinta.
 */
function soft404Reason(r, baseline) {
  if (!r || !baseline) return null;
  for (const [nome, ref] of [['baseline 404', baseline.miss], ['home do app', baseline.root]]) {
    if (!ref || ref.status !== r.status) continue;
    // Um corpo é HTML e o outro não → são coisas diferentes, ponto. Sem esta
    // guarda, um /.git/config REAL de 224 bytes poderia ser descartado só porque
    // a página de 404 do alvo tem tamanho parecido (falso NEGATIVO).
    if (HTML_START_RE.test(r.bodyStart || '') !== HTML_START_RE.test(ref.bodyStart || '')) continue;
    // Corpo byte-a-byte igual: é literalmente a mesma página.
    if (ref.hash && r.hash && ref.hash === r.hash) return `corpo idêntico à ${nome}`;
    // Tamanho ≈ igual (±5%): o app shell varia só por nonce/timestamp embutido.
    const delta = ref.len ? Math.abs(r.len - ref.len) / ref.len : 1;
    if (delta <= 0.05) return `tamanho ≈ ${nome} (${r.len} vs ${ref.len} bytes, ${(delta * 100).toFixed(1)}%)`;
    // Mesmo com tamanho diferente, mesmo começo de corpo = mesmo template.
    if (ref.bodyStart && r.bodyStart && ref.bodyStart === r.bodyStart) return `início do corpo idêntico à ${nome}`;
  }
  return null;
}

export function diffAccessControl(anon, auth, pageOrigin) {
  const findings = [];
  const isOpen = (r) => r && r.status === 200 && r.len > 120;
  const isLoginRedirect = (r) => r && [301, 302, 303, 307, 308].includes(r.status) && LOGIN_REDIRECT_RE.test(r.location || '');
  const isBlocked = (r) => r && (r.status === 401 || r.status === 403 || isLoginRedirect(r));

  // Só uso o baseline se ele for DESTE alvo (runRecon pode não ter rodado).
  const baseline = soft404Baseline && soft404Baseline.origin === pageOrigin ? soft404Baseline : null;

  const allPaths = new Set([...Object.keys(anon || {}), ...Object.keys(auth || {})]);
  for (const p of allPaths) {
    const a = (anon || {})[p];
    const b = (auth || {})[p];
    const sensitive = SENSITIVE_PATH_RE.test(p);

    // 1) Acessível ANONIMAMENTE e sensível → controle de acesso quebrado.
    //    Exige EVIDÊNCIA POSITIVA: 200 com corpo não é prova de nada se o corpo
    //    for o mesmo do "não encontrado". Dois filtros anti-FP:
    //    (a) resposta indistinguível do baseline de soft-404 / da home;
    //    (b) HTML devolvido para path que só poderia ser texto/binário.
    if (isOpen(a) && sensitive) {
      const motivo = soft404Reason(a, baseline);
      if (motivo) continue;  // catch-all da SPA respondendo tudo com o app shell

      // FP concreto: "/.git/config acessível sem login (HIGH)" onde o corpo era
      // `<!DOCTYPE html>…` — a home do Next.js. Um .git/config real é texto
      // `[core]\n\trepositoryformatversion = 0`, nunca HTML.
      if (TEXT_ONLY_PATH_RE.test(p) && HTML_START_RE.test(a.bodyStart || '')) continue;

      findings.push({
        type: 'broken_access_control', severity: /\.git|\.env|backup|dump|config/i.test(p) ? 'HIGH' : 'MEDIUM',
        thirdParty: false, phase: 'PRÉ-LOGIN', confidence: 'provável',
        label: `Caminho sensível acessível SEM login: ${p}`,
        url: pageOrigin + p,
        currentValue: `anônimo: HTTP ${a.status}, ${a.len} bytes${baseline && baseline.miss ? ` (404 do alvo: HTTP ${baseline.miss.status}, ${baseline.miss.len} bytes — resposta DIFERENTE)` : ''}`,
        risk: `O caminho "${p}" respondeu 200 com conteúdo DIFERENTE da página de "não encontrado" deste alvo para um usuário NÃO autenticado. Se for mesmo uma área sensível, qualquer pessoa acessa sem credenciais (Broken Access Control).`,
        recommendation: 'Exigir autenticação e autorização no servidor para esse caminho. Não depender de "esconder" a URL.',
      });
      continue;
    }

    // 2) Bloqueado anônimo, mas 200 autenticado, e é área ADMIN → revisar escalonamento.
    //    Mesmo filtro: se o 200 autenticado é só o app shell, não houve acesso a
    //    área administrativa nenhuma.
    if (isOpen(b) && soft404Reason(b, baseline)) continue;

    if (isBlocked(a) && isOpen(b) && /admin|manage|gerenc|console|interno|internal/i.test(p)) {
      findings.push({
        type: 'privilege_escalation', severity: 'LOW', thirdParty: false, phase: 'PÓS-LOGIN', confidence: 'provável',
        label: `Área administrativa acessível autenticado: ${p}`,
        url: pageOrigin + p,
        currentValue: `anônimo: ${a.status} → autenticado: ${b.status} (${b.len} bytes)`,
        risk: `"${p}" é bloqueado sem login, mas abriu com a sua sessão. Se o seu usuário NÃO deveria ser admin, isso é escalonamento de privilégio. Verificar manualmente o papel esperado.`,
        recommendation: 'Garantir que áreas administrativas exijam o papel/permissão correta, não apenas estar logado.',
      });
    }
  }
  return findings;
}

// ─── Open redirect ─────────────────────────────────────────

export function detectRedirectParams(url) {
  try {
    const u = new URL(url);
    const found = [];
    for (const [k] of u.searchParams) if (REDIRECT_PARAMS.includes(k.toLowerCase())) found.push(k);
    return found;
  } catch { return []; }
}

export async function testOpenRedirect(request, url) {
  const findings = [];
  const params = detectRedirectParams(url);
  for (const p of params) {
    let target;
    try { const u = new URL(url); u.searchParams.set(p, EVIL_REDIRECT); target = u.toString(); } catch { continue; }
    const r = await safeGet(request, target);
    if (r && [301, 302, 303, 307, 308].includes(r.status) && /sentinela-openredir\.example/i.test(r.location || '')) {
      findings.push({
        type: 'open_redirect', severity: 'MEDIUM', thirdParty: false, phase: 'PÓS-LOGIN', confidence: 'confirmado',
        label: `Open redirect no parâmetro "${p}"`,
        url: url.split('?')[0],
        currentValue: `${p}=${EVIL_REDIRECT} → Location: ${r.location}`,
        risk: `O parâmetro "${p}" redireciona para um domínio externo arbitrário. Usado em phishing: o link parece do seu domínio, mas joga a vítima num site malicioso.`,
        recommendation: 'Validar o destino do redirect contra uma allowlist, ou permitir apenas caminhos relativos internos.',
      });
    }
  }
  return findings;
}

// ─── Guessing de arquivos de backup (só --active) ─────────

export async function testBackupFiles(request, assetUrls) {
  const findings = [];
  const seen = new Set();
  for (const asset of (assetUrls || []).slice(0, 15)) {
    for (const suf of BACKUP_SUFFIXES) {
      const target = asset + suf;
      if (seen.has(target)) continue;
      seen.add(target);
      const r = await safeGet(request, target);
      if (r && r.status === 200 && r.len > 20) {
        findings.push({
          type: 'backup_file_exposed', severity: 'HIGH', thirdParty: false, phase: 'PÓS-LOGIN',
          label: `Arquivo de backup exposto: ${target.split('/').pop()}`,
          url: target,
          currentValue: `HTTP 200, ${r.len} bytes`,
          risk: 'Um arquivo de backup/temporário do código-fonte está acessível publicamente. Pode conter código, segredos e lógica interna.',
          recommendation: 'Remover arquivos de backup do diretório público e bloquear extensões .bak/.old/~ no servidor.',
        });
        break;
      }
    }
  }
  return findings;
}
