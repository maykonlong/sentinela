/**
 * Testes ATIVOS (Tier 3) — enviam requisições ao alvo, então só rodam com a
 * flag --active (exigem autorização explícita do dono do site).
 *
 * Cobre:
 *   - Métodos HTTP perigosos habilitados (TRACE/PUT/DELETE/CONNECT)
 *   - Ausência de /.well-known/security.txt
 *   - Arquivos sensíveis expostos (.git, .env, server-status, actuator...)
 *   - Rate limiting ausente no login (checkRateLimit)
 *   - Enumeração de usuário via mensagem de erro/timing do login (checkUserEnumeration)
 *   - Política de senha fraca/ausente no formulário (checkPasswordPolicyHints, passivo)
 *
 * Deliberadamente conservador: poucas requisições, sem fuzzing, sem brute force.
 */

const SENSITIVE_FILES = [
  { path: '/.git/HEAD', sig: /ref:\s*refs\//i, label: 'Repositório .git exposto' },
  { path: '/.env', sig: /^[A-Z0-9_]+=/m, label: 'Arquivo .env exposto' },
  { path: '/.svn/entries', sig: /^\d+|svn/i, label: 'Diretório .svn exposto' },
  { path: '/server-status', sig: /Apache Server Status|Server Version/i, label: 'Apache server-status exposto' },
  { path: '/actuator/health', sig: /"status"\s*:/i, label: 'Spring Boot Actuator exposto' },
  { path: '/phpinfo.php', sig: /phpinfo\(\)|PHP Version/i, label: 'phpinfo() exposto' },
];

/**
 * Executa as checagens ativas a partir do contexto da página (same-origin).
 * @returns {Promise<Array>} findings
 */
export async function runActiveChecks(page, pageOrigin) {
  const findings = [];

  const raw = await page.evaluate(async ({ origin, files }) => {
    // fetch() do browser não tem timeout próprio — contra um alvo real (WAF/CDN
    // pode descartar a sonda em silêncio, sem nunca fechar a conexão) isso trava
    // pra sempre. Aborta em 8s, mesmo padrão usado em recon-rules.mjs.
    const fetchWithTimeout = async (url, opts = {}, ms = 8000) => {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), ms);
      try {
        return await fetch(url, { ...opts, signal: ctrl.signal });
      } finally {
        clearTimeout(t);
      }
    };

    const out = { methods: null, securityTxt: null, files: [] };

    // 1) Métodos HTTP via OPTIONS (same-origin → Allow legível)
    try {
      const res = await fetchWithTimeout(origin + '/', { method: 'OPTIONS' });
      out.methods = { status: res.status, allow: res.headers.get('allow') || res.headers.get('access-control-allow-methods') || '' };
    } catch (e) { out.methods = { error: String(e) }; }

    // 2) security.txt
    try {
      const res = await fetchWithTimeout(origin + '/.well-known/security.txt', { method: 'GET' });
      out.securityTxt = { status: res.status };
    } catch (e) { out.securityTxt = { error: String(e) }; }

    // 3) Arquivos sensíveis
    for (const f of files) {
      try {
        const res = await fetchWithTimeout(origin + f.path, { method: 'GET' });
        let body = '';
        try { body = (await res.text()).slice(0, 500); } catch { /* ignore */ }
        out.files.push({ path: f.path, status: res.status, body });
      } catch (e) {
        out.files.push({ path: f.path, error: String(e) });
      }
    }
    return out;
  }, { origin: pageOrigin, files: SENSITIVE_FILES.map(f => ({ path: f.path })) });

  // Métodos perigosos
  if (raw.methods && raw.methods.allow) {
    const dangerous = ['TRACE', 'TRACK', 'PUT', 'DELETE', 'CONNECT', 'PATCH'];
    const enabled = dangerous.filter(m => new RegExp(`\\b${m}\\b`, 'i').test(raw.methods.allow));
    if (enabled.length > 0) {
      findings.push({
        type: 'http_method_enabled', severity: 'MEDIUM', thirdParty: false, phase: 'PÓS-LOGIN',
        label: `Métodos HTTP perigosos habilitados: ${enabled.join(', ')}`,
        url: pageOrigin + '/', allow: raw.methods.allow,
        risk: `O servidor anuncia os métodos ${enabled.join(', ')} no header Allow. TRACE pode permitir Cross-Site Tracing (roubo de cookies), e PUT/DELETE mal configurados permitem alterar/remover recursos.`,
        recommendation: 'Desabilitar métodos não usados no servidor/proxy. Manter apenas GET, POST, HEAD, OPTIONS conforme necessário.',
      });
    }
  }

  // security.txt ausente
  if (raw.securityTxt && raw.securityTxt.status && raw.securityTxt.status >= 400) {
    findings.push({
      type: 'missing_security_txt', severity: 'LOW', thirdParty: false, phase: 'PÓS-LOGIN',
      label: 'Sem /.well-known/security.txt',
      url: pageOrigin + '/.well-known/security.txt',
      risk: 'Não há canal padronizado (security.txt) para pesquisadores reportarem vulnerabilidades de forma responsável.',
      recommendation: 'Publicar /.well-known/security.txt com contato de segurança (RFC 9116).',
    });
  }

  // Arquivos sensíveis expostos
  for (let i = 0; i < raw.files.length; i++) {
    const r = raw.files[i];
    const meta = SENSITIVE_FILES[i];
    if (r && r.status === 200 && r.body && meta.sig.test(r.body)) {
      findings.push({
        type: 'exposed_sensitive_file', severity: 'HIGH', thirdParty: false, phase: 'PÓS-LOGIN',
        label: meta.label,
        url: pageOrigin + meta.path,
        risk: `${meta.label} — acessível publicamente em ${meta.path}. Pode vazar código-fonte, segredos, ou informação de infraestrutura para qualquer pessoa.`,
        recommendation: `Bloquear o acesso a ${meta.path} no servidor/proxy e remover o arquivo do diretório público.`,
      });
    }
  }

  return findings;
}

/**
 * Teste de IDOR / BOLA (Broken Object Level Authorization).
 * Para cada URL GET autenticada com ID numérico, refaz a requisição trocando o
 * ID (n-1 ou n+1) e compara. Se o servidor devolve 200 com conteúdo similar,
 * é indício de que você acessa dados de OUTRO registro sem autorização.
 *
 * Só GET (idempotente), same-origin, com os cookies da sessão. --active only.
 */
export async function runIdorChecks(page, candidates, pageOrigin) {
  const findings = [];
  const sample = (candidates || []).slice(0, 10);
  if (sample.length === 0) return findings;

  const results = await page.evaluate(async ({ items }) => {
    // Parâmetros de cache-busting/versão: o número ali NÃO é um identificador de
    // objeto. FP concreto evitado: `?v=1755500000` era reescrito para
    // `?v=1755499999`, o servidor devolvia exatamente o mesmo recurso, e isso
    // virava "IDOR confirmado". Só troco dígitos que não sejam desses params.
    const CACHE_PARAM_RE = /(?:^|[?&])(v|_|t|ts|cb|rev|version|timestamp|time|nocache|rnd|random|hash|build)$/i;
    const ID_RE = /(\/|=)(\d{1,12})(\/|$|&|\?|;)/g;

    // Troca o PRIMEIRO id numérico que não seja cache-buster. Devolve os dois
    // valores (from/to) para depois podermos exigir evidência de que a resposta
    // modificada fala mesmo do OUTRO objeto.
    const tweak = (u) => {
      ID_RE.lastIndex = 0;
      let m;
      while ((m = ID_RE.exec(u)) !== null) {
        // u.slice(0, m.index) termina exatamente no nome do parâmetro (o '=' é m[1]).
        if (m[1] === '=' && CACHE_PARAM_RE.test(u.slice(0, m.index))) continue;
        const n = parseInt(m[2], 10);
        const nn = n > 1 ? n - 1 : n + 1;
        const url = u.slice(0, m.index) + m[1] + nn + m[3] + u.slice(m.index + m[0].length);
        return { url, from: m[2], to: String(nn) };
      }
      return null;
    };

    const out = [];
    for (const it of items) {
      const t = tweak(it.url);
      if (!t || t.url === it.url) continue;
      try {
        const [o, mres] = await Promise.all([
          fetch(it.url, { credentials: 'include' }),
          fetch(t.url, { credentials: 'include' }),
        ]);
        const ot = await o.text();
        const mt = await mres.text();
        out.push({
          orig: it.url, mod: t.url, oStatus: o.status, mStatus: mres.status,
          oLen: ot.length, mLen: mt.length, mSample: mt.slice(0, 160),
          oCt: o.headers.get('content-type') || '', mCt: mres.headers.get('content-type') || '',
          // Evidência de que as respostas são objetos DISTINTOS, e não o mesmo
          // app shell renderizado duas vezes.
          identical: mt === ot,
          lenDiff: ot.length ? Math.abs(mt.length - ot.length) / ot.length : 1,
          mHasTo: mt.includes(t.to),
          mHasFrom: mt.includes(t.from),
        });
      } catch (e) {
        out.push({ orig: it.url, error: String(e) });
      }
    }
    return out;
  }, { items: sample });

  for (const r of results) {
    if (r.error) continue;
    const ratio = r.oLen ? r.mLen / r.oLen : 0;
    const authErr = /unauthor|forbidden|denied|not allowed|acesso negado|não autorizado|"error"|\blogin\b|\b401\b|\b403\b/i.test(r.mSample || '');
    if (!(r.oStatus === 200 && r.mStatus === 200 && r.mLen > 50 && ratio > 0.5 && ratio < 2 && !authErr)) continue;

    // ── EVIDÊNCIA POSITIVA OBRIGATÓRIA ────────────────────────────────
    // FP concreto evitado: em SPA/Next.js, `/pedido/123` e `/pedido/122` são
    // roteadas no cliente e o servidor devolve o MESMO app shell nas duas —
    // ratio 1.0, e o teste `authErr` (que só olha os 160 primeiros bytes, isto é
    // `<!DOCTYPE html><html...`) nunca casa. O resultado era `idor_suspected`
    // HIGH em cima de páginas que sequer carregaram dados. 200 + tamanho
    // parecido NÃO é prova: só conta se os DOIS corpos forem objetos distintos.
    if (r.identical) continue;                                    // literalmente a mesma resposta

    const isHtml = /text\/html/i.test(r.mCt || '') || /text\/html/i.test(r.oCt || '');
    // HTML exige diferença maior: o shell varia por nonce/__NEXT_DATA__ e muda
    // alguns bytes sem que nenhum dado do outro registro tenha sido servido.
    const minDiff = isHtml ? 0.05 : 0.02;
    // Para JSON, um corpo que traz o id TROCADO (e não o original) é evidência
    // de que o servidor entregou mesmo o outro objeto, ainda que do mesmo tamanho.
    const trazOutroId = !isHtml && r.mHasTo && !r.mHasFrom;
    if (r.lenDiff < minDiff && !trazOutroId) continue;

    findings.push({
      // MEDIUM/provável, não HIGH/confirmado: este teste no máximo levanta a
      // suspeita — confirmar exige saber que o objeto do outro id pertence a
      // OUTRO usuário, o que o scanner não tem como saber sozinho.
      type: 'idor_suspected', severity: 'MEDIUM', thirdParty: false, phase: 'PÓS-LOGIN',
      confidence: 'provável',
      label: 'Possível IDOR/BOLA — acesso a objeto de outro ID',
      url: r.orig,
      currentValue: `troquei o ID → ${r.mod} | resposta ${r.mStatus}, ${r.mLen} bytes (original ${r.oLen} bytes; corpos diferem em ${(r.lenDiff * 100).toFixed(1)}%${trazOutroId ? '; o corpo devolvido cita o ID trocado' : ''})`,
      risk: 'Ao trocar o ID na requisição autenticada, o servidor devolveu 200 com um corpo DIFERENTE do original (não é a mesma página repetida) — indício de que é possível acessar dados de OUTRO usuário/registro (Broken Object Level Authorization). Confirmar manualmente se o registro do ID trocado pertence a outro usuário.',
      recommendation: 'No backend, validar em TODA requisição se o objeto pertence ao usuário autenticado (autorização por objeto), não apenas se está logado.',
    });
  }
  return findings;
}

// ─── Rate limit / user enumeration / password policy (--active) ──
//
// As 3 funções abaixo testam o formulário de LOGIN, não a página atual, então
// usam context.request (não page.evaluate) — mesmo padrão de recon-rules.mjs
// (safeGet), mas com POST de formulário.

/**
 * POST com timeout — equivalente ao fetchWithTimeout usado em runActiveChecks
 * lá em cima, só que aqui via context.request em vez de fetch() do browser
 * (Playwright já dá timeout/failOnStatusCode nativos, não precisa de
 * AbortController manual). Devolve null em qualquer erro de rede/timeout: o
 * chamador decide abortar o teste inteiro sem gerar finding.
 */
async function postWithTimeout(request, url, form, ms = 8000) {
  try {
    const t0 = Date.now();
    const res = await request.post(url, { form, timeout: ms, failOnStatusCode: false, maxRedirects: 0 });
    const elapsed = Date.now() - t0;
    let body = '';
    try { body = await res.text(); } catch { /* binário/sem corpo */ }
    return { status: res.status(), elapsed, body };
  } catch {
    return null;
  }
}

/**
 * Monta o corpo do POST de login. Com `formFieldNames` ({user, pass}) reais,
 * usa exatamente esses nomes — caso ideal, zero ambiguidade. Sem eles, manda
 * OS DOIS nomes mais comuns (username+email, password+senha) NO MESMO
 * request: como o backend ignora campos que não reconhece, isso cobre a
 * heurística sem precisar de requisições extras "tentando" cada combinação
 * (o que inflaria à toa o nº de tentativas contra o alvo).
 */
function buildLoginBody(formFieldNames, userValue, passValue) {
  const body = {};
  const userField = formFieldNames && formFieldNames.user;
  const passField = formFieldNames && formFieldNames.pass;
  if (userField) {
    body[userField] = userValue;
  } else {
    body.username = userValue;
    body.email = userValue;
  }
  if (passField) {
    body[passField] = passValue;
  } else {
    body.password = passValue;
    body.senha = passValue;
  }
  return body;
}

/** Credencial obviamente falsa e sempre diferente a cada chamada — nunca uma senha real. */
function fakeCredential(tag) {
  const rnd = Math.random().toString(36).slice(2, 10);
  return {
    email: `sentinela-probe-${tag}-${rnd}@test.invalid`,
    pass: `S3ntinela!Probe-${rnd}`,
  };
}

const CAPTCHA_RE = /captcha|recaptcha|hcaptcha|cloudflare/i;

/**
 * Testa ausência de rate limiting no login.
 *
 * No MÁXIMO 5 requisições — sequenciais, nunca em paralelo: disparar em
 * paralelo é a própria assinatura de um ataque de força bruta (e o WAF pode
 * reagir bloqueando o IP do auditor), enquanto sequencial com poucas
 * tentativas já é suficiente para observar se status/tempo de resposta mudam
 * sob repetição — e continua gentil com um alvo de produção real.
 */
export async function checkRateLimit(request, loginUrl, formFieldNames, opts = {}) {
  const findings = [];
  const MAX_ATTEMPTS = 5;
  const timeoutMs = opts.timeoutMs || 8000;

  const attempts = [];
  for (let i = 0; i < MAX_ATTEMPTS; i++) {
    const { email, pass } = fakeCredential(`rl${i}`);
    const body = buildLoginBody(formFieldNames, email, pass);
    const r = await postWithTimeout(request, loginUrl, body, timeoutMs);
    // Erro de rede/timeout em QUALQUER tentativa: ausência de evidência não é
    // evidência de vulnerabilidade — aborta o teste inteiro sem reportar nada.
    if (!r) return findings;
    attempts.push(r);

    // 429 explícito ou CAPTCHA no corpo: rate limit está funcionando. Para
    // aqui mesmo — não faz sentido continuar "testando" um bloqueio já visto.
    if (r.status === 429) return findings;
    if (CAPTCHA_RE.test(r.body)) return findings;
  }

  // Delay crescente: compara a mediana das 2 primeiras respostas (baseline,
  // "defesa ainda não reagiu") com cada uma das seguintes. Se alguma tentativa
  // ficou > 2x mais lenta, é indício de throttling/backoff progressivo — não
  // reporta, mesmo que os status HTTP continuem iguais.
  const baseline = (attempts[0].elapsed + attempts[1].elapsed) / 2;
  const grewSlow = baseline > 0 && attempts.slice(2).some(a => a.elapsed > baseline * 2);
  if (grewSlow) return findings;

  // Status divergente entre tentativas: sinal ambíguo (pode já ser algum tipo
  // de bloqueio que as heurísticas acima não capturaram). Na dúvida, não
  // afirma "sem rate limit" — só afirma isso quando as 5 respostas foram uniformes.
  const statuses = new Set(attempts.map(a => a.status));
  if (statuses.size > 1) return findings;

  findings.push({
    type: 'no_rate_limit', severity: 'MEDIUM', thirdParty: false, phase: 'PRÉ-LOGIN', confidence: 'confirmado',
    label: `Sem rate limiting perceptível no login (${MAX_ATTEMPTS} tentativas sequenciais)`,
    url: loginUrl,
    currentValue: attempts.map((a, i) => `#${i + 1}: HTTP ${a.status} em ${a.elapsed}ms`).join('  '),
    risk: `${MAX_ATTEMPTS} tentativas de login sequenciais, cada uma com credenciais inválidas e diferentes, devolveram respostas estatisticamente iguais — mesmo status HTTP em todas, sem crescimento de latência, sem CAPTCHA, sem HTTP 429. Isso facilita ataques de força bruta e credential stuffing contra contas reais.`,
    recommendation: 'Implementar rate limiting por IP e/ou por conta no endpoint de login (ex.: bloqueio temporário ou CAPTCHA após N tentativas, HTTP 429 com backoff progressivo).',
  });
  return findings;
}

// Heurísticas textuais de mensagem de erro do login — servem só para COMPARAR
// as duas respostas entre si (nunca para provar isolado que um usuário existe).
const USER_NOT_FOUND_RE = /usu[aá]rio.{0,20}n[aã]o.{0,15}encontrad|user.{0,10}not.{0,10}found|n[aã]o existe|invalid.{0,10}user/i;
const WRONG_PASSWORD_RE = /senha.{0,15}incorret|invalid.{0,10}password|credenciais/i;

/**
 * Testa se a resposta do login vaza se o "usuário" existe ou não.
 *
 * Envia só 2 requisições (até 4 no pior caso, se o sinal de timing for
 * ambíguo e precisar de confirmação) — as DUAS com e-mails igualmente
 * inexistentes, nunca tentando adivinhar um usuário real. Fica dentro do
 * escopo autorizado: o objetivo não é enumerar contas de verdade, é só ver
 * se o backend trata dois usuários inexistentes de forma DISTINGUÍVEL entre
 * si (o que já indicaria que ele distingue "existe" vs "não existe" de forma
 * observável, em geral).
 */
export async function checkUserEnumeration(request, loginUrl, formFieldNames, opts = {}) {
  const findings = [];
  const timeoutMs = opts.timeoutMs || 8000;

  const probeOnce = (tag) => {
    const { email, pass } = fakeCredential(tag);
    const body = buildLoginBody(formFieldNames, email, pass);
    return postWithTimeout(request, loginUrl, body, timeoutMs);
  };

  const a = await probeOnce('ue1');
  if (!a) return findings; // erro de rede → aborta sem finding
  const b = await probeOnce('ue2');
  if (!b) return findings;

  // Respostas idênticas (status + corpo) → não há distinção observável. Bom.
  if (a.status === b.status && a.body === b.body) return findings;

  const aSignal = USER_NOT_FOUND_RE.test(a.body) ? 'not_found' : (WRONG_PASSWORD_RE.test(a.body) ? 'wrong_pass' : null);
  const bSignal = USER_NOT_FOUND_RE.test(b.body) ? 'not_found' : (WRONG_PASSWORD_RE.test(b.body) ? 'wrong_pass' : null);

  // As duas mensagens caem em categorias TEXTUAIS diferentes (uma parece
  // "usuário não encontrado", a outra "senha incorreta") apesar de nenhum dos
  // dois usuários existir de verdade — evidência direta de enumeração por
  // mensagem de erro.
  if (aSignal && bSignal && aSignal !== bSignal) {
    findings.push({
      type: 'user_enumeration', severity: 'LOW', thirdParty: false, phase: 'PRÉ-LOGIN', confidence: 'confirmado',
      label: 'Mensagem de erro do login distingue usuário inexistente de senha incorreta',
      url: loginUrl,
      currentValue: `tentativa 1 → padrão "${aSignal}" | tentativa 2 → padrão "${bSignal}" (nenhum dos dois usuários existe)`,
      risk: 'A mensagem de erro do login muda de forma perceptível dependendo do valor de usuário/e-mail enviado, mesmo quando NENHUM dos dois existe. Um atacante pode usar isso para testar e-mails em massa e descobrir quais são contas cadastradas (enumeração de usuário).',
      recommendation: 'Padronizar a mensagem de erro do login para um texto único e genérico ("credenciais inválidas"), independente de o usuário existir ou a senha estar errada.',
    });
    return findings;
  }

  // Sem sinal textual claro: tenta timing, mas só reporta com CONFIRMAÇÃO (uma
  // segunda rodada) — timing sozinho é ruidoso (rede, GC, cache) e sem repetir
  // vira falso positivo fácil. >3x é o corte para "diferença grande demais pra
  // ser ruído"; a mesma tentativa precisa continuar mais lenta na 2ª rodada.
  if (a.elapsed > 0 && b.elapsed > 0) {
    const ratio1 = Math.max(a.elapsed, b.elapsed) / Math.min(a.elapsed, b.elapsed);
    if (ratio1 > 3) {
      const a2 = await probeOnce('ue3');
      if (!a2) return findings;
      const b2 = await probeOnce('ue4');
      if (!b2) return findings;
      const ratio2 = (a2.elapsed > 0 && b2.elapsed > 0) ? Math.max(a2.elapsed, b2.elapsed) / Math.min(a2.elapsed, b2.elapsed) : 0;
      const sameDirection = (a.elapsed > b.elapsed) === (a2.elapsed > b2.elapsed);
      if (ratio2 > 3 && sameDirection) {
        findings.push({
          type: 'user_enumeration', severity: 'LOW', thirdParty: false, phase: 'PRÉ-LOGIN', confidence: 'provável',
          label: 'Possível enumeração de usuário por tempo de resposta do login',
          url: loginUrl,
          currentValue: `rodada 1: ${a.elapsed}ms vs ${b.elapsed}ms | rodada 2 (confirmação): ${a2.elapsed}ms vs ${b2.elapsed}ms`,
          risk: 'O tempo de resposta do login variou de forma consistente e repetida (mais de 3x) entre dois "usuários" igualmente inexistentes. Diferente do caso confirmado por texto, esta é evidência por TIMING (side-channel): pode indicar que o backend faz um trabalho extra (ex.: hash de senha) só quando encontra o usuário no banco.',
          recommendation: 'Garantir tempo de resposta constante no login independente de o usuário existir (ex.: sempre computar um hash de senha "dummy" para usuário inexistente).',
        });
      }
    }
  }

  return findings;
}

// Regras simples de "parece uma política de senha razoável" — minlength >= 8
// (heurística de tamanho mínimo aceitável) ou um pattern de complexidade
// qualquer já conta como sinal de política presente.
const PASSWORD_HINT_TEXT_RE = /m[ií]nimo de\s*\d+\s*caracter|no m[ií]nimo\s*\d+\s*caracter|pelo menos\s*\d+\s*caracter/i;

/**
 * Recorta o HTML de um <form> específico por id (#foo) ou classe (.foo).
 * Regex simples (não é um parser DOM de verdade), assume forms não-aninhados
 * — suficiente para essa heurística de UI. Se o seletor não for reconhecido
 * ou não bater com nenhum <form>, devolve o HTML inteiro (mais seguro do que
 * devolver vazio e gerar um falso "sem política" por engano de seletor).
 */
function extractFormHtml(html, formSelector) {
  if (!formSelector) return html;
  let attrRe;
  if (formSelector.startsWith('#')) {
    attrRe = new RegExp(`id\\s*=\\s*["']${formSelector.slice(1)}["']`, 'i');
  } else if (formSelector.startsWith('.')) {
    attrRe = new RegExp(`class\\s*=\\s*["'][^"']*\\b${formSelector.slice(1)}\\b[^"']*["']`, 'i');
  } else {
    return html;
  }
  const formOpenRe = /<form\b[^>]*>/gi;
  let m;
  while ((m = formOpenRe.exec(html)) !== null) {
    if (attrRe.test(m[0])) {
      const end = html.indexOf('</form>', m.index);
      return end === -1 ? html.slice(m.index) : html.slice(m.index, end + 7);
    }
  }
  return html;
}

/**
 * Checagem PASSIVA de política de senha (não precisa de --active de verdade:
 * não cria conta, não troca senha, só lê o HTML já carregado da página de
 * cadastro/troca de senha). Síncrona de propósito — não faz nenhuma requisição.
 */
export function checkPasswordPolicyHints(pageHtml, formSelector) {
  const findings = [];
  const html = String(pageHtml || '');
  if (!html) return findings;

  const scoped = extractFormHtml(html, formSelector);
  const passwordInputs = scoped.match(/<input\b[^>]*type\s*=\s*["']?password["']?[^>]*>/gi) || [];
  if (passwordInputs.length === 0) return findings; // sem campo de senha nesta página — nada a avaliar

  let hasStrongMinlength = false;
  let hasPattern = false;
  for (const tag of passwordInputs) {
    const ml = tag.match(/minlength\s*=\s*["']?(\d+)["']?/i);
    if (ml && parseInt(ml[1], 10) >= 8) hasStrongMinlength = true;
    if (/pattern\s*=\s*["'][^"']+["']/i.test(tag)) hasPattern = true;
  }
  if (hasStrongMinlength || hasPattern) return findings;

  // Texto de ajuda pode estar fora da tag <form> (tooltip, modal) — procura no
  // documento inteiro, não só no form recortado.
  if (PASSWORD_HINT_TEXT_RE.test(html)) return findings;

  findings.push({
    type: 'weak_password_policy', severity: 'LOW', thirdParty: false, phase: 'PÓS-LOGIN', confidence: 'provável',
    label: 'Nenhuma política de senha visível no formulário',
    url: null,
    currentValue: `${passwordInputs.length} campo(s) de senha encontrados: sem minlength >= 8, sem pattern de complexidade, sem texto de requisito na página`,
    risk: 'O HTML do formulário não expõe nenhum sinal de política de senha (minlength, pattern de complexidade ou texto de ajuda). É uma checagem de UI/heurística: o BACKEND pode validar a política mesmo sem essa pista visual no front-end — confirmar manualmente enviando uma senha fraca (ex.: "123456") e observando se o servidor rejeita.',
    recommendation: 'Expor no formulário os requisitos de senha (minlength >= 8, pattern de complexidade e/ou texto) e, principalmente, garantir que o BACKEND aplique a mesma política — nunca confiar apenas em validação client-side.',
  });
  return findings;
}
