/**
 * Testes ATIVOS (Tier 3) — enviam requisições ao alvo, então só rodam com a
 * flag --active (exigem autorização explícita do dono do site).
 *
 * Cobre:
 *   - Métodos HTTP perigosos habilitados (TRACE/PUT/DELETE/CONNECT)
 *   - Ausência de /.well-known/security.txt
 *   - Arquivos sensíveis expostos (.git, .env, server-status, actuator...)
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
    const out = { methods: null, securityTxt: null, files: [] };

    // 1) Métodos HTTP via OPTIONS (same-origin → Allow legível)
    try {
      const res = await fetch(origin + '/', { method: 'OPTIONS' });
      out.methods = { status: res.status, allow: res.headers.get('allow') || res.headers.get('access-control-allow-methods') || '' };
    } catch (e) { out.methods = { error: String(e) }; }

    // 2) security.txt
    try {
      const res = await fetch(origin + '/.well-known/security.txt', { method: 'GET' });
      out.securityTxt = { status: res.status };
    } catch (e) { out.securityTxt = { error: String(e) }; }

    // 3) Arquivos sensíveis
    for (const f of files) {
      try {
        const res = await fetch(origin + f.path, { method: 'GET' });
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
    const tweak = (u) => u.replace(/(\/|=)(\d{1,12})(\/|$|&|\?|;)/, (m, a, num, b) => {
      const n = parseInt(num, 10);
      return a + (n > 1 ? n - 1 : n + 1) + b;
    });
    const out = [];
    for (const it of items) {
      const mod = tweak(it.url);
      if (mod === it.url) continue;
      try {
        const [o, mres] = await Promise.all([
          fetch(it.url, { credentials: 'include' }),
          fetch(mod, { credentials: 'include' }),
        ]);
        const ot = await o.text();
        const mt = await mres.text();
        out.push({ orig: it.url, mod, oStatus: o.status, mStatus: mres.status, oLen: ot.length, mLen: mt.length, mSample: mt.slice(0, 160) });
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
    if (r.oStatus === 200 && r.mStatus === 200 && r.mLen > 50 && ratio > 0.5 && ratio < 2 && !authErr) {
      findings.push({
        type: 'idor_suspected', severity: 'HIGH', thirdParty: false, phase: 'PÓS-LOGIN',
        label: 'Possível IDOR/BOLA — acesso a objeto de outro ID',
        url: r.orig,
        currentValue: `troquei o ID → ${r.mod} | resposta ${r.mStatus}, ${r.mLen} bytes (original ${r.oLen} bytes)`,
        risk: 'Ao trocar o ID na requisição autenticada, o servidor devolveu 200 com conteúdo similar — indício de que é possível acessar dados de OUTRO usuário/registro (Broken Object Level Authorization).',
        recommendation: 'No backend, validar em TODA requisição se o objeto pertence ao usuário autenticado (autorização por objeto), não apenas se está logado.',
      });
    }
  }
  return findings;
}
