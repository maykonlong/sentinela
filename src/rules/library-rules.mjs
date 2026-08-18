/**
 * Detecção de bibliotecas JavaScript com versões vulneráveis (estilo retire.js).
 * Identifica a lib + versão (via URL do script ou assinatura no conteúdo) e
 * cruza com faixas conhecidamente vulneráveis (CVE).
 *
 * Base curada e enxuta focada nas libs mais comuns em produção. Não é
 * exaustiva como a base do retire.js, mas cobre os casos que mais aparecem.
 */

// Comparação semver simples (major.minor.patch). Retorna -1, 0 ou 1.
function cmpVersion(a, b) {
  const pa = String(a).split('.').map(n => parseInt(n, 10) || 0);
  const pb = String(b).split('.').map(n => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i++) {
    const x = pa[i] || 0, y = pb[i] || 0;
    if (x < y) return -1;
    if (x > y) return 1;
  }
  return 0;
}
const lt = (a, b) => cmpVersion(a, b) < 0;

// Base de dados: cada lib tem regex de URL e de conteúdo para extrair a versão,
// e uma lista de regras {below, severity, cve, note}.
const LIBRARY_DB = [
  {
    name: 'jQuery',
    urlRe: /jquery[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i,
    contentRe: /jQuery(?:\s+JavaScript\s+Library)?\s+v(\d+\.\d+\.\d+)/,
    rules: [
      { below: '3.5.0', severity: 'HIGH', cve: 'CVE-2020-11022 / CVE-2020-11023', note: 'XSS via manipulação de HTML de fontes não confiáveis (htmlPrefilter).' },
      { below: '3.4.0', severity: 'HIGH', cve: 'CVE-2019-11358', note: 'Prototype pollution via jQuery.extend.' },
      { below: '1.9.0', severity: 'HIGH', cve: 'CVE-2012-6708 / CVE-2015-9251', note: 'XSS em versões antigas (seletor $() com HTML).' },
    ],
  },
  {
    name: 'jQuery UI',
    urlRe: /jquery-ui[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i,
    contentRe: /jQuery UI[\s\S]{0,20}?(\d+\.\d+\.\d+)/,
    rules: [
      { below: '1.13.2', severity: 'MEDIUM', cve: 'CVE-2022-31160', note: 'XSS no widget de checkboxradio (label).' },
      { below: '1.12.0', severity: 'MEDIUM', cve: 'CVE-2016-7103', note: 'XSS na opção closeText do Dialog.' },
    ],
  },
  {
    name: 'Bootstrap',
    urlRe: /bootstrap[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.(?:js|css)/i,
    contentRe: /Bootstrap\s+v(\d+\.\d+\.\d+)/,
    rules: [
      { below: '4.3.1', severity: 'MEDIUM', cve: 'CVE-2019-8331', note: 'XSS via atributos data-* (tooltip/popover).' },
      { below: '3.4.1', severity: 'MEDIUM', cve: 'CVE-2018-14041 / CVE-2019-8331', note: 'XSS em componentes (v3.x). Atualizar para 3.4.1+.' },
    ],
  },
  {
    name: 'AngularJS',
    urlRe: /angular[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i,
    contentRe: /AngularJS\s+v(\d+\.\d+\.\d+)/,
    rules: [
      // AngularJS (1.x) está em EOL desde 2022 — qualquer versão 1.x é risco.
      // O guard `when` é obrigatório: a urlRe casa também `angular-17.3.0.js`
      // (Angular moderno, produto diferente e com suporte ativo), que sem ele
      // seria reportado como "AngularJS 1.x em EOL" HIGH — falso-positivo puro.
      {
        below: '999.0.0',
        when: (v) => parseInt(String(v).split('.')[0], 10) === 1,
        severity: 'HIGH',
        cve: 'EOL',
        note: 'AngularJS 1.x está sem suporte (EOL desde jan/2022). Não recebe mais patches de segurança — migrar para Angular moderno.',
      },
    ],
  },
  {
    name: 'Lodash',
    urlRe: /lodash[-.@](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i,
    contentRe: /lodash[\s\S]{0,80}?VERSION\s*=\s*['"](\d+\.\d+\.\d+)['"]/,
    rules: [
      { below: '4.17.21', severity: 'HIGH', cve: 'CVE-2021-23337 / CVE-2020-8203', note: 'Command injection (template) e prototype pollution.' },
    ],
  },
  {
    name: 'Moment.js',
    urlRe: /moment[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i,
    contentRe: /\/\/!\s*version\s*:\s*(\d+\.\d+\.\d+)/,
    rules: [
      { below: '2.29.4', severity: 'MEDIUM', cve: 'CVE-2022-31129', note: 'ReDoS no parsing de datas. Além disso, Moment.js está em modo legado (recomendado migrar).' },
    ],
  },
  {
    name: 'Handlebars',
    urlRe: /handlebars[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i,
    contentRe: /Handlebars[\s\S]{0,40}?(?:VERSION\s*=\s*|@version\s+)['"]?(\d+\.\d+\.\d+)/,
    rules: [
      { below: '4.7.7', severity: 'HIGH', cve: 'CVE-2021-23369 / CVE-2019-19919', note: 'Prototype pollution → RCE no servidor ao compilar templates.' },
    ],
  },
  {
    name: 'DOMPurify',
    urlRe: /(?:dom)?purify[-.@](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i,
    contentRe: /DOMPurify[\s\S]{0,40}?version\s*[=:]\s*['"](\d+\.\d+\.\d+)['"]/,
    rules: [
      { below: '3.0.0', severity: 'MEDIUM', cve: 'múltiplos bypasses', note: 'Versões antigas têm bypasses de sanitização conhecidos. Atualizar para a mais recente.' },
    ],
  },
];

function extractVersion(lib, scriptUrl, content) {
  if (scriptUrl && lib.urlRe) {
    const m = scriptUrl.match(lib.urlRe);
    if (m && m[1]) return m[1];
  }
  if (content && lib.contentRe) {
    const m = content.match(lib.contentRe);
    if (m && m[1]) return m[1];
  }
  return null;
}

/**
 * Detecta bibliotecas vulneráveis num script (por URL e/ou conteúdo).
 * @param {string} scriptUrl
 * @param {string} content  conteúdo do script (pode ser vazio)
 * @param {object} opts     { thirdParty, vendor }
 * @returns {Array} findings
 */
/**
 * Detecta biblioteca+versão SEM filtrar por vulnerabilidade conhecida — ao
 * contrário de `detectLibraries`, que só devolve algo quando a versão já bate
 * numa CVE hardcoded aqui embaixo. É o que alimenta `checkOsvVulnerabilities`:
 * uma versão "não vulnerável" pela lista fixa pode ter CVE nova no OSV.dev que
 * ninguém lembrou de adicionar aqui (confirmado na prática: lodash@4.17.21, a
 * própria versão marcada como "corrigida" neste arquivo, tem 3 advisories
 * abertos no OSV — a lista fixa fica desatualizada por natureza).
 */
export function detectAllLibraryVersions(scriptUrl, content) {
  const out = [];
  for (const lib of LIBRARY_DB) {
    const version = extractVersion(lib, scriptUrl, content);
    if (version) out.push({ name: lib.name, version });
  }
  return out;
}

export function detectLibraries(scriptUrl, content, opts = {}) {
  const findings = [];

  for (const lib of LIBRARY_DB) {
    const version = extractVersion(lib, scriptUrl, content);
    if (!version) continue;

    // Regras aplicáveis: versão detectada < below (e, se a regra tiver um guard
    // `when`, ele também precisa passar — ex.: restringir a AngularJS major 1).
    const matched = lib.rules.filter(r => lt(version, r.below) && (!r.when || r.when(version)));
    if (matched.length === 0) continue;

    // Consolidar num único finding por lib.
    const order = { CRITICAL: 3, HIGH: 2, MEDIUM: 1, LOW: 0 };
    const worst = matched.reduce((a, b) => (order[b.severity] > order[a.severity] ? b : a));
    const fixedIn = matched
      .map(r => r.below)
      .filter(v => v !== '999.0.0')
      .sort(cmpVersion)
      .pop();
    const cves = [...new Set(matched.map(r => r.cve))].join('; ');
    const notes = matched.map(r => r.note).join(' ');

    findings.push({
      type: 'vulnerable_library',
      severity: worst.severity,
      thirdParty: !!opts.thirdParty,
      vendor: opts.vendor || null,
      label: `Biblioteca vulnerável: ${lib.name} ${version}`,
      library: lib.name,
      version,
      fixedIn: fixedIn || null,
      cve: cves,
      url: scriptUrl,
      risk: `${lib.name} ${version} tem vulnerabilidade(s) conhecida(s) [${cves}]. ${notes}`,
      recommendation: fixedIn
        ? `Atualizar ${lib.name} para ${fixedIn} ou superior.`
        : `Substituir ${lib.name} por uma alternativa com suporte ativo.`,
    });
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Verificação real via OSV.dev (Open Source Vulnerabilities, mantida pela
// Google/OpenSSF) — complementa a base fixa acima com dados vivos, sem
// depender de alguém lembrar de atualizar CVEs hardcoded neste arquivo.
// ---------------------------------------------------------------------------

// Nomes de exibição (os que aparecem em LIBRARY_DB / no relatório) → nome do
// pacote no ecossistema npm, que é o que a API do OSV espera em `package.name`
// para `ecosystem: 'npm'`. Testado contra a API real (ver relatório da tarefa):
// 'jquery-ui-dist' (o pacote "óbvio") NÃO tem advisories associados no OSV;
// quem recebe os GHSA de jQuery UI é o pacote 'jquery-ui'.
const NPM_PACKAGE_NAME = {
  'jquery': 'jquery',
  'jquery ui': 'jquery-ui',
  'bootstrap': 'bootstrap',
  'angularjs': 'angular',
  'lodash': 'lodash',
  'moment.js': 'moment',
  'handlebars': 'handlebars',
  'dompurify': 'dompurify',
};

// Fallback para libs fora da lista curada acima: normaliza o nome de exibição
// num slug plausível de pacote npm (best-effort — não garante que exista).
function guessNpmPackageName(displayName) {
  const key = String(displayName || '').trim().toLowerCase();
  if (NPM_PACKAGE_NAME[key]) return NPM_PACKAGE_NAME[key];
  return key
    .replace(/\.js$/, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

// fetch com timeout — mesmo padrão de recon-rules.mjs/active-rules.mjs, mas
// via fetch nativo do Node (Node 18+; este projeto roda em Node 24), já que
// esta chamada é para o OSV.dev e não para a página auditada (não precisa de
// page.evaluate).
async function fetchWithTimeout(url, opts = {}, ms = 8000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}

/**
 * Consulta o OSV.dev (batch) para uma lista de bibliotecas já detectadas
 * (name+version) e devolve findings no MESMO formato usado pelo resto deste
 * arquivo. 100% passiva para o alvo auditado — só conversa com api.osv.dev.
 *
 * IMPORTANTE (ausência de evidência não é evidência de vulnerabilidade):
 * qualquer falha de rede/timeout/parse devolve [] silenciosamente. NUNCA cria
 * finding de "vulnerável" a partir de erro, e NUNCA cria um "PASS"/afirmação
 * de que a lib está limpa — só afirma o que o OSV realmente confirmou.
 *
 * @param {Array<{name:string, version:string, ecosystem?:string, url?:string, contexts?:string[], thirdParty?:boolean, vendor?:string}>} detectedLibraries
 *   Lista já consolidada da sessão (pode ter duplicatas — este função dedupa
 *   por name+version antes de consultar). `ecosystem` default 'npm'.
 * @param {object} [opts]
 * @param {number} [opts.timeoutMs=8000]
 * @param {string} [opts.batchUrl] override para testes (padrão: OSV.dev real)
 * @param {(info:{name:string,version:string,error:string})=>void} [opts.onNotVerified]
 *   callback opcional chamado quando uma consulta não pôde ser verificada
 *   (rede/timeout/parse) — NÃO gera finding, é só para log/telemetria.
 * @returns {Promise<Array>} findings (vazio se nada encontrado OU se a
 *   consulta falhou — os dois casos são indistinguíveis no array em si;
 *   use onNotVerified se precisar diferenciar).
 */
export async function checkOsvVulnerabilities(detectedLibraries, opts = {}) {
  const timeoutMs = opts.timeoutMs || 8000;
  const batchUrl = opts.batchUrl || 'https://api.osv.dev/v1/querybatch';

  if (!Array.isArray(detectedLibraries) || detectedLibraries.length === 0) return [];

  // Dedupe por name+version (normalizado), mesclando contexts/urls de todas
  // as ocorrências para não perder onde a lib apareceu.
  const dedup = new Map();
  for (const item of detectedLibraries) {
    if (!item || !item.name || !item.version) continue;
    const key = `${String(item.name).trim().toLowerCase()}@@${String(item.version).trim()}`;
    if (!dedup.has(key)) {
      dedup.set(key, {
        name: item.name,
        version: item.version,
        ecosystem: item.ecosystem || 'npm',
        packageName: guessNpmPackageName(item.name),
        thirdParty: !!item.thirdParty,
        vendor: item.vendor || null,
        contexts: new Set(),
      });
    }
    const entry = dedup.get(key);
    if (item.url) entry.contexts.add(item.url);
    if (Array.isArray(item.contexts)) for (const c of item.contexts) entry.contexts.add(c);
  }

  const entries = [...dedup.values()];
  if (entries.length === 0) return [];

  const queries = entries.map(e => ({ package: { name: e.packageName, ecosystem: e.ecosystem }, version: e.version }));

  let data;
  try {
    const res = await fetchWithTimeout(batchUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ queries }),
    }, timeoutMs);

    if (!res.ok) {
      // Erro HTTP do OSV (rate limit, 5xx, etc.) — não verificado, não é achado.
      for (const e of entries) opts.onNotVerified?.({ name: e.name, version: e.version, error: `HTTP ${res.status}` });
      return [];
    }
    data = await res.json();
  } catch (err) {
    // Timeout (AbortError), DNS, rede indisponível, JSON malformado...
    for (const e of entries) opts.onNotVerified?.({ name: e.name, version: e.version, error: String(err && err.message || err) });
    return [];
  }

  const results = Array.isArray(data?.results) ? data.results : null;
  if (!results || results.length !== entries.length) {
    // Resposta em formato inesperado — não dá pra confiar no alinhamento
    // índice-a-índice com `entries`. Trata como não verificado.
    for (const e of entries) opts.onNotVerified?.({ name: e.name, version: e.version, error: 'resposta OSV em formato inesperado' });
    return [];
  }

  const findings = [];
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    const vulns = Array.isArray(results[i]?.vulns) ? results[i].vulns : [];
    if (vulns.length === 0) continue; // OSV não achou nada para essa versão — não é finding (e também não é "PASS" explícito, só ausência).

    const ids = vulns.map(v => v.id).filter(Boolean);

    // O endpoint de BATCH do OSV (testado ao vivo em 2026-08-18 contra
    // jquery@1.8.2, bootstrap@3.4.0, lodash@4.17.10 etc.) devolve só
    // {id, modified} por vulnerabilidade — SEM summary, SEM severity/CVSS,
    // ao contrário do que a doc de alto nível sugere. Buscar o detalhe de
    // cada id via GET /v1/vulns/{id} exigiria 1 chamada extra por CVE (podem
    // ser dezenas por lib) — evitado de propósito (ver instrução da tarefa).
    // Sem CVSS disponível, usamos HIGH como severidade padrão CONSERVADORA:
    // é uma vulnerabilidade catalogada e real (não uma heurística nossa),
    // então preferimos superestimar a subestimar.
    const severity = 'HIGH';

    findings.push({
      type: 'vulnerable_library_osv',
      severity,
      thirdParty: entry.thirdParty,
      vendor: entry.vendor,
      label: `Vulnerabilidade conhecida (OSV.dev): ${entry.name} ${entry.version} — ${ids.length} ${ids.length > 1 ? 'advisories' : 'advisory'}`,
      library: entry.name,
      version: entry.version,
      ecosystem: entry.ecosystem,
      packageName: entry.packageName,
      osvIds: ids,
      cve: ids.join('; '),
      url: [...entry.contexts][0] || null,
      occurrenceUrls: [...entry.contexts],
      risk: `${entry.name} ${entry.version} tem ${ids.length} vulnerabilidade(s) catalogada(s) no OSV.dev [${ids.join(', ')}]. Severidade não informada pelo endpoint de batch — assumida HIGH por padrão conservador; consulte os links abaixo para o CVSS real de cada advisory.`,
      recommendation: `Revisar ${ids.map(id => `https://osv.dev/vulnerability/${id}`).join(', ')} e atualizar ${entry.name} para uma versão sem vulnerabilidades conhecidas.`,
    });
  }

  return findings;
}
