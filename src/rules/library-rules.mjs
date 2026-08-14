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
      // AngularJS (1.x) está em EOL desde 2022 — qualquer versão é risco.
      { below: '999.0.0', severity: 'HIGH', cve: 'EOL', note: 'AngularJS 1.x está sem suporte (EOL desde jan/2022). Não recebe mais patches de segurança — migrar para Angular moderno.' },
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
export function detectLibraries(scriptUrl, content, opts = {}) {
  const findings = [];

  for (const lib of LIBRARY_DB) {
    const version = extractVersion(lib, scriptUrl, content);
    if (!version) continue;

    // Regras aplicáveis: versão detectada < below.
    const matched = lib.rules.filter(r => lt(version, r.below));
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
