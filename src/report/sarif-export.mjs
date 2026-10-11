/**
 * Export SARIF 2.1.0 — Static Analysis Results Interchange Format (OASIS).
 *
 * Transforma os findings do Sentinela no formato que GitHub Code Scanning,
 * DefectDojo, SonarQube, Azure DevOps e afins consomem nativamente. Cada achado
 * já carrega OWASP/CWE/confiança/severidade, então o mapeamento é direto e
 * determinístico — sem heurística, sem perda de informação.
 *
 * Design: aditivo e puro (não muta o reportData). Um result por achado de
 * 1ª e 3ª parte com severity != INFO; inventário (INFO) fica de fora (não é
 * vulnerabilidade). ruleId = finding.type; regras deduplicadas em tool.driver.rules.
 */

// Severidade Sentinela → nível SARIF + security-severity (0-10, usado pelo
// GitHub para ordenar/filtrar). CRITICAL/HIGH = error, MEDIUM = warning, resto = note.
const LEVEL = { CRITICAL: 'error', HIGH: 'error', MEDIUM: 'warning', LOW: 'note', INFO: 'note' };
const SEC_SEVERITY = { CRITICAL: '9.5', HIGH: '8.0', MEDIUM: '5.0', LOW: '2.5', INFO: '0.0' };

/** URI de localização: usa a URL do achado; cai pro alvo quando o achado não tem uma. */
function locationUri(f, targetUrl) {
  const raw = (f.url ? String(f.url) : '') .replace(/\s.*$/, '').trim();
  if (raw && /^https?:\/\//i.test(raw)) return raw;
  return String(targetUrl || 'about:blank');
}

/** Extrai o número do CWE (SARIF taxa em "CWE-89"); ignora "—" e múltiplos. */
function cweTags(cwe) {
  if (!cwe || cwe === '—') return [];
  return (String(cwe).match(/CWE-\d+/gi) || []).map(c => c.toUpperCase());
}

/**
 * @param {object} reportData  o objeto salvo no JSON (findings, thirdParty, meta)
 * @param {object} [opts] { toolVersion, infoUri }
 * @returns {object} documento SARIF 2.1.0
 */
export function generateSarif(reportData, opts = {}) {
  const meta = reportData.meta || {};
  const target = meta.target || '';
  const toolVersion = opts.toolVersion || '2.1.1';
  const infoUri = opts.infoUri || 'https://github.com/maykonlong/sentinela';

  const issues = [
    ...(reportData.findings || []),
    ...(reportData.thirdParty || []),
  ].filter(f => f && f.severity !== 'INFO');

  // Regras deduplicadas por type.
  const rulesById = new Map();
  for (const f of issues) {
    const id = f.type || 'finding';
    if (rulesById.has(id)) continue;
    const tags = ['security', ...cweTags(f.cwe)];
    if (f.owasp) tags.push('OWASP');
    rulesById.set(id, {
      id,
      name: id.replace(/_/g, '-'),
      shortDescription: { text: (f.label || id).slice(0, 200) },
      fullDescription: { text: (f.risk || f.label || id).slice(0, 1000) },
      helpUri: infoUri,
      properties: {
        tags,
        'security-severity': SEC_SEVERITY[f.severity] || '0.0',
        owasp: f.owasp || undefined,
        cwe: (f.cwe && f.cwe !== '—') ? f.cwe : undefined,
      },
    });
  }
  const rules = [...rulesById.values()];
  const ruleIndex = new Map(rules.map((r, i) => [r.id, i]));

  const results = issues.map(f => {
    const id = f.type || 'finding';
    const msgParts = [f.label || id];
    if (f.currentValue) msgParts.push(`Evidência: ${f.currentValue}`);
    if (f.risk) msgParts.push(f.risk);
    if (f.recommendation) msgParts.push(`Correção: ${f.recommendation}`);
    return {
      ruleId: id,
      ruleIndex: ruleIndex.get(id),
      level: LEVEL[f.severity] || 'warning',
      message: { text: msgParts.join(' — ').slice(0, 2000) },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: locationUri(f, target) },
          region: { startLine: 1 }, // scanner dinâmico: alvo é URL, não linha de arquivo
        },
      }],
      properties: {
        severity: f.severity,
        confidence: f.confidence || undefined,
        thirdParty: !!f.thirdParty,
        phase: f.phase || undefined,
        'security-severity': SEC_SEVERITY[f.severity] || '0.0',
      },
    };
  });

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'Sentinela',
          version: toolVersion,
          informationUri: infoUri,
          rules,
        },
      },
      // Metadados do alvo/execução (não-padrão, mas SARIF permite properties).
      properties: {
        target,
        timestamp: meta.auditTimestamp || meta.timestamp,
        git_sha: meta.git_sha || opts.gitSha,
        sessionId: meta.sessionId,
        // Lista de fases configuradas não comprova login nem conclusão.
        authenticated: meta.authenticated === true,
        score: meta.score,
        grade: meta.grade,
        firstPartyIssues: meta.firstPartyIssues,
        thirdPartyIssues: meta.thirdPartyIssues,
      },
      invocations: [{ executionSuccessful: meta.executionSuccessful === true }],
      results,
    }],
  };
}
