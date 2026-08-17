/**
 * Score Breakdown — Pontuação por categoria com deduções explicadas
 *
 * Calcula o score total e detalha quanto cada categoria contribuiu/perdeu,
 * com explicação textual das deduções.
 */

const CATEGORIES = [
  { id: 'headers',   label: 'Headers de Segurança',         maxPts: 20, types: ['missing_security_header', 'weak_security_header', 'information_disclosure_header', 'cors_wildcard', 'cors_credentials'] },
  { id: 'cookies',   label: 'Cookies',                      maxPts: 20, types: ['cookie_insecure_flags', 'cookie_sensitive_no_httponly'] },
  { id: 'tls',       label: 'TLS / Certificado',            maxPts: 15, types: ['weak_tls', 'cert_expired', 'cert_expiring', 'cert_self_signed', 'no_https'] },
  { id: 'storage',   label: 'Storage (localStorage/session)', maxPts: 10, types: ['storage_sensitive_data', 'storage_jwt_exposed'] },
  { id: 'code',      label: 'Código-fonte',                 maxPts: 15, types: ['exposed_key', 'dangerous_code', 'missing_sri', 'frontend_role_definition', 'source_map_exposed', 'global_variable_sensitive'] },
  { id: 'network',   label: 'Rede e API',                   maxPts: 10, types: ['mixed_content', 'token_in_url', 'password_in_url', 'credential_in_url', 'token_in_non_auth_response'] },
  { id: 'infra',     label: 'Infraestrutura',               maxPts: 10, types: ['exposed_port', 'ip_blacklisted'] },
];

const PENALTY = { CRITICAL: 15, HIGH: 6, MEDIUM: 2, LOW: 0.5 };

/**
 * Calcula o score detalhado por categoria.
 * @param {object[]} firstPartyFindings - Achados de 1ª parte (sem INFO)
 * @returns {object} { totalScore, categories: [{id, label, maxPts, earnedPts, deductions, items}], grade }
 */
export function computeScoreBreakdown(firstPartyFindings) {
  const issues = firstPartyFindings.filter(f => f.severity !== 'INFO');
  const result = [];

  for (const cat of CATEGORIES) {
    const catIssues = issues.filter(f => cat.types.includes(f.type));
    let deduction = 0;
    const deductions = [];

    for (const f of catIssues) {
      const pen = PENALTY[f.severity] || 0;
      deduction += pen;
      deductions.push({
        severity: f.severity,
        label: f.label || f.type,
        penalty: pen,
      });
    }

    // Limitar dedução ao máximo da categoria
    const cappedDeduction = Math.min(deduction, cat.maxPts);
    const earned = cat.maxPts - cappedDeduction;

    result.push({
      id: cat.id,
      label: cat.label,
      maxPts: cat.maxPts,
      earnedPts: Math.max(0, earned),
      deduction: -cappedDeduction,
      issueCount: catIssues.length,
      deductions,
      pct: cat.maxPts > 0 ? Math.round((Math.max(0, earned) / cat.maxPts) * 100) : 100,
    });
  }

  const totalScore = Math.max(0, Math.min(100, result.reduce((sum, c) => sum + c.earnedPts, 0)));

  // Classificação A-F
  let grade, gradeLabel, gradeColor;
  if (totalScore >= 90)      { grade = 'A'; gradeLabel = 'Excelente';          gradeColor = '#2f9e44'; }
  else if (totalScore >= 75) { grade = 'B'; gradeLabel = 'Bom';                gradeColor = '#37b24d'; }
  else if (totalScore >= 60) { grade = 'C'; gradeLabel = 'Precisa Melhorar';   gradeColor = '#f08c00'; }
  else if (totalScore >= 40) { grade = 'D'; gradeLabel = 'Inseguro';           gradeColor = '#e8590c'; }
  else                       { grade = 'F'; gradeLabel = 'Crítico';            gradeColor = '#c92a2a'; }

  return {
    totalScore,
    grade,
    gradeLabel,
    gradeColor,
    categories: result,
  };
}
