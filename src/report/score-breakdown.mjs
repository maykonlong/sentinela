/**
 * Score Breakdown — Pontuação por categoria com deduções explicadas
 *
 * Calcula o score total e detalha quanto cada categoria contribuiu/perdeu,
 * com explicação textual das deduções.
 *
 * ═══════════════════════════════════════════════════════════════════════════
 * POR QUE A FÓRMULA MUDOU (a versão antiga dava "66/100 — C" para um alvo com
 * 28 CRITICAL + 97 HIGH; qualquer pessoa olhando o alvo diria "F")
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * 1. TETO DURO POR CATEGORIA MATAVA A DIFERENCIAÇÃO.
 *    `Math.min(deduction, maxPts)` fazia a categoria `headers` com 206 achados
 *    perder os MESMOS 15 pts que perderia com 1 achado. A soma bruta das
 *    penalidades era 1.239 pts e o score só caía 34. Um site quase íntegro e um
 *    site gravemente comprometido recebiam notas parecidas.
 *    → Agora a dedução é aplicada por DECAIMENTO EXPONENCIAL:
 *         earned = maxPts * e^(-dedução / maxPts)
 *      Continua limitada a [0, maxPts] (nunca "estoura" a categoria), mas é
 *      estritamente monotônica: 1 achado ≠ 10 achados ≠ 200 achados. Perder
 *      exatamente o "orçamento" da categoria (dedução == maxPts) deixa ~37%
 *      dela de pé; a partir daí a categoria tende a zero.
 *
 * 2. PISO ARTIFICIAL DE 60 PTS.
 *    Categorias que o Sentinela nem chegou a avaliar (sem TLS scan, sem infra,
 *    sem storage) entregavam maxPts "de graça" — 60 pts do total. Categoria NÃO
 *    AVALIADA ≠ categoria APROVADA.
 *    → Agora o denominador é DINÂMICO: só categorias efetivamente avaliadas
 *      entram no cálculo (score = 100 * ganhos / máximo das avaliadas).
 *      Como uma categoria é considerada avaliada:
 *        (a) SEM `opts.evaluatedCategories` (caso comum): valem os padrões da
 *            ferramenta — `defaultEvaluated` abaixo. Headers, cookies, TLS,
 *            storage, código, rede, auth, LGPD e libs rodam em toda página;
 *            infra/DNS/TCP e recon rodam em toda sessão. Portanto elas CONTAM
 *            mesmo limpas, e uma auditoria que não achou nada tira 100.
 *        (b) COM `opts.evaluatedCategories`: só as declaradas contam. É assim
 *            que um scan parcial (ex.: `--login-only`, sem fase pós-login)
 *            evita ganhar pontos de graça por checagem que não rodou.
 *      Em qualquer um dos dois modos, uma categoria com achado é sempre
 *      avaliada — se produziu achado, obviamente foi checada.
 *
 *      ⚠️ INVERSÃO JÁ CORRIGIDA: a primeira versão inferia "avaliada" APENAS da
 *      presença de achados. Zero achados tem dois significados — "não rodou" e
 *      "rodou e passou" — e a presença não distingue os dois, então assumia
 *      sempre "não rodou": um alvo limpo zerava o denominador e saía
 *      "0/100 — F, Inseguro", enquanto um alvo com 1 achado LOW tirava "A".
 *      Exatamente ao contrário do correto. Por isso o default agora é
 *      `defaultEvaluated`, e a inferência por presença virou só um reforço.
 *
 * 3. ACHADOS FORA DE `CATEGORIES` NUNCA PONTUAVAM.
 *    31 achados (8,8% de uma sessão real) — incluindo 2 HIGH de
 *    `session_fixation`, `form_no_csrf`, `login_no_csrf`, SPF/DMARC/CAA — não
 *    estavam em nenhuma categoria e eram silenciosamente ignorados pela nota.
 *    → Categorias novas (`auth`, `access`, `recon`, `deps`) + a catch-all
 *      `outros`, que recolhe QUALQUER type não mapeado. Nenhum achado é
 *      descartado; `unmappedTypes` no retorno denuncia os que caíram na
 *      catch-all para serem classificados depois.
 *
 * 4. SEM TRAVA POR SEVERIDADE.
 *    Média ponderada dilui: dava para ter CRITICAL confirmado e nota "C".
 *    → Teto de grade por severidade (ver GRADE_CAPS).
 *
 * 5. REPETIÇÃO NÃO PESAVA.
 *    Com a dedup (src/report/dedup.mjs), o mesmo header ausente em 27 páginas
 *    virou 1 achado com `occurrenceCount: 27`. Ignorar isso trata 27 páginas
 *    expostas como 1. Contar linearmente traz de volta a inflação de antes.
 *    → Fator LOGARÍTMICO com retorno decrescente (ver occurrenceFactor).
 *
 * Os pesos (`maxPts`) NÃO precisam mais somar 100 — o denominador dinâmico
 * normaliza. Eles são peso RELATIVO entre categorias.
 */

/**
 * `defaultEvaluated`: a checagem roda em TODA auditoria padrão do Sentinela, e
 * portanto, quando o chamador não declara nada, a categoria entra no
 * denominador mesmo limpa (categoria limpa = pontos ganhos, não pontos de
 * graça). As exceções são as categorias que só existem em modos específicos:
 *   - `access`: depende de `--active` (IDOR, open redirect, diff de acesso).
 *   - `outros`: catch-all; só faz sentido quando de fato recebeu algum achado.
 * Ambas só entram no cálculo se produzirem achado.
 */
const CATEGORIES = [
  { id: 'headers',   label: 'Headers de Segurança',           maxPts: 15, defaultEvaluated: true, types: ['missing_security_header', 'weak_security_header', 'information_disclosure_header', 'cors_wildcard', 'cors_credentials', 'cors_reflected', 'cache_control_sensitive', 'http_method_enabled'] },
  { id: 'cookies',   label: 'Cookies',                        maxPts: 12, defaultEvaluated: true, types: ['cookie_insecure_flags', 'cookie_sensitive_no_httponly', 'cookie_missing_secure_prefix'] },
  { id: 'tls',       label: 'TLS / Certificado',              maxPts: 15, defaultEvaluated: true, types: ['weak_tls', 'cert_expired', 'cert_expiring', 'cert_self_signed', 'no_https', 'http_downgrade'] },
  { id: 'storage',   label: 'Storage (localStorage/session)', maxPts: 10, defaultEvaluated: true, types: ['storage_sensitive_data', 'storage_jwt_exposed', 'pii_in_storage', 'pii_in_storage_value'] },
  { id: 'code',      label: 'Código-fonte e Runtime',         maxPts: 12, defaultEvaluated: true, types: ['exposed_key', 'dangerous_code', 'missing_sri', 'frontend_role_definition', 'source_map_exposed', 'source_map_content_exposed', 'source_map_internal_routes', 'global_variable_sensitive', 'console_sensitive', 'console_error', 'target_blank_noopener', 'browser_issue'] },
  { id: 'network',   label: 'Rede e API',                     maxPts: 10, defaultEvaluated: true, types: ['mixed_content', 'token_in_url', 'password_in_url', 'credential_in_url', 'token_in_non_auth_response', 'pii_in_url', 'pii_in_url_value', 'sensitive_in_url', 'sensitive_in_body', 'password_in_response', 'insecure_websocket'] },
  { id: 'infra',     label: 'Infraestrutura e DNS',           maxPts: 10, defaultEvaluated: true, types: ['exposed_port', 'ip_blacklisted', 'missing_spf_record', 'missing_dmarc_record', 'missing_caa_record', 'missing_ptr_record'] },
  { id: 'lgpd',      label: 'LGPD & Privacidade',             maxPts: 10, defaultEvaluated: true, types: ['missing_privacy_policy', 'missing_form_optin', 'cookie_consent_violation'] },

  // ── Categorias novas: recolhem os achados que antes não pontuavam ──
  { id: 'auth',      label: 'Autenticação e Sessão',          maxPts: 15, defaultEvaluated: true, types: ['session_fixation', 'form_no_csrf', 'login_no_csrf', 'user_enumeration', 'no_rate_limit', 'weak_password_policy', 'login_password_maxlength', 'login_password_visible', 'login_password_autocomplete', 'password_autocomplete', 'auth_over_http', 'login_form_http', 'login_forgot_password_http', 'login_form_get', 'form_get_sensitive', 'login_password_in_url', 'login_password_in_response', 'login_token_in_response', 'login_token_in_url', 'login_redirect_with_token', 'login_credentials_sent', 'login_role_in_response', 'cross_origin_auth'] },
  { id: 'access',    label: 'Controle de Acesso',             maxPts: 15, defaultEvaluated: false, types: ['idor_suspected', 'idor_confirmed', 'broken_access_control', 'privilege_escalation', 'open_redirect', 'excessive_data_exposure'] },
  { id: 'recon',     label: 'Exposição e Recon',              maxPts: 8,  defaultEvaluated: true, types: ['tech_fingerprint', 'robots_disclosure', 'sitemap_disclosure', 'exposed_sensitive_file', 'backup_file_exposed', 'api_docs_exposed', 'graphql_introspection', 'graphql_introspection_enabled', 'openid_config_exposed', 'verbose_error', 'missing_security_txt', 'cloud_bucket_detected'] },
  { id: 'deps',      label: 'Dependências (libs)',            maxPts: 10, defaultEvaluated: true, types: ['vulnerable_library', 'vulnerable_library_osv'] },

  // Catch-all: qualquer type que ainda não foi classificado. Existe para que
  // NENHUM achado seja silenciosamente ignorado pela nota. Peso baixo de
  // propósito — é o purgatório, não um destino final: veja `unmappedTypes`.
  { id: 'outros',    label: 'Outros achados',                 maxPts: 8,  defaultEvaluated: false, types: [] },
];

const CATALOGUED_TYPES = new Set(CATEGORIES.flatMap(c => c.types));

const PENALTY = { CRITICAL: 15, HIGH: 6, MEDIUM: 2, LOW: 0.5 };

/**
 * Teto de grade. Um alvo com CRITICAL confirmado não pode sair com "C, Precisa
 * Melhorar" só porque o resto do site está bem — a nota é um resumo de RISCO, e
 * risco é dominado pelo PIOR achado, não pela média. A média ponderada sozinha
 * sempre dilui: uma categoria zerada custa só o peso dela.
 *
 * As 3 primeiras regras são por severidade; a 4ª é ESTRUTURAL (uma categoria
 * inteira desmoronada — ex.: 9 headers ausentes em 27 páginas, tudo MEDIUM —
 * não pode conviver com "Excelente"). Todas são avaliadas e vence a MAIS
 * SEVERA, não a primeira que casar.
 */
const GRADE_CAPS = [
  { id: 'critical', maxGrade: 'D', maxScore: 59,
    when: (c) => c.CRITICAL >= 1,
    reason: (c) => `${c.CRITICAL} achado(s) CRITICAL — nota limitada a D` },
  { id: 'high3', maxGrade: 'C', maxScore: 74,
    when: (c) => c.HIGH >= 3,
    reason: (c) => `${c.HIGH} achados HIGH (≥3) — nota limitada a C` },
  { id: 'high1', maxGrade: 'B', maxScore: 89,
    when: (c) => c.HIGH >= 1,
    reason: (c) => `${c.HIGH} achado(s) HIGH — nota limitada a B (não pode ser "Excelente")` },
  { id: 'categoria_colapsada', maxGrade: 'B', maxScore: 89,
    when: (c, cats) => cats.some(x => x.evaluated && x.pct < 50),
    reason: (c, cats) => `categoria(s) abaixo de 50% (${cats.filter(x => x.evaluated && x.pct < 50).map(x => x.id).join(', ')}) — nota limitada a B` },
];

const GRADES = [
  { min: 90, grade: 'A', label: 'Excelente',        color: '#2f9e44' },
  { min: 75, grade: 'B', label: 'Bom',              color: '#37b24d' },
  { min: 60, grade: 'C', label: 'Precisa Melhorar', color: '#f08c00' },
  { min: 40, grade: 'D', label: 'Inseguro',         color: '#e8590c' },
  { min: 0,  grade: 'F', label: 'Crítico',          color: '#c92a2a' },
];

/**
 * Peso da repetição. `occurrenceCount` vem da dedup: um header ausente em 27
 * páginas é 1 achado observado 27 vezes. Ignorar isso trata 27 páginas
 * expostas como 1; multiplicar linearmente devolve a inflação (27x a
 * penalidade). O log10 dá retorno decrescente e um teto explícito:
 *   1 ocorrência → 1.00x | 10 → 2.00x | 27 → 2.43x | 100 → 3.00x (teto)
 * Ou seja: repetir importa, mas repetir muito importa cada vez menos.
 */
const OCCURRENCE_FACTOR_MAX = 3;
function occurrenceFactor(finding) {
  const n = Number(finding.occurrenceCount) || 1;
  if (n <= 1) return 1;
  return Math.min(1 + Math.log10(n), OCCURRENCE_FACTOR_MAX);
}

function round1(n) { return Math.round(n * 10) / 10; }

/**
 * Calcula o score detalhado por categoria.
 *
 * @param {object[]} firstPartyFindings - Achados de 1ª parte (INFO é descartado
 *        para penalidade, mas conta como prova de que a categoria foi avaliada)
 * @param {object} [opts]
 * @param {string[]|Set<string>} [opts.evaluatedCategories] - ids de categorias
 *        que comprovadamente rodaram (mesmo sem achado). Use isto para que uma
 *        categoria LIMPA ganhe os pontos dela em vez de ficar fora do cálculo.
 *        Ex.: `{ evaluatedCategories: ['tls', 'infra'] }` quando o scan de TLS e
 *        o de infra rodaram de fato.
 * @param {object[]} [opts.allFindings] - lista completa (com INFO). Achados de
 *        inventário (cookie_inventory, storage_inventory…) provam que a
 *        categoria foi inspecionada mesmo estando limpa.
 * @returns {object} { totalScore, rawScore, grade, gradeLabel, gradeColor,
 *                     gradeCap, severityCounts, categories[], unmappedTypes[] }
 *        ATENÇÃO: se NENHUMA categoria foi avaliada, `totalScore`/`rawScore`
 *        vêm `null` e a grade é 'N/A' / 'Não avaliado' — o relatório deve tratar
 *        esse caso em vez de imprimir "null/100".
 */
export function computeScoreBreakdown(firstPartyFindings, opts = {}) {
  const all = Array.isArray(firstPartyFindings) ? firstPartyFindings : [];
  const issues = all.filter(f => f.severity !== 'INFO');

  // Achados usados só para detectar "a categoria foi avaliada?" — inclui INFO.
  const evidence = Array.isArray(opts.allFindings) && opts.allFindings.length
    ? opts.allFindings
    : all;

  // O chamador declarou explicitamente o que rodou? Diferente de "declarou uma
  // lista vazia": `undefined`/`null` = "use os padrões da ferramenta"; uma lista
  // (mesmo vazia) = "confie só no que estou dizendo".
  const hasExplicitScope = opts.evaluatedCategories !== undefined && opts.evaluatedCategories !== null;
  const declared = new Set(hasExplicitScope ? opts.evaluatedCategories : []);

  // Types que não pertencem a nenhuma categoria vão para `outros`.
  const unmappedTypes = [...new Set(
    issues.map(f => f.type).filter(t => t && !CATALOGUED_TYPES.has(t))
  )].sort();

  const belongsTo = (cat, f) =>
    cat.id === 'outros' ? !CATALOGUED_TYPES.has(f.type) : cat.types.includes(f.type);

  const result = [];
  for (const cat of CATEGORIES) {
    const catIssues = issues.filter(f => belongsTo(cat, f));
    const hasEvidence = evidence.some(f => belongsTo(cat, f));
    // Com escopo explícito, só vale o que o chamador declarou; sem escopo, valem
    // os padrões. Nos dois modos, ter achado já prova que a checagem rodou.
    const evaluated = hasEvidence
      || (hasExplicitScope ? declared.has(cat.id) : cat.defaultEvaluated === true);

    let deduction = 0;
    const deductions = [];
    for (const f of catIssues) {
      const base = PENALTY[f.severity] || 0;
      const factor = occurrenceFactor(f);
      const pen = base * factor;
      deduction += pen;
      deductions.push({
        severity: f.severity,
        label: f.label || f.type,
        penalty: round1(pen),
        basePenalty: base,
        occurrenceCount: Number(f.occurrenceCount) || 1,
        occurrenceFactor: round1(factor),
      });
    }

    // Decaimento exponencial em vez de teto duro: preserva a ordenação entre
    // "1 achado" e "200 achados" sem nunca ultrapassar o peso da categoria.
    const earnedRaw = evaluated
      ? cat.maxPts * Math.exp(-deduction / cat.maxPts)
      : cat.maxPts;                     // não avaliada: fora do denominador
    const earned = Math.max(0, Math.min(cat.maxPts, earnedRaw));

    result.push({
      id: cat.id,
      label: cat.label,
      maxPts: cat.maxPts,
      earnedPts: Math.round(earned),
      earnedPtsExact: round1(earned),
      // `deduction` continua negativo e em pontos da categoria, como antes:
      // é quanto a categoria perdeu de fato (maxPts - earned).
      deduction: -round1(cat.maxPts - earned),
      rawDeduction: round1(deduction),   // soma bruta, antes do decaimento
      issueCount: catIssues.length,
      occurrenceTotal: catIssues.reduce((s, f) => s + (Number(f.occurrenceCount) || 1), 0),
      evaluated,
      deductions,
      pct: cat.maxPts > 0 ? Math.round((earned / cat.maxPts) * 100) : 100,
    });
  }

  // ── Denominador dinâmico: só categorias avaliadas ──
  const scored = result.filter(c => c.evaluated);
  const maxPossible = scored.reduce((s, c) => s + c.maxPts, 0);
  const earnedTotal = scored.reduce((s, c) => s + c.earnedPtsExact, 0);

  const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of issues) {
    if (severityCounts[f.severity] !== undefined) severityCounts[f.severity]++;
  }

  // ── Blindagem: denominador zero ──
  // Só acontece se o chamador passar um escopo explícito vazio E não houver
  // nenhum achado. Não existe nota honesta aí: 0/0 não é "zero de nota", é
  // "não medido". Devolver 0/F faria o relatório dizer "INSEGURO" sobre algo
  // que sequer foi checado — mentira pior do que não responder.
  if (maxPossible === 0) {
    return {
      totalScore: null,
      rawScore: null,
      grade: 'N/A',
      gradeLabel: 'Não avaliado',
      gradeColor: '#868e96',
      gradeCap: { applied: false, maxGrade: null, reason: 'nenhuma categoria foi avaliada', rules: [] },
      severityCounts,
      maxPossible: 0,
      evaluatedCategories: 0,
      unmappedTypes,
      categories: result,
    };
  }

  let rawScore = Math.max(0, Math.min(100, Math.round((earnedTotal / maxPossible) * 100)));
  // 100 é reservado para "nenhuma dedução". Sem isto, 1 achado LOW (0,5 pt em
  // 127) arredonda de volta para 100 e a nota fica IDÊNTICA à de um alvo sem
  // nenhum achado — o relatório listaria o problema e a nota diria "perfeito".
  if (rawScore === 100 && earnedTotal < maxPossible - 1e-9) rawScore = 99;

  // ── Trava por severidade ──

  // Vence o teto MAIS severo entre todos os que casarem (menor maxScore).
  const hits = GRADE_CAPS.filter(cap => cap.when(severityCounts, result));
  const strictest = hits.reduce((best, cap) => (!best || cap.maxScore < best.maxScore ? cap : best), null);

  let totalScore = rawScore;
  let gradeCap = { applied: false, maxGrade: null, reason: null, rules: hits.map(h => h.id) };
  if (strictest) {
    // `applied` só é true quando o teto REALMENTE baixou a nota; se o alvo já
    // estava abaixo do teto, a regra existe mas não mudou nada — e o relatório
    // não deve dizer "nota rebaixada" sem ter rebaixado.
    const applied = rawScore > strictest.maxScore;
    if (applied) totalScore = strictest.maxScore;
    gradeCap = {
      applied,
      maxGrade: strictest.maxGrade,
      reason: strictest.reason(severityCounts, result),
      rules: hits.map(h => h.id),
    };
  }

  const g = GRADES.find(x => totalScore >= x.min) || GRADES[GRADES.length - 1];

  return {
    totalScore,
    rawScore,                 // nota antes da trava por severidade
    grade: g.grade,
    gradeLabel: g.label,
    gradeColor: g.color,
    gradeCap,                 // { applied, maxGrade, reason }
    severityCounts,
    maxPossible,              // soma dos pesos das categorias AVALIADAS
    evaluatedCategories: scored.length,
    unmappedTypes,            // types que caíram na catch-all `outros`
    categories: result,
  };
}

/** Ids das categorias conhecidas — útil para o chamador montar `evaluatedCategories`. */
export function listCategoryIds() {
  return CATEGORIES.map(c => c.id);
}
