/**
 * HTML Report Generator — Relatório empresarial moderno
 * 
 * Gera um HTML completo, responsivo e interativo com:
 *  - Capa executiva com selo A-F e nota
 *  - Sumário Executivo para C-level
 *  - Infraestrutura completa (IP, GeoIP, Socket timing, Portas TCP, Reputação DNSBL)
 *  - Registros DNS de Segurança (SPF, DMARC, CAA, IPv6)
 *  - Score breakdown por categoria com barras visuais
 *  - Achados agrupados por OWASP com instruções de verificação manual (Prova Real + Teste Focado)
 *  - Botões de copiar em 1 clique para TODOS os comandos, portas e rotas
 *  - Links clicáveis em todas as URLs e endpoints
 *  - Screenshots da auditoria
 *  - Timeline detalhada
 *  - Artefatos de teste gerados (Playwright, cURL, Nginx, Apache)
 *  - Apêndice com metodologia, glossário e aviso legal
 */

import { titleOf, reachOf, dnsRecordState, reputationState, portConfidence, tcpScanNotice } from './labels.mjs';

function esc(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

const SEV_COLOR = {
  CRITICAL: '#c92a2a',
  HIGH:     '#e8590c',
  MEDIUM:   '#f08c00',
  LOW:      '#1c7ed6',
  INFO:     '#868e96',
};

const SEV_EMOJI = {
  CRITICAL: '🔴',
  HIGH:     '🟠',
  MEDIUM:   '🟡',
  LOW:      '🔵',
  INFO:     'ℹ️',
};

// Cor por nota, usada só se `scoreBreakdown.gradeColor` não vier (o módulo de
// score é de outro dono e pode mudar de forma; não queremos acoplar a ele).
const GRADE_FALLBACK_COLOR = {
  A: '#2f9e44', B: '#37b24d', C: '#f08c00', D: '#e8590c', F: '#c92a2a',
};

/**
 * Gera o HTML empresarial standalone do relatório.
 */
export function generateEnterpriseHtml({
  meta, findings, thirdParty, routes, pagesVisited, inventory,
  scoreBreakdown, infraData, screenshots, timeline, testArtifacts,
  regression, counts, evidenceOf,
}) {
  // Leitura defensiva: computeScoreBreakdown está sendo redesenhado e pode
  // ganhar campos novos. Só dependemos de totalScore/grade/gradeLabel, e
  // toleramos a ausência de gradeColor/categories sem quebrar o relatório.
  const sb = scoreBreakdown || {};
  const score = sb.totalScore ?? 0;
  const grade = sb.grade ?? '—';
  const gradeLabel = sb.gradeLabel ?? '';
  const gradeColor = sb.gradeColor || GRADE_FALLBACK_COLOR[grade] || '#868e96';
  const scoreCategories = Array.isArray(sb.categories) ? sb.categories : [];

  const card = (label, val, color) => `
    <div class="card">
      <div class="num" style="color:${color}">${val}</div>
      <div class="lbl">${label}</div>
    </div>`;

  // ── CSS ──
  const css = `<style>
    * { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #f4f5f7; color: #212529; margin: 0; padding: 20px; line-height: 1.5; font-size: 14px; }
    .wrap { max-width: 1100px; margin: 0 auto; }
    a { color: #1c7ed6; text-decoration: none; }
    a:hover { text-decoration: underline; }
    
    /* ── Capa ── */
    .cover { background: linear-gradient(135deg, #1a1b1e 0%, #2c2e33 100%); color: #fff; border-radius: 16px; padding: 36px; display: flex; justify-content: space-between; align-items: center; gap: 24px; flex-wrap: wrap; margin-bottom: 24px; box-shadow: 0 4px 24px rgba(0,0,0,.15); }
    .cover h1 { font-size: 20px; font-weight: 700; margin: 0 0 8px; }
    .cover .target { color: #38bdf8; font-size: 14px; word-break: break-all; font-weight: 600; }
    .cover .info { color: #868e96; font-size: 12px; margin-top: 4px; }
    .grade-badge { text-align: center; min-width: 140px; }
    .grade-badge .letter { font-size: 64px; font-weight: 900; line-height: 1; }
    .grade-badge .score { font-size: 20px; font-weight: 700; margin-top: 4px; }
    .grade-badge .label { font-size: 11px; color: #adb5bd; text-transform: uppercase; letter-spacing: 1px; }
    
    /* ── Cards ── */
    .cards { display: flex; gap: 12px; margin: 0 0 24px; flex-wrap: wrap; }
    .card { background: #fff; border-radius: 12px; padding: 16px 20px; flex: 1; min-width: 110px; box-shadow: 0 1px 4px rgba(0,0,0,.06); text-align: center; }
    .card .num { font-size: 28px; font-weight: 700; }
    .card .lbl { font-size: 11px; color: #868e96; margin-top: 3px; }
    
    /* ── Seções ── */
    .section { background: #fff; border-radius: 14px; padding: 24px; margin: 20px 0; box-shadow: 0 1px 4px rgba(0,0,0,.05); }
    .section h2 { font-size: 16px; font-weight: 700; margin: 0 0 16px; padding-bottom: 8px; border-bottom: 2px solid #e9ecef; }
    .section h3 { font-size: 14px; font-weight: 600; margin: 16px 0 10px; color: #343a40; }
    .section h3 .count { color: #adb5bd; font-weight: 400; }
    
    /* ── Sumário Executivo ── */
    .exec-summary { background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); border-left: 4px solid ${gradeColor}; }
    .exec-summary p { font-size: 14px; color: #495057; margin: 8px 0; }
    .exec-summary .highlight { font-weight: 600; color: #212529; }
    
    /* ── Score Breakdown ── */
    .breakdown-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px; }
    .cat-bar { background: #f8f9fa; border-radius: 8px; padding: 12px 14px; }
    .cat-bar .cat-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
    .cat-bar .cat-name { font-size: 13px; font-weight: 600; }
    .cat-bar .cat-score { font-size: 13px; font-weight: 700; }
    .cat-bar .bar-bg { background: #e9ecef; border-radius: 4px; height: 8px; overflow: hidden; }
    .cat-bar .bar-fill { height: 100%; border-radius: 4px; transition: width .3s; }
    .cat-bar .cat-detail { font-size: 11px; color: #868e96; margin-top: 4px; }
    
    /* ── Infra ── */
    .infra-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; }
    .infra-card { background: #f8f9fa; border-radius: 10px; padding: 14px; }
    .infra-card .ic-label { font-size: 11px; color: #868e96; text-transform: uppercase; letter-spacing: .5px; margin-bottom: 4px; }
    .infra-card .ic-value { font-size: 16px; font-weight: 600; }
    .timing-bar { display: flex; gap: 2px; height: 24px; border-radius: 4px; overflow: hidden; margin: 10px 0; }
    .timing-bar div { display: flex; align-items: center; justify-content: center; color: #fff; font-size: 9px; font-weight: 600; min-width: 30px; }
    .port-table { font-size: 12px; width: 100%; border-collapse: collapse; }
    .port-table td, .port-table th { padding: 8px 10px; border-bottom: 1px solid #e9ecef; }
    .port-open { color: #2f9e44; font-weight: 600; }
    .port-closed { color: #868e96; }
    .port-filtered { color: #f08c00; }
    
    /* ── Achados ── */
    .finding { background: #fff; border-radius: 10px; padding: 16px 18px; margin: 12px 0; border-left: 4px solid #ced4da; box-shadow: 0 1px 3px rgba(0,0,0,.04); }
    .finding.sev-CRITICAL { border-left-color: #c92a2a; } .finding.sev-HIGH { border-left-color: #e8590c; }
    .finding.sev-MEDIUM { border-left-color: #f08c00; } .finding.sev-LOW { border-left-color: #1c7ed6; }
    .fhead { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
    .pill { color: #fff; font-size: 10px; font-weight: 700; padding: 2px 10px; border-radius: 20px; letter-spacing: .5px; }
    .ftitle { font-weight: 600; font-size: 14px; }
    .fmeta { font-size: 11px; color: #868e96; margin: 4px 0; }
    .fwhere { font-size: 12px; margin: 4px 0; } .fwhere code { background: #f1f3f5; padding: 1px 5px; border-radius: 4px; word-break: break-all; font-size: 11px; }
    .frisk { font-size: 13px; color: #495057; margin: 8px 0; }
    .frec { font-size: 13px; color: #2b5c34; background: #ebfbee; padding: 8px 12px; border-radius: 6px; margin: 6px 0; }
    .fevid { font-size: 12px; background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 6px; padding: 8px 12px; margin: 6px 0; }
    .fevid ul { margin: 4px 0 0; padding-left: 18px; } .fevid code { word-break: break-all; font-size: 11px; }
    
    /* ── Verificação Manual & Comandos ── */
    .verify { background: #fff4e6; border: 1px solid #ffe8cc; border-radius: 8px; padding: 12px 14px; margin: 8px 0; font-size: 12px; }
    .verify-title { font-weight: 600; color: #e8590c; margin-bottom: 6px; font-size: 12px; }
    .verify ol { padding-left: 20px; margin: 4px 0; }
    .verify li { margin: 2px 0; }
    
    .cmd-wrapper { display: flex; flex-direction: column; background: #0f172a; border-radius: 8px; margin: 8px 0; overflow: hidden; border: 1px solid #1e293b; }
    .cmd-header { display: flex; justify-content: space-between; align-items: center; background: #1e293b; padding: 6px 12px; font-size: 11px; color: #94a3b8; font-weight: 600; border-bottom: 1px solid #334155; }
    .cmd { color: #38bdf8; padding: 10px 12px; font-family: 'Consolas', 'Fira Code', monospace; font-size: 11px; display: block; word-break: break-all; white-space: pre-wrap; line-height: 1.5; margin: 0; background: transparent; }
    .cmd-pow { color: #4ade80; }
    
    /* ── Botão Copiar ── */
    .btn-copy { background: #3b82f6; border: none; color: #ffffff; font-size: 11px; padding: 4px 10px; border-radius: 4px; cursor: pointer; transition: all .2s; font-family: inherit; font-weight: 600; display: inline-flex; align-items: center; gap: 4px; box-shadow: 0 1px 2px rgba(0,0,0,0.2); }
    .btn-copy:hover { background: #2563eb; }
    .btn-copy.copied { background: #16a34a !important; color: #fff !important; }
    
    .btn-action { background: #1c7ed6; color: #fff; border: none; padding: 4px 10px; border-radius: 4px; font-size: 11px; cursor: pointer; font-weight: 500; transition: background .2s; }
    .btn-action:hover { background: #1971c2; }
    .btn-action.copied { background: #2f9e44; }

    /* ── Tabelas ── */
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th, td { padding: 8px 10px; border-bottom: 1px solid #f1f3f5; text-align: left; }
    th { background: #f8f9fa; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: .3px; color: #495057; }
    .routes code { word-break: break-all; font-size: 11px; }
    
    /* ── Screenshots ── */
    .screenshots { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 16px; }
    .screenshot { border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,.1); border: 1px solid #e9ecef; }
    .screenshot img { width: 100%; display: block; }
    .screenshot .ss-label { font-size: 11px; color: #495057; padding: 8px 12px; background: #f8f9fa; word-break: break-all; }
    
    /* ── Timeline ── */
    .timeline { border-left: 2px solid #e9ecef; padding-left: 16px; margin: 12px 0; }
    .tl-item { margin: 10px 0; position: relative; font-size: 13px; }
    .tl-item::before { content: ''; position: absolute; left: -21px; top: 5px; width: 8px; height: 8px; border-radius: 50%; background: #1c7ed6; }
    .tl-item.tl-warn::before { background: #f08c00; }
    .tl-item.tl-error::before { background: #c92a2a; }
    .tl-time { font-size: 11px; color: #868e96; font-family: monospace; margin-right: 6px; font-weight: 600; }
    .tl-text { font-size: 12px; color: #343a40; }
    
    /* ── Código ── */
    .code-block-wrapper { position: relative; margin: 10px 0; }
    .code-block { background: #1a1b1e; color: #c1c2c5; border-radius: 8px; padding: 14px 16px; font-family: 'Consolas', 'Fira Code', monospace; font-size: 12px; overflow-x: auto; white-space: pre; line-height: 1.6; margin: 0; }

    /* ── Alcance (occurrences do dedup) ── */
    .freach { font-size: 12px; color: #495057; background: #f1f3f5; border-radius: 6px; padding: 6px 10px; margin: 6px 0; }
    .freach summary { cursor: pointer; font-weight: 600; color: #1c7ed6; }
    .freach ul { margin: 6px 0 0; padding-left: 18px; max-height: 220px; overflow-y: auto; }
    .freach li { margin: 2px 0; } .freach code { font-size: 11px; word-break: break-all; }

    /* ── Caixa única "como ler as provas" (antes repetida em cada achado) ── */
    .proof-legend { background: #f8f9fa; border: 1px solid #dee2e6; border-left: 4px solid #1c7ed6; border-radius: 8px; padding: 12px 14px; margin: 0 0 14px; font-size: 12px; color: #343a40; }
    .proof-legend .pl-title { font-weight: 700; color: #1c7ed6; margin-bottom: 6px; }
    .proof-legend .pl-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 8px; margin-top: 8px; }
    .proof-hint { font-size: 11px; color: #868e96; margin-top: 8px; }
    
    /* ── Nota / Alerta ── */
    .note { background: #fff3bf; border: 1px solid #ffe066; border-radius: 10px; padding: 12px 16px; font-size: 13px; color: #664d03; margin: 16px 0; }
    
    /* ── Regressão ── */
    .reggrid { display: flex; gap: 12px; flex-wrap: wrap; }
    
    /* ── Footer ── */
    footer { text-align: center; color: #adb5bd; font-size: 11px; margin: 30px 0 10px; padding-top: 20px; border-top: 1px solid #e9ecef; }
    
    /* ── Print ── */
    @media print {
      body { background: #fff; }
      .cover { box-shadow: none; }
      .section { box-shadow: none; page-break-inside: avoid; }
      .finding { page-break-inside: avoid; }
      .btn-copy, .btn-action { display: none; }
    }
  </style>`;

  // ── Sumário Executivo ──
  const criticals = findings.filter(f => f.severity === 'CRITICAL');
  const highs = findings.filter(f => f.severity === 'HIGH');
  const topRisks = [...criticals, ...highs].slice(0, 3);

  // Categorizar Quick Wins (< 5 minutos) vs Projetos Estruturais
  const quickFixTypes = ['missing_security_header', 'password_autocomplete', 'missing_privacy_policy', 'missing_sri', 'missing_security_txt'];
  const quickWins = findings.filter(f => quickFixTypes.includes(f.type));
  const structuralFixes = findings.filter(f => !quickFixTypes.includes(f.type) && f.severity !== 'INFO');

  const execSummaryHtml = `
  <div class="section exec-summary">
    <h2>📊 Sumário Executivo</h2>
    ${meta.company ? `<p style="font-size:12px;color:#38bdf8;font-weight:600;margin-bottom:6px">🏢 AUDITORIA PREPARADA POR: ${esc(meta.company)}${meta.client ? ` — CLIENTE: ${esc(meta.client)}` : ''}</p>` : ''}
    <p>A auditoria de segurança do site <a href="${esc(meta.target)}" target="_blank" class="highlight">${esc(meta.target)}</a> identificou 
    <span class="highlight">${meta.firstPartyIssues} problema(s)</span> no seu código/configuração, 
    resultando em uma nota de <span class="highlight">${score}/100 (${grade} — ${gradeLabel})</span>.</p>
    
    ${criticals.length > 0 ? `<p style="color:#c92a2a;font-weight:600">⚠️ ${criticals.length} problema(s) CRÍTICO(S) requerem atenção imediata.</p>` : ''}
    
    ${topRisks.length > 0 ? `
    <h3>Top Riscos</h3>
    <ol>${topRisks.map(f => {
      const reach = reachOf(f);
      return `<li><strong>[${f.severity}]</strong> ${esc(titleOf(f))}${reach ? ` <span style="color:#868e96;font-weight:600">(${esc(reach.text)})</span>` : ''}${f.risk ? ` — ${esc(f.risk.substring(0, 120))}${f.risk.length > 120 ? '…' : ''}` : ''}</li>`;
    }).join('')}</ol>
    ` : '<p style="color:#2f9e44">✅ Nenhum problema crítico ou alto encontrado.</p>'}
    
    <h3>⚡ Matriz de Esforço × Impacto (Plano de Ação)</h3>
    <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(280px, 1fr));gap:12px;margin:10px 0">
      <div style="background:#ebfbee;border-left:3px solid #2f9e44;padding:10px 12px;border-radius:6px">
        <b style="color:#2b5c34;font-size:12px">⚡ Ganhas-Rápidos (Quick Fixes < 5 min):</b>
        <p style="font-size:12px;color:#2b5c34;margin:4px 0">${quickWins.length} item(ns) corrigíveis via configuração de servidor ou ajuste de 1 linha de HTML (ex.: Headers de Segurança, Autocomplete, Política de Privacidade).</p>
      </div>
      <div style="background:#fff4e6;border-left:3px solid #e8590c;padding:10px 12px;border-radius:6px">
        <b style="color:#e8590c;font-size:12px">🛠️ Remediação Estrutural (Projetos Dev/Infra):</b>
        <p style="font-size:12px;color:#d9480f;margin:4px 0">${structuralFixes.length} item(ns) requerem ajuste em regras de firewall, refatoração de código backend ou autorização por objeto (IDOR).</p>
      </div>
    </div>

    <p style="margin-top:12px;font-size:12px;color:#868e96">Auditoria realizada em ${new Date(meta.timestamp).toLocaleString('pt-BR')} · ${meta.pagesAudited} página(s) · Fases: PRÉ-LOGIN → LOGIN → PÓS-LOGIN</p>
  </div>`;

  // ── Módulo LGPD & Compliance ──
  const lgpdIssues = findings.filter(f => f.type.startsWith('pii_') || f.type.includes('privacy') || f.type.includes('optin') || f.type.includes('cookie_consent'));
  const piiIssues = findings.filter(f => f.type.startsWith('pii_'));
  const consentIssues = findings.filter(f => f.type === 'cookie_consent_violation');

  const lgpdHtml = `
  <div class="section" style="background:#fff9db;border:1px solid #ffe066">
    <h2>⚖️ LGPD & Compliance de Privacidade (Lei 13.709/2018)</h2>
    <p style="font-size:13px;color:#664d03;margin-bottom:12px">
      Avaliação das obrigações de transparência, proteção de dados pessoais (PII) e consentimento exigidas pela Lei Geral de Proteção de Dados.
    </p>
    <div class="infra-grid">
      <div class="infra-card">
        <div class="ic-label">Status de Compliance</div>
        <div class="ic-value" style="color:${lgpdIssues.length ? '#c92a2a' : '#2f9e44'}">${lgpdIssues.length ? '⚠️ ' + lgpdIssues.length + ' Ponto(s) de Atenção' : '✅ Adequado'}</div>
      </div>
      <div class="infra-card">
        <div class="ic-label">Exposição de PII (CPF/E-mail/Dados)</div>
        <div class="ic-value" style="color:${piiIssues.length ? '#c92a2a' : '#2f9e44'}">${piiIssues.length ? '❌ Exposição Detectada' : '✅ Nenhum Vazamento'}</div>
      </div>
      <div class="infra-card">
        <div class="ic-label">Consentimento de Cookies</div>
        <div class="ic-value" style="color:${consentIssues.length ? '#f08c00' : '#2f9e44'}">${consentIssues.length ? '⚠️ Rastreio Sem Opt-in' : '✅ Conforme'}</div>
      </div>
      <div class="infra-card">
        <div class="ic-label">Multa Máxima Prevista (Art. 52)</div>
        <div class="ic-value" style="color:#c92a2a">Até 2% Faturamento / R$ 50 Mi</div>
      </div>
    </div>
  </div>`;

  // ── Score Breakdown ──
  const breakdownHtml = scoreCategories.length ? `
  <div class="section">
    <h2>📈 Score por Categoria</h2>
    <div class="breakdown-grid">
      ${scoreCategories.map(cat => {
        // `pct` é derivável de earnedPts/maxPts — se a nova versão do módulo de
        // score parar de mandá-lo, recalculamos em vez de imprimir NaN%.
        const pct = Number.isFinite(cat.pct)
          ? cat.pct
          : (cat.maxPts > 0 ? Math.round((cat.earnedPts ?? 0) / cat.maxPts * 100) : 100);
        // Categoria não avaliada (o scan correspondente não rodou) NÃO pode
        // aparecer como "✅ Nenhum problema" — seria afirmar ausência de risco
        // sem ter olhado. `undefined` = módulo antigo, que sempre avaliava.
        const notEvaluated = cat.evaluated === false;
        const fillColor = notEvaluated ? '#ced4da' : pct >= 80 ? '#2f9e44' : pct >= 50 ? '#f08c00' : '#c92a2a';
        const detail = notEvaluated
          ? '❔ Não avaliado (fora do escopo desta sessão)'
          : cat.issueCount > 0
            ? `${cat.issueCount} achado(s)${cat.occurrenceTotal > cat.issueCount ? ` · ${cat.occurrenceTotal} ocorrência(s)` : ''} · ${cat.deduction}pts`
            : '✅ Nenhum problema';
        return `<div class="cat-bar">
          <div class="cat-head">
            <span class="cat-name">${esc(cat.label)}</span>
            <span class="cat-score" style="color:${notEvaluated ? '#868e96' : fillColor}">${notEvaluated ? '—' : `${cat.earnedPts}/${cat.maxPts}`}</span>
          </div>
          <div class="bar-bg"><div class="bar-fill" style="width:${notEvaluated ? 0 : Math.max(0, Math.min(100, pct))}%;background:${fillColor}"></div></div>
          <div class="cat-detail">${detail}</div>
        </div>`;
      }).join('')}
    </div>
    ${sb.gradeCap && sb.gradeCap.applied ? `<p style="font-size:12px;color:#e8590c;margin-top:12px">⚠️ <b>Nota limitada a ${esc(sb.gradeCap.maxGrade)}:</b> ${esc(sb.gradeCap.reason || '')}</p>` : ''}
    ${Number.isFinite(sb.evaluatedCategories) && sb.evaluatedCategories < scoreCategories.length ? `<p style="font-size:11px;color:#868e96;margin-top:8px">❔ ${scoreCategories.length - sb.evaluatedCategories} categoria(s) não avaliada(s) nesta sessão — não entram na nota e não devem ser lidas como "sem problemas".</p>` : ''}
  </div>` : '';

  // ── Infraestrutura ──
  let infraHtml = '';
  if (infraData) {
    const geo = infraData.geoip || {};
    const timing = infraData.socketTiming || {};
    const load = infraData.loadPercentiles || {};
    const rep = infraData.reputation || {};
    const tcp = infraData.tcpScan || {};
    // "Limpo" só com evidência positiva (status PASS); IP privado ou consulta
    // falhada viram "não se aplica"/"não verificado" em vez de um ✅ sem lastro.
    const repState = reputationState(rep);

    // Timing bar visual
    const total = timing.total_ms || 1;
    const pct = (v) => Math.max(3, Math.round((v || 0) / total * 100));
    const timingBarHtml = timing.status === 'PASS' ? `
      <div class="timing-bar">
        <div style="width:${pct(timing.dns_ms)}%;background:#339af0" title="DNS">DNS ${timing.dns_ms}ms</div>
        <div style="width:${pct(timing.tcp_ms)}%;background:#51cf66" title="TCP">TCP ${timing.tcp_ms}ms</div>
        <div style="width:${pct(timing.tls_ms)}%;background:#fcc419" title="TLS">TLS ${timing.tls_ms}ms</div>
        <div style="width:${pct(timing.ttfb_ms)}%;background:#ff6b6b" title="TTFB">TTFB ${timing.ttfb_ms}ms</div>
        <div style="width:${pct(timing.download_ms)}%;background:#845ef7" title="Download">DL ${timing.download_ms}ms</div>
      </div>
      <p style="font-size:11px;color:#868e96;text-align:center">Total: ${timing.total_ms}ms · ${timing.total_bytes ? (timing.total_bytes / 1024).toFixed(1) + ' KB' : ''}</p>
    ` : `<p style="color:#c92a2a">⚠️ Medição de timing falhou${timing.error ? ': ' + esc(timing.error) : ''}</p>`;

    // Portas abertas com botões interativos, risco detalhado e recomendação
    const openPorts = (tcp.ports || []).filter(p => p.state === 'OPEN');
    const targetHost = geo.ip || timing.ip || '10.4.0.20';
    const portTableHtml = openPorts.length > 0 ? `
      <table class="port-table">
        <thead>
          <tr>
            <th style="width:70px">Porta</th>
            <th style="width:130px">Serviço</th>
            <th style="width:80px">Nível</th>
            <th>Risco & Por Quê</th>
            <th>Recomendação de Proteção</th>
            <th style="width:130px">Ação de Teste</th>
          </tr>
        </thead>
        <tbody>${openPorts.map(p => {
          const testCmd = p.port === 80 || p.port === 443 || p.port === 8080 || p.port === 8443 || p.port === 3000 || p.port === 8000
            ? `curl -skD - "http${p.port === 443 || p.port === 8443 ? 's' : ''}://${targetHost}:${p.port}" -o /dev/null`
            : `nc -vv -w 3 ${targetHost} ${p.port}`;
          const sev = p.severity || 'LOW';
          const sevBg = SEV_COLOR[sev] || '#868e96';
          // Porta reportada como aberta mas não confirmada na 2ª passagem não
          // deve ser apresentada com a mesma certeza de uma confirmada.
          const conf = portConfidence(p);
          return `<tr>
          <td><strong>${p.port}</strong></td>
          <td>${esc(p.service)}<br><span style="font-size:10px;color:#868e96">${p.latency_ms}ms</span>${conf ? `<br><span style="font-size:10px;color:${conf.color}">${esc(conf.text)}</span>` : ''}</td>
          <td><span class="pill" style="background:${sevBg}">${sev}</span></td>
          <td style="font-size:12px;color:#495057;line-height:1.4">${esc(p.risk || 'Superfície de ataque exposta.')}</td>
          <td style="font-size:12px;color:#2b5c34;line-height:1.4">${esc(p.recommendation || 'Fechar no firewall se não for estritamente necessária.')}</td>
          <td>
            <button class="btn-action" data-cmd="${esc(testCmd)}" onclick="copyFromData(this)">📋 Testar (${p.port === 80 || p.port === 443 || p.port === 8080 || p.port === 8443 || p.port === 3000 || p.port === 8000 ? 'curl' : 'nc'})</button>
          </td>
        </tr>`;
        }).join('')}</tbody>
      </table>
    ` : `<p style="font-size:12px;color:#868e96">${tcp.status === 'INFO'
        ? 'Nenhuma porta respondeu de forma conclusiva — nada a listar. Isso <b>não</b> é evidência de que as portas estejam fechadas.'
        : 'Nenhuma porta enterprise aberta detectada (portas web padrão podem estar filtradas pelo CDN).'}</p>`;

    // Aviso de varredura inconclusiva: sem ele, "0 portas abertas" seria lido
    // como "servidor bem fechado", quando na verdade nada foi verificado.
    const tcpNotice = tcpScanNotice(tcp);
    const tcpNoticeHtml = tcpNotice ? `<div class="note" style="margin:8px 0">❔ ${esc(tcpNotice)}</div>` : '';

    // Percentis
    const percHtml = load.percentiles ? `
      <div class="infra-grid">
        ${['p50', 'p75', 'p90', 'p95', 'p99'].map(p => `
          <div class="infra-card">
            <div class="ic-label">${p.toUpperCase()}</div>
            <div class="ic-value">${load.percentiles[p] != null ? load.percentiles[p] + 'ms' : '—'}</div>
          </div>
        `).join('')}
      </div>
      <p style="font-size:11px;color:#868e96;margin-top:8px">${load.total_requests} requisições · ${load.success_rate_pct}% sucesso · min ${load.min_ms}ms · max ${load.max_ms}ms · avg ${load.average_ms}ms</p>
    ` : '';

    // Registros DNS de Segurança
    const dnsSec = infraData.dnsSecurity || {};
    const dnsSum = dnsSec.summary || {};
    const dnsRecs = dnsSec.records || {};

    // Cartão de registro DNS. O estado vem do scanner (ok / ausente /
    // nao_verificado / nao_aplicavel) — nunca inferido de um booleano falsy,
    // que fazia falha de consulta DNS aparecer como "⚠️ Ausente".
    const dnsCard = (label, record, evidence) => {
      const st = dnsRecordState(dnsSec, record);
      return `<div class="infra-card">
          <div class="ic-label">${esc(label)}</div>
          <div class="ic-value" style="color:${st.color}">${esc(st.text)}</div>
          ${st.state === 'ok' && evidence ? `<div style="font-size:10px;color:#495057;word-break:break-all;margin-top:4px"><code>${esc(evidence)}</code></div>` : ''}
        </div>`;
    };

    const dnsSecHtml = !dnsSec.isIp && dnsSec.status ? `
      <h3>🛡️ Registros DNS de Segurança & E-mail</h3>
      <div class="infra-grid" style="margin-bottom:12px">
        ${dnsCard('SPF (Anti-Spoofing)', 'SPF', dnsRecs.SPF)}
        ${dnsCard('DMARC (Anti-Phishing)', 'DMARC', dnsRecs.DMARC)}
        ${dnsCard('CAA (Autorização de CA)', 'CAA', (dnsRecs.CAA || []).join(', '))}
        ${dnsCard('PTR (DNS Reverso)', 'PTR', (dnsRecs.PTR || []).join(', '))}
        <div class="infra-card">
          <div class="ic-label">IPv6 (Suporte AAAA)</div>
          <div class="ic-value" style="color:${dnsSum.has_ipv6 ? '#2f9e44' : '#868e96'}">${dnsSum.has_ipv6 ? '✅ Habilitado' : 'ℹ️ Somente IPv4'}</div>
          ${dnsRecs.AAAA && dnsRecs.AAAA.length ? `<div style="font-size:10px;color:#495057;margin-top:4px"><code>${esc(dnsRecs.AAAA[0])}</code></div>` : ''}
        </div>
      </div>
      ${dnsSec.status === 'INFO' ? `<p style="font-size:11px;color:#868e96;margin:-6px 0 12px">❔ Parte das consultas DNS não retornou resposta conclusiva — os itens marcados como "não verificado" não são afirmações sobre a configuração do domínio.</p>` : ''}
    ` : '';

    infraHtml = `
    <div class="section">
      <h2>🏗️ Infraestrutura</h2>
      
      <div class="infra-grid" style="margin-bottom:16px">
        <div class="infra-card"><div class="ic-label">IP</div><div class="ic-value">${esc(geo.ip || timing.ip || '—')}</div></div>
        <div class="infra-card"><div class="ic-label">Localização</div><div class="ic-value">${esc(geo.city || '—')}, ${esc(geo.country || '—')} ${esc(geo.country_code || '')}</div></div>
        <div class="infra-card"><div class="ic-label">ISP</div><div class="ic-value">${esc(geo.isp || '—')}</div></div>
        <div class="infra-card"><div class="ic-label">ASN</div><div class="ic-value">${esc(geo.asn || '—')}</div></div>
        <div class="infra-card"><div class="ic-label">Organização</div><div class="ic-value">${esc(geo.organization || '—')}</div></div>
        <div class="infra-card">
          <div class="ic-label">Reputação IP</div>
          <div class="ic-value" style="color:${repState.color}">${esc(repState.text)}</div>
          ${repState.detail ? `<div style="font-size:10px;color:#868e96;margin-top:4px">${esc(repState.detail)}</div>` : ''}
        </div>
      </div>

      ${dnsSecHtml}

      <h3>⚡ Latência por Fase (Socket)</h3>
      ${timingBarHtml}

      <h3>🔌 Portas TCP Abertas (${openPorts.length} de ${tcp.total_scanned || 0})</h3>
      ${tcpNoticeHtml}
      ${portTableHtml}

      ${percHtml ? `<h3>📊 Percentis de Carga</h3>${percHtml}` : ''}
    </div>`;
  }

  // ── Achados agrupados por OWASP ──
  const byOwasp = {};
  for (const f of findings) {
    const k = f.owasp || 'Diversos / Boas práticas';
    (byOwasp[k] = byOwasp[k] || []).push(f);
  }
  const sevRank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

  const findingHtml = (f) => {
    const ev = evidenceOf ? evidenceOf(f) : [];
    const mv = f.manualVerification;
    // Alcance vem do dedup (occurrenceCount/occurrences): mostra que o mesmo
    // problema aparece em N páginas SEM repetir o achado N vezes no relatório.
    const reach = reachOf(f);

    return `<div class="finding sev-${f.severity}">
      <div class="fhead">
        <span class="pill" style="background:${SEV_COLOR[f.severity] || '#868e96'}">${f.severity}</span>
        <span class="ftitle">${esc(titleOf(f))}</span>
      </div>
      ${reach ? `<div class="freach">📡 <b>Alcance:</b> ${esc(reach.text)}${reach.urls.length > 1 ? `
        <details><summary>ver URLs afetadas (${reach.urls.length})</summary>
        <ul>${reach.urls.map(u => `<li><a href="${esc(String(u).split(' ')[0])}" target="_blank"><code>${esc(u)}</code></a></li>`).join('')}</ul>
        </details>` : ''}</div>` : ''}
      <div class="fmeta">${[f.owasp, f.cwe && f.cwe !== '—' ? f.cwe : '', f.confidence ? 'confiança: ' + f.confidence : ''].filter(Boolean).map(esc).join(' · ')}</div>
      ${f.url ? `<div class="fwhere"><b>📍 Onde:</b> <a href="${esc(f.url.split(' ')[0])}" target="_blank"><code>${esc(f.url)}</code></a></div>` : ''}
      ${f.cve ? `<div class="fwhere"><b>CVE:</b> ${esc(f.cve)}${f.fixedIn ? ` — corrigido em ${esc(f.fixedIn)}` : ''}</div>` : ''}
      ${ev.length ? `<div class="fevid"><b>🔎 Evidência:</b><ul>${ev.map(e => `<li><code>${esc(e)}</code></li>`).join('')}</ul></div>` : ''}
      ${f.risk ? `<div class="frisk">${esc(f.risk)}</div>` : ''}
      ${f.recommendation ? `<div class="frec"><b>✅ Correção:</b> ${esc(f.recommendation)}</div>` : ''}
      ${mv ? `<div class="verify">
        <div class="verify-title">🧪 Como Verificar Manualmente & Provar para a Gestão</div>
        <ol>${mv.steps.map(s => `<li>${esc(s)}</li>`).join('')}</ol>
        ${mv.devtools ? `<p style="margin-top:4px"><b>DevTools (Interface Visual):</b> ${esc(mv.devtools)}</p>` : ''}
        ${mv.consoleSnippet ? `
        <div class="cmd-wrapper">
          <div class="cmd-header">
            <span>🖥️ Teste via Console do Navegador (F12 → Console)</span>
            <button class="btn-copy" onclick="copyFromAttr(this)">📋 Copiar Snippet Console</button>
          </div>
          <pre class="cmd" style="color:#67e8f9">${esc(mv.consoleSnippet)}</pre>
        </div>` : ''}
        ${mv.automated ? `
        <div class="cmd-wrapper">
          <div class="cmd-header">
            <span>Comando de Validação (Terminal cURL/nc)</span>
            <button class="btn-copy" onclick="copyFromAttr(this)">📋 Copiar Terminal</button>
          </div>
          <pre class="cmd">${esc(mv.automated)}</pre>
        </div>` : ''}
        ${mv.proofOfWork ? `
        <div class="cmd-wrapper">
          <div class="cmd-header">
            <span>Comando de Prova Real (Dump Completo)</span>
            <button class="btn-copy" onclick="copyFromAttr(this)">📋 Copiar Dump</button>
          </div>
          <pre class="cmd cmd-pow">${esc(mv.proofOfWork)}</pre>
        </div>` : ''}
        <div class="proof-hint">💡 Como interpretar a saída destes comandos: ver <b>"Resumo Executivo da Prova"</b> no topo desta seção.</div>
      </div>` : ''}
    </div>`;
  };

  // Caixa ÚNICA de interpretação das provas. Este texto era emitido dentro de
  // CADA achado (≈1,1 KB × 351 = 26% do HTML), literalmente idêntico exceto
  // pelo título do achado — que já aparece no cabeçalho de cada card.
  const proofLegendHtml = `
    <div class="proof-legend">
      <div class="pl-title">💡 Resumo Executivo da Prova (Para Gestão &amp; Diretoria)</div>
      <div style="line-height:1.5">
        <b>📌 O que os testes comprovam:</b> cada achado abaixo traz comandos que validam <i>diretamente</i>
        se aquele risco específico está ativo no ambiente ou se já foi protegido. A leitura do resultado é sempre a mesma:
        <div class="pl-grid">
          <div style="background:#fff5f5;border:1px solid #ffc9c9;padding:8px 10px;border-radius:6px;color:#c92a2a">
            <b>🔴 Se Vulnerável (Ambiente em Risco):</b><br>
            O comando/script exibe o dado exposto ou conexão liberada ("succeeded"). Prova que o atacante tem acesso direto a este vetor.
          </div>
          <div style="background:#ebfbee;border:1px solid #b2f2bb;padding:8px 10px;border-radius:6px;color:#2b5c34">
            <b>🟢 Se Corrigido (Ambiente Protegido):</b><br>
            O comando retorna vazio, "Connection refused" ou confirmação de bloqueio. Prova que a remediação foi concluída com sucesso.
          </div>
        </div>
      </div>
    </div>`;

  // Cada grupo OWASP vira uma <section> própria para que o filtro de severidade
  // possa escondê-la inteira quando nenhum achado dela estiver visível — antes
  // o <h3> ficava órfão na tela, com uma contagem que não batia com o filtro.
  const owaspSections = Object.entries(byOwasp)
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([owasp, items]) => {
      items.sort((x, y) => sevRank[x.severity] - sevRank[y.severity]);
      return `<section class="owasp-group">
        <h3>${esc(owasp)} <span class="count" data-total="${items.length}">(${items.length})</span></h3>
        ${items.map(findingHtml).join('')}
      </section>`;
    }).join('');

  // ── Terceiros ──
  const tpGroups = {};
  for (const f of (thirdParty || [])) {
    const k = `${f.vendor || 'Terceiro'} — ${titleOf(f)}`;
    // Achados de terceiros também passam pelo dedup: somar occurrenceCount
    // mantém a coluna "Ocorrências" fiel ao volume bruto observado.
    tpGroups[k] = (tpGroups[k] || 0) + (Number(f.occurrenceCount) || 1);
  }
  const tpRows = Object.entries(tpGroups).sort((a, b) => b[1] - a[1])
    .map(([k, n]) => `<tr><td>${esc(k)}</td><td style="text-align:center">${n}</td></tr>`).join('');

  // ── Rotas com Links Clicáveis e Copiador cURL ──
  const originBase = meta.target ? new URL(meta.target).origin : 'https://10.4.0.20:8443';
  const fpRoutes = (routes || []).filter(r => !r.thirdParty);
  const routeRows = fpRoutes.slice(0, 150).map(r => {
    const fullUrl = r.path.startsWith('http') ? r.path : `${originBase}${r.path}${r.query ? '?' + r.query : ''}`;
    const curlCmd = `curl -skD - -X ${r.method} "${fullUrl}" -o /dev/null`;
    return `<tr>
      <td><strong>${esc(r.method)}</strong></td>
      <td><a href="${esc(fullUrl)}" target="_blank"><code>${esc(r.path + (r.query ? '?' + r.query : ''))}</code></a></td>
      <td>${esc(r.kind)}</td>
      <td>${esc(r.phase)}</td>
      <td style="text-align:center">${r.hasAuth ? '🔑' : ''}</td>
      <td><button class="btn-action" data-cmd="${esc(curlCmd)}" onclick="copyFromData(this)">📋 cURL</button></td>
    </tr>`;
  }).join('');

  const pagesHtml = (pagesVisited || []).map(u => `<li><a href="${esc(u)}" target="_blank"><code>${esc(u)}</code></a></li>`).join('');

  // ── Screenshots ──
  const screenshotsHtml = (screenshots && screenshots.length > 0) ? `
  <div class="section">
    <h2>📸 Screenshots</h2>
    <div class="screenshots">
      ${screenshots.map(ss => `<div class="screenshot">
        <img src="data:image/png;base64,${ss.base64}" alt="${esc(ss.url)}" loading="lazy" />
        <div class="ss-label"><a href="${esc(ss.url)}" target="_blank">${esc(ss.url)}</a></div>
      </div>`).join('')}
    </div>
  </div>` : '';

  // ── Timeline ──
  const timelineHtml = (timeline && timeline.length > 0) ? `
  <div class="section">
    <h2>📜 Timeline da Auditoria</h2>
    <div class="timeline">
      ${timeline.map(t => `<div class="tl-item ${t.type === 'warn' ? 'tl-warn' : t.type === 'error' ? 'tl-error' : ''}">
        <span class="tl-time">[${esc(t.time)}]</span>
        <span class="tl-text">${esc(t.text)}</span>
      </div>`).join('')}
    </div>
  </div>` : '';

  // ── Testes Gerados com Botões de Cópia ──
  // Bloco de código com botão de cópia. O texto NÃO é interpolado em literal
  // JavaScript: o botão lê o textContent do <pre> irmão (copyFromAttr), então
  // aspas, apóstrofos e crases no conteúdo não quebram nada e o usuário copia
  // o comando literal — não a versão HTML-escapada (&quot;), que não roda.
  const codeBlock = (title, content, btnLabel) => `
    <h3>${esc(title)}</h3>
    <div class="code-block-wrapper">
      <pre class="code-block">${esc(content || '')}</pre>
      <button class="btn-copy" onclick="copyFromAttr(this)">📋 ${esc(btnLabel)}</button>
    </div>`;

  const testsHtml = testArtifacts ? `
  <div class="section">
    <h2>🧪 Testes de Verificação Gerados</h2>
    <p style="font-size:13px;color:#868e96;margin-bottom:12px">Execute estes testes para confirmar que as correções foram aplicadas corretamente.</p>
    ${codeBlock('Playwright (.spec.ts)', testArtifacts.playwright, 'Copiar Playwright')}
    ${codeBlock('cURL', testArtifacts.code_snippets?.curl, 'Copiar cURL')}
    ${codeBlock('Correção Nginx', testArtifacts.server_fix?.nginx, 'Copiar Config Nginx')}
    ${codeBlock('Correção Apache', testArtifacts.server_fix?.apache, 'Copiar Config Apache')}
  </div>` : '';

  // ── Regressão ──
  let regHtml = '';
  if (regression && regression.hasPrev) {
    const delta = score - (regression.prevScore ?? score);
    const arrow = delta > 0 ? `▲ +${delta}` : delta < 0 ? `▼ ${delta}` : '– 0';
    const dColor = delta > 0 ? '#2f9e44' : delta < 0 ? '#c92a2a' : '#868e96';
    regHtml = `<div class="section">
      <h2>🔁 Comparação com Auditoria Anterior</h2>
      <div class="reggrid">
        ${card('Nota anterior', regression.prevScore ?? '?', '#495057')}
        ${card('Nota atual', score, gradeColor)}
        ${card('Variação', arrow, dColor)}
        ${card('🆕 Novos', regression.new.length, '#c92a2a')}
        ${card('✅ Corrigidos', regression.fixed.length, '#2f9e44')}
        ${card('⏳ Persistentes', regression.persisted, '#f08c00')}
      </div>
    </div>`;
  }

  // ── Apêndice ──
  const appendixHtml = `
  <div class="section">
    <h2>📎 Apêndice</h2>
    
    <h3>Metodologia</h3>
    <p style="font-size:13px">O Sentinela é um auditor de segurança web guiado por humano. Abre um navegador real (Microsoft Edge InPrivate), você faz login e navegue normalmente. Em paralelo, ele:</p>
    <ul style="font-size:13px;padding-left:20px;margin:8px 0">
      <li><strong>Coleta passiva:</strong> Headers, cookies, storage, código-fonte, certificado TLS, bibliotecas vulneráveis</li>
      <li><strong>Recon autônomo:</strong> robots.txt, sitemap.xml, Swagger/OpenAPI, GraphQL, CORS, erro verboso</li>
      <li><strong>Monitoramento de rede:</strong> Requisições/respostas, mixed content, tokens na URL</li>
      <li><strong>Análise de login:</strong> CSRF, credenciais em HTTP, session fixation, diff before/after</li>
      <li><strong>Infraestrutura:</strong> Port scan, timing de socket, GeoIP, reputação IP, registros DNS (SPF/DMARC/CAA)</li>
      ${infraData ? '<li><strong>Testes ativos (opt-in):</strong> IDOR, open redirect, arquivos sensíveis, métodos HTTP</li>' : ''}
    </ul>
    <p style="font-size:13px">Todos os achados são mapeados para <strong>OWASP Top 10 (2021)</strong> e <strong>CWE</strong>.</p>
    
    <h3>Glossário</h3>
    <table>
      <tr><td><strong>OWASP</strong></td><td>Open Web Application Security Project — referência mundial em segurança de aplicações web</td></tr>
      <tr><td><strong>CWE</strong></td><td>Common Weakness Enumeration — catálogo de fraquezas de software</td></tr>
      <tr><td><strong>CVE</strong></td><td>Common Vulnerabilities and Exposures — vulnerabilidades conhecidas e catalogadas</td></tr>
      <tr><td><strong>HSTS</strong></td><td>HTTP Strict Transport Security — força o uso de HTTPS</td></tr>
      <tr><td><strong>CSP</strong></td><td>Content Security Policy — controla quais recursos a página pode carregar</td></tr>
      <tr><td><strong>XSS</strong></td><td>Cross-Site Scripting — injeção de scripts maliciosos na página</td></tr>
      <tr><td><strong>CSRF</strong></td><td>Cross-Site Request Forgery — forja requisições autenticadas</td></tr>
      <tr><td><strong>IDOR</strong></td><td>Insecure Direct Object Reference — acesso a recursos de outros usuários</td></tr>
      <tr><td><strong>SRI</strong></td><td>Subresource Integrity — garante que scripts externos não foram adulterados</td></tr>
      <tr><td><strong>DNSBL</strong></td><td>DNS-based Blackhole List — lista de IPs associados a spam/malware</td></tr>
      <tr><td><strong>TTFB</strong></td><td>Time to First Byte — tempo até o primeiro byte da resposta</td></tr>
    </table>
    
    <h3>Limitações</h3>
    <ul style="font-size:13px;padding-left:20px">
      <li>A auditoria cobre apenas as páginas visitadas durante a sessão</li>
      <li>Testes ativos (IDOR, open redirect) requerem flag --active e autorização</li>
      <li>A nota considera apenas problemas de 1ª parte (seu código/config)</li>
      <li>Port scan pode ser limitado por firewalls e CDNs</li>
    </ul>
  </div>`;

  // ── JavaScript Interativo de Cópia ──
  const jsScript = `<script>
    // Copia o texto do bloco de código irmão. O comando NUNCA é interpolado
    // dentro de um literal JavaScript no onclick — assim o usuário copia o
    // comando literal (com aspas de verdade, não &quot;) e rotas com apóstrofo
    // não quebram o atributo.
    function copyFromAttr(btnElement) {
      const wrapper = btnElement.closest('.cmd-wrapper, .code-block-wrapper');
      if (!wrapper) return;
      const cmdEl = wrapper.querySelector('.cmd, .code-block');
      if (!cmdEl) return;
      copyText(cmdEl.innerText || cmdEl.textContent, btnElement);
    }

    // Mesma ideia para botões soltos (portas, rotas): o comando vive num
    // data-cmd, que o parser HTML já devolve decodificado em dataset.cmd.
    function copyFromData(btnElement) {
      copyText(btnElement.dataset.cmd || '', btnElement);
    }

    function copyText(text, btnElement) {
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(() => showSuccess(btnElement)).catch(() => fallbackCopy(text, btnElement));
      } else {
        fallbackCopy(text, btnElement);
      }
    }

    function fallbackCopy(text, btnElement) {
      const textArea = document.createElement("textarea");
      textArea.value = text;
      textArea.style.position = "fixed";
      textArea.style.left = "-999999px";
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      try {
        document.execCommand('copy');
        showSuccess(btnElement);
      } catch (err) {
        console.error('Falha ao copiar:', err);
      }
      document.body.removeChild(textArea);
    }

    function showSuccess(btn) {
      if (!btn) return;
      const originalText = btn.innerHTML;
      btn.classList.add('copied');
      btn.innerHTML = '✓ Copiado!';
      setTimeout(() => {
        btn.classList.remove('copied');
        btn.innerHTML = originalText;
      }, 2000);
    }

    // Filtra por severidade e mantém os cabeçalhos OWASP coerentes: grupo sem
    // nenhum achado visível some, e o (N) do título passa a contar o visível.
    function filterFindings(sev, btn) {
      document.querySelectorAll('.filter-btn').forEach(b => b.style.opacity = '0.6');
      if (btn) btn.style.opacity = '1';

      document.querySelectorAll('.owasp-group').forEach(group => {
        let visible = 0;
        group.querySelectorAll('.finding').forEach(el => {
          const show = sev === 'ALL' || el.classList.contains('sev-' + sev);
          el.style.display = show ? 'block' : 'none';
          if (show) visible++;
        });

        group.style.display = visible ? '' : 'none';

        const countEl = group.querySelector('.count');
        if (countEl) {
          const total = countEl.dataset.total || visible;
          // Mostra "(3 de 12)" quando filtrado, para não parecer que o grupo encolheu.
          countEl.textContent = sev === 'ALL' ? '(' + total + ')' : '(' + visible + ' de ' + total + ')';
        }
      });
    }
  </script>`;

  // ── Montagem Final ──
  return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentinela — Relatório de Segurança — ${esc(meta.target)}</title>
${css}
</head><body><div class="wrap">

  <div class="cover">
    <div>
      <h1>🛡️ Sentinela — Relatório de Auditoria de Segurança</h1>
      <div class="target"><a href="${esc(meta.target)}" target="_blank">${esc(meta.target)}</a></div>
      <div class="info">${new Date(meta.timestamp).toLocaleString('pt-BR')} · ${meta.pagesAudited} página(s) auditada(s)</div>
    </div>
    <div class="grade-badge">
      <div class="letter" style="color:${gradeColor}">${grade}</div>
      <div class="score" style="color:${gradeColor}">${score}/100</div>
      <div class="label">${gradeLabel}</div>
    </div>
  </div>

  <div class="cards">
    ${card(`${SEV_EMOJI.CRITICAL} CRITICAL`, counts.CRITICAL, SEV_COLOR.CRITICAL)}
    ${card(`${SEV_EMOJI.HIGH} HIGH`, counts.HIGH, SEV_COLOR.HIGH)}
    ${card(`${SEV_EMOJI.MEDIUM} MEDIUM`, counts.MEDIUM, SEV_COLOR.MEDIUM)}
    ${card(`${SEV_EMOJI.LOW} LOW`, counts.LOW, SEV_COLOR.LOW)}
    ${card('🏢 Terceiros', meta.thirdPartyIssues, '#868e96')}
  </div>

  <div class="note">Contagem e nota consideram <b>apenas o seu código/config (1ª parte)</b>. Achados em bibliotecas e domínios de terceiros aparecem à parte e não afetam a nota.</div>

  ${execSummaryHtml}
  ${lgpdHtml}
  ${regHtml}
  ${infraHtml}
  ${breakdownHtml}

  <div class="section">
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;margin-bottom:12px">
      <h2 style="margin:0;border:none">🔎 Achados (${findings.length})</h2>
      <div style="display:flex;gap:6px;flex-wrap:wrap">
        <button class="btn-action filter-btn" onclick="filterFindings('ALL', this)" style="background:#495057">Todos (${findings.length})</button>
        <button class="btn-action filter-btn" onclick="filterFindings('CRITICAL', this)" style="background:#c92a2a;opacity:0.6">🔴 CRITICAL (${counts.CRITICAL})</button>
        <button class="btn-action filter-btn" onclick="filterFindings('HIGH', this)" style="background:#e8590c;opacity:0.6">🟠 HIGH (${counts.HIGH})</button>
        <button class="btn-action filter-btn" onclick="filterFindings('MEDIUM', this)" style="background:#f08c00;opacity:0.6">🟡 MEDIUM (${counts.MEDIUM})</button>
        <button class="btn-action filter-btn" onclick="filterFindings('LOW', this)" style="background:#1c7ed6;opacity:0.6">🔵 LOW (${counts.LOW})</button>
      </div>
    </div>
    ${findings.length ? proofLegendHtml + owaspSections : '<p>Nenhum problema de 1ª parte encontrado. 🎉</p>'}
  </div>

  ${(routes || []).length ? `<div class="section">
    <h2>🗺️ Rotas e Endpoints</h2>
    <p style="font-size:13px;color:#868e96">${(routes || []).length} requisições distintas observadas (${fpRoutes.length} do seu domínio). Clique na rota para abrir no navegador ou use o botão para copiar o comando cURL.</p>
    ${pagesHtml ? `<p style="font-size:13px;margin:8px 0"><b>Páginas visitadas:</b></p><ul class="routes" style="margin-bottom:12px">${pagesHtml}</ul>` : ''}
    ${routeRows ? `<table class="routes"><thead><tr><th>Método</th><th>Rota</th><th>Tipo</th><th>Fase</th><th>Auth</th><th>Ação</th></tr></thead><tbody>${routeRows}</tbody></table>` : ''}
  </div>` : ''}

  ${tpRows ? `<div class="section">
    <h2>🏢 Terceiros (fora do seu controle)</h2>
    <p style="font-size:13px;color:#868e96">Bibliotecas/CDNs/domínios de terceiros. Não entram na nota.</p>
    <table><thead><tr><th>Origem / Tipo</th><th style="text-align:center">Ocorrências</th></tr></thead><tbody>${tpRows}</tbody></table>
  </div>` : ''}

  ${screenshotsHtml}
  ${timelineHtml}
  ${testsHtml}
  ${appendixHtml}

  <footer>
    Gerado por <strong>Sentinela v2.2.2</strong> — Vulnerability Collector &amp; Security Auditor<br>
    <span style="font-size:10px">Este relatório é confidencial. Distribuir apenas para pessoas autorizadas.</span>
  </footer>

</div>${jsScript}</body></html>`;
}
