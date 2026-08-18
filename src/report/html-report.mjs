/**
 * HTML Report Generator — Relatório empresarial completo
 *
 * Gera relatório HTML profissional com:
 * - Capa com selo A/B/C/D/F
 * - Sumário executivo (linguagem C-level)
 * - Seção de infraestrutura (portas, timing, GeoIP, reputação)
 * - Score breakdown visual por categoria
 * - Achados com "Como Verificar Manualmente" e snippets de correção
 * - Tabela de cookies e headers detalhada
 * - Screenshots embeddadas (base64)
 * - Timeline da auditoria
 * - Testes gerados
 * - Apêndice com glossário e metodologia
 */

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

const SEV_COLOR = { CRITICAL: '#c92a2a', HIGH: '#e8590c', MEDIUM: '#f08c00', LOW: '#1c7ed6', INFO: '#868e96' };
const SEV_EMOJI = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵', INFO: 'ℹ️' };

function card(label, val, color) {
  return `<div class="card"><div class="num" style="color:${color}">${val}</div><div class="lbl">${label}</div></div>`;
}

/**
 * Gera o relatório HTML empresarial completo.
 */
export function generateEnterpriseHtml({
  meta, findings, thirdParty, routes, pagesVisited, inventory,
  scoreBreakdown, infraData, testArtifacts, screenshots, timeline,
  regression, counts, evidenceOf,
}) {
  const score = scoreBreakdown.totalScore;
  const grade = scoreBreakdown.grade;
  const gradeColor = scoreBreakdown.gradeColor;
  const gradeLabel = scoreBreakdown.gradeLabel;

  // ── CSS ──
  const css = `
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap');
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Inter', -apple-system, Segoe UI, Roboto, sans-serif; background: #f8f9fa; color: #212529; line-height: 1.5; }
    .wrap { max-width: 1060px; margin: 0 auto; padding: 24px; }
    
    /* ── Capa ── */
    .cover { background: linear-gradient(135deg, #1a1b1e 0%, #2c2e33 100%); color: #fff; border-radius: 16px; padding: 36px; display: flex; justify-content: space-between; align-items: center; gap: 24px; flex-wrap: wrap; margin-bottom: 24px; box-shadow: 0 4px 24px rgba(0,0,0,.15); }
    .cover h1 { font-size: 20px; font-weight: 700; margin: 0 0 8px; }
    .cover .target { color: #adb5bd; font-size: 13px; word-break: break-all; }
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
    .port-table { font-size: 12px; }
    .port-table td, .port-table th { padding: 5px 8px; }
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
    
    /* ── Verificação Manual ── */
    .verify { background: #fff4e6; border: 1px solid #ffe8cc; border-radius: 8px; padding: 10px 14px; margin: 8px 0; font-size: 12px; }
    .verify-title { font-weight: 600; color: #e8590c; margin-bottom: 6px; font-size: 12px; }
    .verify ol { padding-left: 20px; margin: 4px 0; }
    .verify li { margin: 2px 0; }
    .verify .cmd { background: #1a1b1e; color: #51cf66; padding: 6px 10px; border-radius: 4px; font-family: 'Consolas', monospace; font-size: 11px; margin: 4px 0; display: block; word-break: break-all; }
    
    /* ── Tabelas ── */
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th, td { padding: 8px 10px; border-bottom: 1px solid #f1f3f5; text-align: left; }
    th { background: #f8f9fa; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: .3px; color: #495057; }
    .routes code { word-break: break-all; font-size: 11px; }
    
    /* ── Screenshots ── */
    .screenshots { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 16px; }
    .screenshot { border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,.1); }
    .screenshot img { width: 100%; display: block; }
    .screenshot .ss-label { font-size: 11px; color: #868e96; padding: 6px 10px; background: #f8f9fa; }
    
    /* ── Timeline ── */
    .timeline { border-left: 2px solid #e9ecef; padding-left: 16px; }
    .tl-item { margin: 8px 0; position: relative; }
    .tl-item::before { content: ''; position: absolute; left: -21px; top: 6px; width: 8px; height: 8px; border-radius: 50%; background: #868e96; }
    .tl-item.tl-warn::before { background: #f08c00; }
    .tl-item.tl-error::before { background: #c92a2a; }
    .tl-time { font-size: 11px; color: #868e96; font-family: monospace; }
    .tl-text { font-size: 12px; }
    
    /* ── Código ── */
    .code-block { background: #1a1b1e; color: #c1c2c5; border-radius: 8px; padding: 14px 16px; font-family: 'Consolas', 'Fira Code', monospace; font-size: 12px; overflow-x: auto; white-space: pre; margin: 8px 0; line-height: 1.6; }
    
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
    }
  </style>`;

  // ── Sumário Executivo ──
  const criticals = findings.filter(f => f.severity === 'CRITICAL');
  const highs = findings.filter(f => f.severity === 'HIGH');
  const topRisks = [...criticals, ...highs].slice(0, 3);

  const execSummaryHtml = `
  <div class="section exec-summary">
    <h2>📊 Sumário Executivo</h2>
    <p>A auditoria de segurança do site <span class="highlight">${esc(meta.target)}</span> identificou 
    <span class="highlight">${meta.firstPartyIssues} problema(s)</span> no seu código/configuração, 
    resultando em uma nota de <span class="highlight">${score}/100 (${grade} — ${gradeLabel})</span>.</p>
    
    ${criticals.length > 0 ? `<p style="color:#c92a2a;font-weight:600">⚠️ ${criticals.length} problema(s) CRÍTICO(S) requerem atenção imediata.</p>` : ''}
    
    ${topRisks.length > 0 ? `
    <h3>Top Riscos</h3>
    <ol>${topRisks.map(f => `<li><strong>[${f.severity}]</strong> ${esc(f.label || f.type)}${f.risk ? ` — ${esc(f.risk.substring(0, 120))}${f.risk.length > 120 ? '…' : ''}` : ''}</li>`).join('')}</ol>
    ` : '<p style="color:#2f9e44">✅ Nenhum problema crítico ou alto encontrado.</p>'}
    
    <p style="margin-top:12px;font-size:12px;color:#868e96">Auditoria realizada em ${new Date(meta.timestamp).toLocaleString('pt-BR')} · ${meta.pagesAudited} página(s) · Fases: PRÉ-LOGIN → LOGIN → PÓS-LOGIN</p>
  </div>`;

  // ── Score Breakdown ──
  const breakdownHtml = `
  <div class="section">
    <h2>📈 Score por Categoria</h2>
    <div class="breakdown-grid">
      ${scoreBreakdown.categories.map(cat => {
        const fillColor = cat.pct >= 80 ? '#2f9e44' : cat.pct >= 50 ? '#f08c00' : '#c92a2a';
        return `<div class="cat-bar">
          <div class="cat-head">
            <span class="cat-name">${esc(cat.label)}</span>
            <span class="cat-score" style="color:${fillColor}">${cat.earnedPts}/${cat.maxPts}</span>
          </div>
          <div class="bar-bg"><div class="bar-fill" style="width:${cat.pct}%;background:${fillColor}"></div></div>
          <div class="cat-detail">${cat.issueCount > 0 ? `${cat.issueCount} achado(s) · ${cat.deduction}pts` : '✅ Nenhum problema'}</div>
        </div>`;
      }).join('')}
    </div>
  </div>`;

  // ── Infraestrutura ──
  let infraHtml = '';
  if (infraData) {
    const geo = infraData.geoip || {};
    const timing = infraData.socketTiming || {};
    const load = infraData.loadPercentiles || {};
    const rep = infraData.reputation || {};
    const tcp = infraData.tcpScan || {};

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

    // Portas abertas
    const openPorts = (tcp.ports || []).filter(p => p.state === 'OPEN');
    const portTableHtml = openPorts.length > 0 ? `
      <table class="port-table">
        <thead><tr><th>Porta</th><th>Serviço</th><th>Estado</th><th>Latência</th></tr></thead>
        <tbody>${openPorts.map(p => `<tr>
          <td><strong>${p.port}</strong></td><td>${esc(p.service)}</td>
          <td class="port-open">OPEN</td><td>${p.latency_ms}ms</td>
        </tr>`).join('')}</tbody>
      </table>
    ` : '<p style="font-size:12px;color:#868e96">Nenhuma porta enterprise aberta detectada (portas web padrão podem estar filtradas pelo CDN).</p>';

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

    const dnsSecHtml = !dnsSec.isIp && dnsSec.status ? `
      <h3>🛡️ Registros DNS de Segurança & E-mail</h3>
      <div class="infra-grid" style="margin-bottom:12px">
        <div class="infra-card">
          <div class="ic-label">SPF (Anti-Spoofing)</div>
          <div class="ic-value" style="color:${dnsSum.has_spf ? '#2f9e44' : '#f08c00'}">${dnsSum.has_spf ? '✅ Configurado' : '⚠️ Ausente'}</div>
          ${dnsRecs.SPF ? `<div style="font-size:10px;color:#495057;word-break:break-all;margin-top:4px"><code>${esc(dnsRecs.SPF)}</code></div>` : ''}
        </div>
        <div class="infra-card">
          <div class="ic-label">DMARC (Anti-Phishing)</div>
          <div class="ic-value" style="color:${dnsSum.has_dmarc ? '#2f9e44' : '#f08c00'}">${dnsSum.has_dmarc ? '✅ Configurado' : '⚠️ Ausente'}</div>
          ${dnsRecs.DMARC ? `<div style="font-size:10px;color:#495057;word-break:break-all;margin-top:4px"><code>${esc(dnsRecs.DMARC)}</code></div>` : ''}
        </div>
        <div class="infra-card">
          <div class="ic-label">CAA (Autorização de CA)</div>
          <div class="ic-value" style="color:${dnsSum.has_caa ? '#2f9e44' : '#f08c00'}">${dnsSum.has_caa ? '✅ Configurado' : '⚠️ Sem Restrição'}</div>
          ${dnsRecs.CAA && dnsRecs.CAA.length ? `<div style="font-size:10px;color:#495057;margin-top:4px"><code>${esc(dnsRecs.CAA.join(', '))}</code></div>` : ''}
        </div>
        <div class="infra-card">
          <div class="ic-label">IPv6 (Suporte AAAA)</div>
          <div class="ic-value" style="color:${dnsSum.has_ipv6 ? '#2f9e44' : '#868e96'}">${dnsSum.has_ipv6 ? '✅ Habilitado' : 'ℹ️ Somente IPv4'}</div>
          ${dnsRecs.AAAA && dnsRecs.AAAA.length ? `<div style="font-size:10px;color:#495057;margin-top:4px"><code>${esc(dnsRecs.AAAA[0])}</code></div>` : ''}
        </div>
      </div>
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
        <div class="infra-card"><div class="ic-label">Reputação IP</div><div class="ic-value" style="color:${rep.is_blacklisted ? '#c92a2a' : '#2f9e44'}">${rep.is_blacklisted ? '❌ Blacklisted' : '✅ Limpo'}</div></div>
      </div>

      ${dnsSecHtml}

      <h3>⚡ Latência por Fase (Socket)</h3>
      ${timingBarHtml}

      <h3>🔌 Portas TCP Abertas (${openPorts.length} de ${tcp.total_scanned || 0})</h3>
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
    
    return `<div class="finding sev-${f.severity}">
      <div class="fhead">
        <span class="pill" style="background:${SEV_COLOR[f.severity] || '#868e96'}">${f.severity}</span>
        <span class="ftitle">${esc(f.label || f.type)}</span>
      </div>
      <div class="fmeta">${[f.owasp, f.cwe && f.cwe !== '—' ? f.cwe : '', f.confidence ? 'confiança: ' + f.confidence : ''].filter(Boolean).map(esc).join(' · ')}</div>
      ${f.url ? `<div class="fwhere"><b>📍 Onde:</b> <code>${esc(f.url)}</code></div>` : ''}
      ${f.cve ? `<div class="fwhere"><b>CVE:</b> ${esc(f.cve)}${f.fixedIn ? ` — corrigido em ${esc(f.fixedIn)}` : ''}</div>` : ''}
      ${ev.length ? `<div class="fevid"><b>🔎 Evidência:</b><ul>${ev.map(e => `<li><code>${esc(e)}</code></li>`).join('')}</ul></div>` : ''}
      ${f.risk ? `<div class="frisk">${esc(f.risk)}</div>` : ''}
      ${f.recommendation ? `<div class="frec"><b>✅ Correção:</b> ${esc(f.recommendation)}</div>` : ''}
      ${mv ? `<div class="verify">
        <div class="verify-title">🧪 Como Verificar Manualmente</div>
        <ol>${mv.steps.map(s => `<li>${esc(s)}</li>`).join('')}</ol>
        ${mv.devtools ? `<p style="margin-top:4px"><b>DevTools:</b> ${esc(mv.devtools)}</p>` : ''}
        ${mv.automated ? `<p style="margin-top:6px;font-weight:600;color:#212529">Comando de Validação (Teste Focado):</p><span class="cmd">${esc(mv.automated)}</span>` : ''}
        ${mv.proofOfWork ? `<p style="margin-top:4px;font-weight:600;color:#212529">Comando de Prova Real (Dump Completo):</p><span class="cmd" style="color:#69db7c">${esc(mv.proofOfWork)}</span>` : ''}
      </div>` : ''}
    </div>`;
  };

  const owaspSections = Object.entries(byOwasp)
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([owasp, items]) => {
      items.sort((x, y) => sevRank[x.severity] - sevRank[y.severity]);
      return `<h3>${esc(owasp)} <span class="count">(${items.length})</span></h3>${items.map(findingHtml).join('')}`;
    }).join('');

  // ── Terceiros ──
  const tpGroups = {};
  for (const f of (thirdParty || [])) {
    const k = `${f.vendor || 'Terceiro'} — ${f.label || f.type}`;
    tpGroups[k] = (tpGroups[k] || 0) + 1;
  }
  const tpRows = Object.entries(tpGroups).sort((a, b) => b[1] - a[1])
    .map(([k, n]) => `<tr><td>${esc(k)}</td><td style="text-align:center">${n}</td></tr>`).join('');

  // ── Rotas ──
  const fpRoutes = (routes || []).filter(r => !r.thirdParty);
  const routeRows = fpRoutes.slice(0, 120).map(r =>
    `<tr><td>${esc(r.method)}</td><td><code>${esc(r.path + (r.query ? '?' + r.query : ''))}</code></td><td>${esc(r.kind)}</td><td>${esc(r.phase)}</td><td style="text-align:center">${r.hasAuth ? '🔑' : ''}</td></tr>`).join('');
  const pagesHtml = (pagesVisited || []).map(u => `<li><code>${esc(u)}</code></li>`).join('');

  // ── Screenshots ──
  const screenshotsHtml = (screenshots && screenshots.length > 0) ? `
  <div class="section">
    <h2>📸 Screenshots</h2>
    <div class="screenshots">
      ${screenshots.map(ss => `<div class="screenshot">
        <img src="data:image/png;base64,${ss.base64}" alt="${esc(ss.url)}" loading="lazy" />
        <div class="ss-label">${esc(ss.url)}</div>
      </div>`).join('')}
    </div>
  </div>` : '';

  // ── Timeline ──
  const timelineHtml = (timeline && timeline.length > 0) ? `
  <div class="section">
    <h2>📜 Timeline da Auditoria</h2>
    <div class="timeline">
      ${timeline.map(t => `<div class="tl-item ${t.type === 'warn' ? 'tl-warn' : t.type === 'error' ? 'tl-error' : ''}">
        <span class="tl-time">${esc(t.time)}</span>
        <span class="tl-text"> ${esc(t.text)}</span>
      </div>`).join('')}
    </div>
  </div>` : '';

  // ── Testes Gerados ──
  const testsHtml = testArtifacts ? `
  <div class="section">
    <h2>🧪 Testes de Verificação Gerados</h2>
    <p style="font-size:13px;color:#868e96;margin-bottom:12px">Execute estes testes para confirmar que as correções foram aplicadas corretamente.</p>
    
    <h3>Playwright (.spec.ts)</h3>
    <div class="code-block">${esc(testArtifacts.playwright)}</div>
    
    <h3>cURL</h3>
    <div class="code-block">${esc(testArtifacts.code_snippets?.curl || '')}</div>
    
    <h3>Correção Nginx</h3>
    <div class="code-block">${esc(testArtifacts.server_fix?.nginx || '')}</div>
    
    <h3>Correção Apache</h3>
    <div class="code-block">${esc(testArtifacts.server_fix?.apache || '')}</div>
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
    <p style="font-size:13px">O Sentinela é um auditor de segurança web guiado por humano. Abre um navegador real (Microsoft Edge InPrivate), você faz login e navega normalmente. Em paralelo, ele:</p>
    <ul style="font-size:13px;padding-left:20px;margin:8px 0">
      <li><strong>Coleta passiva:</strong> Headers, cookies, storage, código-fonte, certificado TLS, bibliotecas vulneráveis</li>
      <li><strong>Recon autônomo:</strong> robots.txt, sitemap.xml, Swagger/OpenAPI, GraphQL, CORS, erro verboso</li>
      <li><strong>Monitoramento de rede:</strong> Requisições/respostas, mixed content, tokens na URL</li>
      <li><strong>Análise de login:</strong> CSRF, credenciais em HTTP, session fixation, diff before/after</li>
      <li><strong>Infraestrutura:</strong> Port scan, timing de socket, GeoIP, reputação IP</li>
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

  // ── Montagem Final ──
  return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentinela — Relatório de Segurança — ${esc(meta.target)}</title>
${css}
</head><body><div class="wrap">

  <div class="cover">
    <div>
      <h1>🛡️ Sentinela — Relatório de Auditoria de Segurança</h1>
      <div class="target">${esc(meta.target)}</div>
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
  ${regHtml}
  ${infraHtml}
  ${breakdownHtml}

  <div class="section">
    <h2>🔎 Achados (seu código / config)</h2>
    ${findings.length ? owaspSections : '<p>Nenhum problema de 1ª parte encontrado. 🎉</p>'}
  </div>

  ${(routes || []).length ? `<div class="section">
    <h2>🗺️ Rotas e Endpoints</h2>
    <p style="font-size:13px;color:#868e96">${(routes || []).length} requisições distintas observadas (${fpRoutes.length} do seu domínio).</p>
    ${pagesHtml ? `<p style="font-size:13px;margin:8px 0"><b>Páginas visitadas:</b></p><ul class="routes" style="margin-bottom:12px">${pagesHtml}</ul>` : ''}
    ${routeRows ? `<table class="routes"><thead><tr><th>Método</th><th>Rota</th><th>Tipo</th><th>Fase</th><th>Auth</th></tr></thead><tbody>${routeRows}</tbody></table>` : ''}
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
    Gerado por <strong>Sentinela v2.0</strong> — Vulnerability Collector &amp; Security Auditor<br>
    <span style="font-size:10px">Este relatório é confidencial. Distribuir apenas para pessoas autorizadas.</span>
  </footer>

</div></body></html>`;
}
