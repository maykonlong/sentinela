/**
 * Markdown Report Generator — Relatório empresarial em Markdown
 *
 * Versão Markdown do relatório empresarial, com as mesmas seções
 * do HTML: sumário executivo, infraestrutura, breakdown, achados
 * com verificação manual, testes gerados.
 */

/**
 * Gera o relatório Markdown completo.
 */
export function generateEnterpriseMd({
  meta, findings, thirdParty, routes, pagesVisited, inventory,
  scoreBreakdown, infraData, testArtifacts, regression, counts, evidenceOf,
}) {
  const lines = [];
  const score = scoreBreakdown.totalScore;
  const grade = scoreBreakdown.grade;
  const gradeLabel = scoreBreakdown.gradeLabel;

  lines.push('# 🛡️ Sentinela — Relatório de Auditoria de Segurança');
  lines.push('');
  lines.push(`**Alvo:** ${meta.target}`);
  lines.push(`**Data:** ${new Date(meta.timestamp).toLocaleString('pt-BR')}`);
  lines.push(`**Páginas auditadas:** ${meta.pagesAudited}`);
  lines.push(`**Nota:** ${score}/100 (${grade} — ${gradeLabel})`);
  lines.push(`**Fases:** PRÉ-LOGIN → LOGIN → PÓS-LOGIN`);
  lines.push('');

  // ── Sumário Executivo ──
  lines.push('## 📊 Sumário Executivo');
  lines.push('');
  lines.push(`> Contagem e nota consideram **apenas problemas do seu código/config (1ª parte)**.`);
  lines.push('');

  const tc = meta.thirdPartySeverity || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  lines.push('| Severidade | Seu (1ª parte) | Terceiros |');
  lines.push('|------------|:--------------:|:---------:|');
  lines.push(`| 🔴 CRITICAL | ${counts.CRITICAL} | ${tc.CRITICAL} |`);
  lines.push(`| 🟠 HIGH | ${counts.HIGH} | ${tc.HIGH} |`);
  lines.push(`| 🟡 MEDIUM | ${counts.MEDIUM} | ${tc.MEDIUM} |`);
  lines.push(`| 🔵 LOW | ${counts.LOW} | ${tc.LOW} |`);
  lines.push(`| **TOTAL** | **${meta.firstPartyIssues}** | **${meta.thirdPartyIssues}** |`);
  lines.push('');

  // ── Score Breakdown ──
  lines.push('## 📈 Score por Categoria');
  lines.push('');
  lines.push('| Categoria | Pontos | Deduções | Achados |');
  lines.push('|-----------|:------:|:--------:|:-------:|');
  for (const cat of scoreBreakdown.categories) {
    lines.push(`| ${cat.label} | ${cat.earnedPts}/${cat.maxPts} | ${cat.deduction} | ${cat.issueCount} |`);
  }
  lines.push('');

  // ── Regressão ──
  if (regression && regression.hasPrev) {
    const delta = score - (regression.prevScore ?? score);
    const arrow = delta > 0 ? `📈 +${delta}` : delta < 0 ? `📉 ${delta}` : '➖ 0';
    lines.push('## 🔁 Comparação com Auditoria Anterior');
    lines.push('');
    lines.push(`- Nota: **${regression.prevScore ?? '?'} → ${score}** (${arrow})`);
    lines.push(`- 🆕 Novos: **${regression.new.length}** · ✅ Corrigidos: **${regression.fixed.length}** · ⏳ Persistentes: **${regression.persisted}**`);
    lines.push('');
  }

  // ── Infraestrutura ──
  if (infraData) {
    lines.push('## 🏗️ Infraestrutura');
    lines.push('');
    const geo = infraData.geoip || {};
    const timing = infraData.socketTiming || {};
    const load = infraData.loadPercentiles || {};
    const rep = infraData.reputation || {};
    const tcp = infraData.tcpScan || {};

    lines.push(`- **IP:** ${geo.ip || timing.ip || '—'}`);
    lines.push(`- **Localização:** ${geo.city || '—'}, ${geo.country || '—'} ${geo.country_code || ''}`);
    lines.push(`- **ISP:** ${geo.isp || '—'} · **ASN:** ${geo.asn || '—'}`);
    lines.push(`- **Reputação IP:** ${rep.is_blacklisted ? '❌ Blacklisted (' + (rep.blacklists_flagged || []).join(', ') + ')' : '✅ Limpo'}`);
    lines.push('');

    const dnsSec = infraData.dnsSecurity || {};
    if (!dnsSec.isIp && dnsSec.status) {
      const sum = dnsSec.summary || {};
      const recs = dnsSec.records || {};
      lines.push('### 🛡️ Registros DNS de Segurança & E-mail');
      lines.push('');
      lines.push(`- **SPF (Anti-Spoofing):** ${sum.has_spf ? '✅ Configurado (`' + recs.SPF + '`)' : '⚠️ Ausente (Risco de Email Spoofing)'}`);
      lines.push(`- **DMARC (Anti-Phishing):** ${sum.has_dmarc ? '✅ Configurado (`' + recs.DMARC + '`)' : '⚠️ Ausente (Sem política de rejeição)'}`);
      lines.push(`- **CAA (Autorização de CA):** ${sum.has_caa ? '✅ Configurado (`' + (recs.CAA || []).join(', ') + '`)' : '⚠️ Sem Restrição (Qualquer CA pública pode emitir)'}`);
      lines.push(`- **IPv6 (Suporte AAAA):** ${sum.has_ipv6 ? '✅ Habilitado (`' + recs.AAAA[0] + '`)' : 'ℹ️ Somente IPv4'}`);
      lines.push('');
    }

    if (timing.status === 'PASS') {
      lines.push('### ⚡ Latência por Fase');
      lines.push('');
      lines.push('| Fase | Tempo |');
      lines.push('|------|------:|');
      lines.push(`| DNS | ${timing.dns_ms}ms |`);
      lines.push(`| TCP | ${timing.tcp_ms}ms |`);
      lines.push(`| TLS | ${timing.tls_ms}ms |`);
      lines.push(`| TTFB | ${timing.ttfb_ms}ms |`);
      lines.push(`| Download | ${timing.download_ms}ms |`);
      lines.push(`| **Total** | **${timing.total_ms}ms** |`);
      lines.push('');
    }

    const openPorts = (tcp.ports || []).filter(p => p.state === 'OPEN');
    if (openPorts.length > 0) {
      lines.push('### 🔌 Portas TCP Abertas');
      lines.push('');
      lines.push('| Porta | Serviço | Latência |');
      lines.push('|------:|---------|--------:|');
      for (const p of openPorts) {
        lines.push(`| ${p.port} | ${p.service} | ${p.latency_ms}ms |`);
      }
      lines.push('');
    }

    if (load.percentiles) {
      lines.push('### 📊 Percentis de Carga');
      lines.push('');
      lines.push(`P50: ${load.percentiles.p50}ms · P75: ${load.percentiles.p75}ms · P90: ${load.percentiles.p90}ms · P95: ${load.percentiles.p95}ms · P99: ${load.percentiles.p99}ms`);
      lines.push(`> ${load.total_requests} requisições · ${load.success_rate_pct}% sucesso`);
      lines.push('');
    }
  }

  // ── Achados ──
  lines.push('## 🔎 Achados (seu código / config)');
  lines.push('');

  const byOwasp = {};
  for (const f of findings) {
    const k = f.owasp || 'Diversos / Boas práticas';
    (byOwasp[k] = byOwasp[k] || []).push(f);
  }

  for (const [owasp, items] of Object.entries(byOwasp).sort((a, b) => a[0].localeCompare(b[0]))) {
    const sevRank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    items.sort((x, y) => sevRank[x.severity] - sevRank[y.severity]);

    lines.push(`### ${owasp} (${items.length})`);
    lines.push('');

    for (const f of items) {
      lines.push(`#### [${f.severity}] ${f.label || f.type}`);
      lines.push('');

      const badge = [f.owasp, f.cwe && f.cwe !== '—' ? f.cwe : '', f.confidence ? `confiança: ${f.confidence}` : ''].filter(Boolean).join(' · ');
      if (badge) { lines.push(`\`${badge}\``); lines.push(''); }

      if (f.url) lines.push(`**📍 Onde:** \`${f.url}\``);

      const ev = evidenceOf ? evidenceOf(f) : [];
      if (ev.length > 0) {
        lines.push('');
        lines.push('**🔎 Evidência:**');
        ev.forEach(e => lines.push(`- \`${e}\``));
      }

      if (f.risk) { lines.push(''); lines.push(`**⚠️ Risco:** ${f.risk}`); }
      if (f.recommendation) { lines.push(''); lines.push(`**✅ Correção:** ${f.recommendation}`); }

      // Verificação manual
      if (f.manualVerification) {
        const mv = f.manualVerification;
        lines.push('');
        lines.push(`**🧪 Como Verificar:**`);
        mv.steps.forEach((s, i) => lines.push(`${i + 1}. ${s}`));
        if (mv.automated) {
          lines.push(`**Comando de Validação (Teste Focado):**`);
          lines.push(`\`\`\`bash\n${mv.automated}\n\`\`\``);
        }
        if (mv.proofOfWork) {
          lines.push(`**Comando de Prova Real (Dump Completo):**`);
          lines.push(`\`\`\`bash\n${mv.proofOfWork}\n\`\`\``);
        }
      }

      lines.push('');
      lines.push('---');
      lines.push('');
    }
  }

  // ── Terceiros ──
  const tpItems = thirdParty || [];
  if (tpItems.length > 0) {
    lines.push('## 🏢 Terceiros (fora do seu controle)');
    lines.push('');
    const groups = {};
    for (const f of tpItems) {
      const g = `${f.vendor || 'Terceiro'} — ${f.label || f.type}`;
      groups[g] = (groups[g] || 0) + 1;
    }
    lines.push('| Origem / Tipo | Ocorrências |');
    lines.push('|---------------|:-----------:|');
    for (const [g, n] of Object.entries(groups).sort((a, b) => b[1] - a[1])) {
      lines.push(`| ${g} | ${n} |`);
    }
    lines.push('');
  }

  // ── Rotas ──
  const fpRoutes = (routes || []).filter(r => !r.thirdParty);
  if (fpRoutes.length > 0) {
    lines.push('## 🗺️ Rotas e Endpoints');
    lines.push('');
    if (pagesVisited && pagesVisited.length > 0) {
      lines.push('**Páginas visitadas:**');
      pagesVisited.forEach(u => lines.push(`- ${u}`));
      lines.push('');
    }
    lines.push('| Método | Rota | Tipo | Fase | Auth |');
    lines.push('|--------|------|------|------|:----:|');
    for (const r of fpRoutes.slice(0, 100)) {
      lines.push(`| ${r.method} | \`${r.path}${r.query ? '?' + r.query : ''}\` | ${r.kind} | ${r.phase} | ${r.hasAuth ? '🔑' : ''} |`);
    }
    lines.push('');
  }

  // ── Testes ──
  if (testArtifacts) {
    lines.push('## 🧪 Testes de Verificação');
    lines.push('');
    if (testArtifacts.code_snippets?.curl) {
      lines.push('### cURL');
      lines.push('```bash');
      lines.push(testArtifacts.code_snippets.curl);
      lines.push('```');
      lines.push('');
    }
  }

  lines.push('---');
  lines.push('*Relatório gerado por **Sentinela v2.0** — Vulnerability Collector & Security Auditor*');

  return lines.join('\n');
}
