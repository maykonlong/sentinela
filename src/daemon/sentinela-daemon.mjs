/**
 * Sentinela Daemon — Orquestrador principal
 *
 * Integra:
 *  - Session Store (persistência contínua em disco)
 *  - Control Server (HTTP localhost:3141)
 *  - Auditor (Playwright + regras de segurança)
 *
 * Sinais de finalização (qualquer um encerra a sessão):
 *  1. POST /finalize via HTTP
 *  2. Arquivo sessions/<id>/.finalize (compatível com WSL/outros terminais)
 *  3. Browser fechado (Playwright browser.on('disconnected'))
 *  4. Timeout configurável (padrão: 60 min)
 *  5. SIGINT / SIGTERM → graceful shutdown
 */

import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { readFileSync, existsSync } from 'fs';
import chalk from 'chalk';

import * as store from './session-store.mjs';
import { startControlServer, updateServerState, controlEvents, setReportPath } from './control-server.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── Controle de finalização ───────────────────────────────────
let _finalized = false;
let _finalizeResolve = null;
const finalizePromise = new Promise(resolve => { _finalizeResolve = resolve; });

function triggerFinalize(reason = 'manual') {
  if (_finalized) return;
  _finalized = true;
  console.log(chalk.cyan(`\n🔔 Sinal de finalização recebido: ${reason}`));
  if (_finalizeResolve) _finalizeResolve(reason);
}

// Polling de arquivo sentinela a cada 2s (compatível com WSL/scripts externos)
function startFinalizeFileWatcher(sessionId) {
  const interval = setInterval(() => {
    if (store.isFinalizeSigned(sessionId)) {
      clearInterval(interval);
      triggerFinalize('arquivo .finalize detectado');
    }
  }, 2000);
  return interval;
}

// ── Interface pública de callback para o auditor ──────────────

/**
 * Cria hooks para o auditor.mjs injetar dados na sessão em tempo real.
 * O auditor chama esses callbacks a cada finding/rota/screenshot detectado.
 */
function createSessionHooks(sessionId) {
  const findings = [];

  return {
    onFinding(finding) {
      findings.push(finding);
      store.appendFinding(sessionId, finding);
      controlEvents.emit('finding', finding);
      updateServerState({ findings, meta: store.getSessionMeta(sessionId) });
    },

    onRoute(route) {
      store.appendRoute(sessionId, route);
      const meta = store.getSessionMeta(sessionId);
      updateServerState({ meta });
    },

    onScreenshot(url, buffer) {
      store.saveScreenshot(sessionId, url, buffer);
      const meta = store.getSessionMeta(sessionId);
      if (meta) {
        meta.lastUrl = url;
        updateServerState({ meta });
      }
    },

    onTimeline(text, type) {
      store.appendTimeline(sessionId, text, type);
    },

    onInfra(infraData) {
      store.saveInfra(sessionId, infraData);
    },

    onBrowserDisconnect() {
      triggerFinalize('browser fechado');
    },

    requestScreenshot: null, // preenchido pelo auditor
    getFindings: () => findings,
  };
}

// ── Crash recovery ────────────────────────────────────────────

/**
 * Verifica se existe sessão IN_PROGRESS e decide o que fazer.
 * Retorna: {action:'resume'|'report'|'discard', sessionId} | null (sem sessão anterior)
 *
 * @param {string|null} onOrphan - decisão pré-definida ('report'|'resume'|'discard'|'fail').
 *   Quando informada, NÃO pergunta nada. É o caminho usado por automação/IA.
 */
async function handleCrashRecovery(onOrphan = null) {
  const active = store.findActiveSession();
  if (!active) return null;

  const elapsed = Math.round((Date.now() - new Date(active.startedAt).getTime()) / 60000);
  console.log(chalk.yellow(`\n⚠️  Sessão interrompida detectada:`));
  console.log(chalk.white(`   Alvo: ${active.target}`));
  console.log(chalk.white(`   Iniciada: ${new Date(active.startedAt).toLocaleString('pt-BR')} (${elapsed} min atrás)`));
  console.log(chalk.white(`   Achados salvos: ${active.findingsCount} | Rotas: ${active.routesCount}`));
  console.log('');

  // Resolve a decisão sem interação quando ela já foi dada por flag.
  const decide = (n) => {
    if (n === 'resume' || n === '2') return { action: 'resume', sessionId: active.id };
    if (n === 'discard' || n === '3') { store.archiveSession(active.id); return { action: 'discard' }; }
    if (n === 'fail') {
      throw new Error(`Sessão ${active.id} está IN_PROGRESS e --on-orphan=fail foi pedido. ` +
        `Resolva com: node sentinela.mjs report ${active.id} | resume ${active.id} | cancel`);
    }
    return { action: 'report', sessionId: active.id };
  };

  if (onOrphan) {
    console.log(chalk.gray(`  → --on-orphan=${onOrphan} (sem pergunta)`));
    return decide(onOrphan);
  }

  // SEM TTY (rodando em background, via IA, cron, pipe) o stdin já está em EOF:
  // o callback do readline NUNCA dispara e esta Promise nunca resolve — o
  // processo fica pendurado para sempre sem nem abrir o browser. Foi exatamente
  // o que travou uma sessão real. Sem terminal interativo, assume o padrão
  // seguro e não-destrutivo: gerar relatório com o que já está salvo em disco.
  if (!process.stdin.isTTY) {
    console.log(chalk.gray('  → sem terminal interativo: gerando relatório com os dados salvos.'));
    console.log(chalk.gray('    (use --on-orphan=resume|discard|fail para escolher outro comportamento)'));
    return decide('report');
  }

  console.log(chalk.cyan('O que deseja fazer?'));
  console.log(chalk.white('  [1] Gerar relatório com os dados salvos (sem reabrir browser)'));
  console.log(chalk.white('  [2] Retomar auditoria (reabrir browser na mesma sessão)'));
  console.log(chalk.white('  [3] Descartar e iniciar nova sessão'));
  console.log('');

  const { createInterface } = await import('readline');
  const rl = createInterface({ input: process.stdin, output: process.stdout });

  return new Promise((resolve, reject) => {
    // Rede de segurança: se o stdin fechar sem resposta (ex.: pipe encerrado),
    // resolve no padrão em vez de pendurar o processo.
    let done = false;
    const finish = (fn) => { if (done) return; done = true; rl.close(); try { fn(); } catch (e) { reject(e); } };

    rl.on('close', () => { if (!done) { done = true; try { resolve(decide('report')); } catch (e) { reject(e); } } });
    rl.question('Escolha [1/2/3]: ', answer => {
      finish(() => resolve(decide(answer.trim())));
    });
  });
}

// ── Geração de relatório a partir da sessão ───────────────────

export async function generateFromSession(sessionId) {
  const session = store.loadSession(sessionId);
  if (!session) throw new Error(`Sessão ${sessionId} não encontrada`);

  const { meta, routes, timeline, screenshotPaths, infra } = session;

  // findings.ndjson guarda o fluxo BRUTO: um achado por resposta HTTP. Sem
  // deduplicar, o mesmo "Sem COOP" vira 27 achados (um por URL) e infla
  // contagem, nota, HTML e artefatos de teste. O caminho do auditor ao vivo já
  // deduplicava; este aqui não — e as duas rotas produziam números diferentes
  // para a MESMA sessão (351 vs 41). Fonte única: src/report/dedup.mjs.
  const { deduplicateFindings } = await import('../report/dedup.mjs');
  const findings = deduplicateFindings(session.findings);

  // Carregar screenshots como base64
  const screenshots = screenshotPaths.map(p => {
    try {
      return { url: p, base64: readFileSync(p).toString('base64') };
    } catch { return null; }
  }).filter(Boolean);

  // Importar módulos de geração de relatório
  const { mapFinding } = await import('../rules/owasp-map.mjs');
  const { enrichWithVerification } = await import('../generators/manual-verification.mjs');
  const { generateTestArtifacts } = await import('../generators/test-generator.mjs');
  const { computeScoreBreakdown } = await import('../report/score-breakdown.mjs');
  const { generateEnterpriseHtml } = await import('../report/html-report.mjs');
  const { generateEnterpriseMd } = await import('../report/md-report.mjs');
  const { exportPdf } = await import('../report/pdf-export.mjs');
  const { writeFileSync, mkdirSync } = await import('fs');
  const { join: pathJoin, dirname: pathDirname } = await import('path');

  // Enriquecer com OWASP/CWE
  for (const f of findings) {
    const m = mapFinding(f);
    f.owasp = m.owasp;
    f.cwe = m.cwe;
    if (!f.confidence) f.confidence = m.confidence;
  }

  const enriched = enrichWithVerification(findings, meta.target);
  const firstParty = enriched.filter(f => !f.thirdParty);
  const thirdParty = enriched.filter(f => f.thirdParty);
  const firstPartyIssues = firstParty.filter(f => f.severity !== 'INFO');

  const scoreBreakdown = computeScoreBreakdown(firstPartyIssues);

  function countBySeverity(arr) {
    return arr.reduce((acc, f) => {
      if (f.severity !== 'INFO') acc[f.severity] = (acc[f.severity] || 0) + 1;
      return acc;
    }, { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 });
  }

  const counts = countBySeverity(firstParty);
  const thirdCounts = countBySeverity(thirdParty);
  const testArtifacts = generateTestArtifacts(meta.target, firstPartyIssues);

  // Preparar diretório de relatórios
  const reportsDir = pathJoin(__dirname, '..', '..', 'reports');
  mkdirSync(reportsDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const htmlPath = pathJoin(reportsDir, `security-audit-${stamp}.html`);
  const mdPath = pathJoin(reportsDir, `security-audit-${stamp}.md`);
  const jsonPath = pathJoin(reportsDir, `security-audit-${stamp}.json`);
  const pdfPath = pathJoin(reportsDir, `security-audit-${stamp}.pdf`);

  const reportMeta = {
    target: meta.target,
    company: meta.options?.company || meta.company,
    client: meta.options?.client || meta.client,
    logo: meta.options?.logo || meta.logo,
    timestamp: new Date().toISOString(),
    pagesAudited: meta.pagesCount || 1,
    totalFindings: enriched.length,
    firstPartyIssues: firstPartyIssues.length,
    thirdPartyIssues: thirdParty.filter(f => f.severity !== 'INFO').length,
    severity: counts,
    thirdPartySeverity: thirdCounts,
    score: scoreBreakdown.totalScore,
    grade: scoreBreakdown.grade,
    gradeLabel: scoreBreakdown.gradeLabel,
    phases: ['PRÉ-LOGIN', 'LOGIN', 'PÓS-LOGIN'],
    sessionId,
  };

  function evidenceOf(f) {
    const parts = [];
    const trunc = s => { const t = String(s); return t.length > 220 ? t.slice(0, 220) + '…' : t; };
    if (f.currentValue) parts.push(`valor atual: ${trunc(f.currentValue)}`);
    if (f.valuePreview) parts.push(`valor: ${trunc(f.valuePreview)}`);
    if (f.tokenPreview) parts.push(`${f.tokenField || 'token'}: ${trunc(f.tokenPreview)}`);
    if (f.value && !f.valuePreview) parts.push(`valor: ${trunc(typeof f.value === 'string' ? f.value : JSON.stringify(f.value))}`);
    if (f.formAction) parts.push(`action: ${trunc(f.formAction)} (${(f.formMethod || 'GET').toUpperCase()})`);
    return parts;
  }

  const reportData = {
    meta: reportMeta,
    scoreBreakdown,
    infra,
    findings: firstPartyIssues,
    thirdParty: thirdParty.filter(f => f.severity !== 'INFO'),
    inventory: enriched.filter(f => f.severity === 'INFO'),
    routes,
    pagesVisited: [],
    testArtifacts,
  };

  // Salvar JSON completo
  writeFileSync(jsonPath, JSON.stringify(reportData, null, 2), 'utf8');

  // Salvar SUMMARY enxuto — pensado para ser lido por IA/automação.
  // O JSON completo passa de 300 KB (só `manualVerification` é ~1/3 dele) e
  // custa dezenas de milhares de tokens para uma IA ler. O summary carrega o
  // que responde 90% das perguntas ("quão ruim está? o que é mais grave? onde?")
  // em ~15 KB, e aponta para o JSON completo quando o detalhe for necessário.
  const summaryPath = pathJoin(reportsDir, `security-audit-${stamp}.summary.json`);
  const summary = {
    meta: reportMeta,
    score: {
      total: scoreBreakdown.totalScore,
      grade: scoreBreakdown.grade,
      gradeLabel: scoreBreakdown.gradeLabel,
      // gradeCap: quando a nota foi limitada por severidade (ex.: existe CRITICAL,
      // então no máximo D) — a IA precisa disso para explicar a nota corretamente.
      gradeCap: scoreBreakdown.gradeCap ?? null,
      maxPossible: scoreBreakdown.maxPossible ?? null,
      // Só categorias efetivamente AVALIADAS entram — categoria não avaliada não
      // é categoria aprovada (era o "piso grátis" de 60 pts do modelo antigo).
      categories: (scoreBreakdown.categories || [])
        .filter(c => c.evaluated !== false)
        .map(c => ({
          id: c.id, label: c.label,
          earnedPts: c.earnedPts, maxPts: c.maxPts, pct: c.pct,
          issues: c.issueCount, occurrences: c.occurrenceTotal,
        })),
      unmappedTypes: scoreBreakdown.unmappedTypes || [],
    },
    counts,
    // Só o essencial por achado. Sem manualVerification, sem recommendation longa.
    findings: firstPartyIssues.map(f => ({
      type: f.type,
      severity: f.severity,
      subject: f.header || f.cookieName || f.key || f.library || f.port || null,
      url: f.url || null,
      owasp: f.owasp || null,
      cwe: f.cwe || null,
      confidence: f.confidence || null,
      occurrences: f.occurrenceCount || 1,
      risk: typeof f.risk === 'string' ? f.risk.slice(0, 240) : null,
    })),
    reports: { html: htmlPath, md: mdPath, json: jsonPath, pdf: pdfPath },
  };
  writeFileSync(summaryPath, JSON.stringify(summary, null, 2), 'utf8');

  // Gerar e salvar HTML
  const { generateEnterpriseMd: genMd } = await import('../report/md-report.mjs');
  const htmlContent = generateEnterpriseHtml({
    ...reportData,
    infraData: infra,
    screenshots,
    timeline,
    regression: { hasPrev: false, new: [], fixed: [], persisted: 0 },
    counts,
    evidenceOf,
  });
  writeFileSync(htmlPath, htmlContent, 'utf8');

  // Gerar e salvar MD
  const mdContent = genMd({
    ...reportData,
    regression: { hasPrev: false, new: [], fixed: [], persisted: 0 },
    counts,
    evidenceOf,
  });
  writeFileSync(mdPath, mdContent, 'utf8');

  // PDF em background
  exportPdf(htmlPath, pdfPath).then(() => {
    console.log(chalk.green(`  📄 PDF gerado: ${pdfPath}`));
  }).catch(err => {
    console.log(chalk.gray(`  (PDF: ${err.message})`));
  });

  return { htmlPath, mdPath, jsonPath, pdfPath, summaryPath, scoreBreakdown, counts };
}

// ── Função principal exportada ────────────────────────────────

/**
 * Inicia o daemon de auditoria.
 * @param {string} targetUrl - URL a auditar
 * @param {object} opts - opções (scope, activeMode, timeoutMs, sessionId)
 */
export async function startDaemon(targetUrl, opts = {}) {
  const { scope = 'navigate', activeMode = false, secondAccount = false, timeoutMs = 60 * 60 * 1000 } = opts;

  // 1. Verificar crash recovery
  if (!opts.sessionId) {
    const recovery = await handleCrashRecovery(opts.onOrphan);
    if (recovery) {
      if (recovery.action === 'report') {
        console.log(chalk.cyan('\n📝 Gerando relatório da sessão anterior...'));
        const paths = await generateFromSession(recovery.sessionId);
        store.markDone(recovery.sessionId, paths);
        console.log(chalk.green(`\n✅ Relatório gerado: ${paths.htmlPath}`));
        return;
      }
      if (recovery.action === 'resume') {
        opts.sessionId = recovery.sessionId;
        console.log(chalk.cyan(`\n🔄 Retomando sessão ${recovery.sessionId}...`));
      }
      // 'discard' → cai no fluxo normal de nova sessão
    }
  }

  // 2. Criar ou usar sessão existente
  const sessionId = opts.sessionId || store.createSession(targetUrl, { scope, activeMode, timeoutMs });
  store.appendTimeline(sessionId, `Auditoria iniciada: ${targetUrl}`, 'info');

  console.log(chalk.cyan(`\n🗂️  Sessão: ${sessionId}`));
  console.log(chalk.cyan(`🌐 Controle ao vivo: http://localhost:3141`));

  // 3. Criar hooks de sessão
  const hooks = createSessionHooks(sessionId);

  // 4. Iniciar HTTP control server
  let screenshotRequestCallback = null;
  const server = startControlServer(
    () => triggerFinalize('botão Finalizar no browser'),
    () => { if (screenshotRequestCallback) screenshotRequestCallback(); }
  );
  updateServerState({ meta: store.getSessionMeta(sessionId), findings: store.loadFindings(sessionId), sessionId });

  // 5. Iniciar polling de arquivo .finalize
  const fileWatcherInterval = startFinalizeFileWatcher(sessionId);

  // 6. Timeout de segurança
  const timeoutHandle = setTimeout(() => {
    triggerFinalize(`timeout de ${Math.round(timeoutMs / 60000)} minutos`);
  }, timeoutMs);

  // 7. Graceful shutdown em SIGINT/SIGTERM
  const handleSignal = (sig) => triggerFinalize(`sinal ${sig}`);
  process.once('SIGINT', () => handleSignal('SIGINT'));
  process.once('SIGTERM', () => handleSignal('SIGTERM'));

  // 8. Importar e executar o auditor com hooks
  try {
    const { runAudit } = await import('../auditor.mjs');
    screenshotRequestCallback = () => hooks.onScreenshot && hooks._requestScreenshot?.();

    // Executar auditoria com hooks de sessão
    await runAudit(targetUrl, { scope, activeMode }, hooks, finalizePromise);

  } catch (err) {
    console.error(chalk.red(`\n❌ Erro no auditor: ${err.message}`));
    store.appendTimeline(sessionId, `Erro: ${err.message}`, 'error');
  }

  // 9. Limpar timers
  clearInterval(fileWatcherInterval);
  clearTimeout(timeoutHandle);
  server.close();

  // 10. Gerar relatório final
  console.log(chalk.cyan('\n📝 Gerando relatório completo...'));
  try {
    const paths = await generateFromSession(sessionId);
    store.markDone(sessionId, paths);
    setReportPath(paths.htmlPath);

    const score = paths.scoreBreakdown.totalScore;
    const grade = paths.scoreBreakdown.grade;
    const gradeLabel = paths.scoreBreakdown.gradeLabel;
    const counts = paths.counts;

    console.log(chalk.cyan.bold(`
╔════════════════════════════════════════════════════════════╗
║                    RESULTADO DA AUDITORIA                  ║
╠════════════════════════════════════════════════════════════╣`));
    console.log(chalk.white(`║  🎯 Alvo: ${targetUrl.padEnd(47)}║`));
    console.log(chalk.white(`║  📊 NOTA: ${score}/100 — ${grade} (${gradeLabel})`.padEnd(63) + '║'));
    if (counts.CRITICAL > 0) console.log(chalk.red(`║  🔴 CRITICAL: ${String(counts.CRITICAL).padEnd(43)}║`));
    if (counts.HIGH > 0) console.log(chalk.red(`║  🟠 HIGH:     ${String(counts.HIGH).padEnd(43)}║`));
    if (counts.MEDIUM > 0) console.log(chalk.yellow(`║  🟡 MEDIUM:   ${String(counts.MEDIUM).padEnd(43)}║`));
    if (counts.LOW > 0) console.log(chalk.blue(`║  🔵 LOW:      ${String(counts.LOW).padEnd(43)}║`));
    console.log(chalk.cyan.bold(`╠════════════════════════════════════════════════════════════╣`));
    console.log(chalk.white(`║  🌐 HTML: ${paths.htmlPath.split('\\').pop().padEnd(48)}║`));
    console.log(chalk.white(`║  📄 PDF:  ${paths.pdfPath.split('\\').pop().padEnd(48)}║`));
    console.log(chalk.white(`║  📝 MD:   ${paths.mdPath.split('\\').pop().padEnd(48)}║`));
    console.log(chalk.cyan.bold(`╚════════════════════════════════════════════════════════════╝`));
  } catch (err) {
    console.error(chalk.red(`\n❌ Erro ao gerar relatório: ${err.message}`));
  }
}
