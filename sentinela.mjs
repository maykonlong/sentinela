#!/usr/bin/env node
/**
 * Sentinela CLI — Entry point principal
 *
 * Uso:
 *   node sentinela.mjs start <url> [--active] [--crawl] [--timeout 60]
 *   node sentinela.mjs done
 *   node sentinela.mjs status
 *   node sentinela.mjs sessions
 *   node sentinela.mjs resume <id>
 *   node sentinela.mjs report [id]
 *   node sentinela.mjs cancel
 */

import chalk from 'chalk';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { existsSync } from 'fs';

const __dirname = dirname(fileURLToPath(import.meta.url));

const args = process.argv.slice(2);
const command = args[0] || 'help';
const param = args[1];

// Parsear flags
const hasFlag = (f) => args.includes(f);
const getFlag = (f) => {
  const i = args.indexOf(f);
  if (i !== -1 && args[i + 1] && !args[i + 1].startsWith('--')) return args[i + 1];
  // aceita também a forma --flag=valor
  const eq = args.find(a => a.startsWith(f + '='));
  return eq ? eq.slice(f.length + 1) : null;
};

// ── Modo máquina (--json) ─────────────────────────────────────
// Toda a saída "bonita" é pt-BR com emoji e caixas ASCII — ótimo para humano,
// péssimo para automação. Com --json, cada comando imprime UMA linha JSON
// estável no stdout e nada mais, para poder ser consumido por IA/CI sem parsing
// de texto. Respeita também NO_COLOR (convenção de facto).
const jsonMode = hasFlag('--json');
if (jsonMode || process.env.NO_COLOR) chalk.level = 0;

/**
 * Emite o resultado de um comando: JSON puro em modo máquina, saída humana caso
 * contrário. `human` é uma função para não pagar o custo de montar texto à toa.
 */
function emit(payload, human) {
  if (jsonMode) console.log(JSON.stringify(payload));
  else if (human) human();
}

// Exit codes — permitem usar o Sentinela como gate em CI/automação sem parsear
// texto. Antes o processo sempre saía 0, mesmo com CRITICAL no relatório.
const EXIT = {
  OK: 0,          // executou e nada grave encontrado
  ERROR: 1,       // erro operacional (falha de execução)
  HIGH: 2,        // achados HIGH presentes
  CRITICAL: 3,    // achados CRITICAL presentes
  NO_SESSION: 4,  // não havia sessão para operar
};

function exitCodeFor(counts = {}) {
  if (counts.CRITICAL > 0) return EXIT.CRITICAL;
  if (counts.HIGH > 0) return EXIT.HIGH;
  return EXIT.OK;
}

// ── Banner ────────────────────────────────────────────────────

function printBanner() {
  console.log(chalk.cyan.bold(`
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗       ║
║   ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║       ║
║   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║       ║
║   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║       ║
║   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║       ║
║   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝       ║
║                    S E N T I N E L A  v2.1               ║
║        Vulnerability Collector · Security Auditor        ║
╚══════════════════════════════════════════════════════════╝`));
}

// ── Ajuda ─────────────────────────────────────────────────────

function printHelp() {
  printBanner();
  console.log(`
${chalk.white.bold('USO:')}
  ${chalk.cyan('node sentinela.mjs start')} ${chalk.gray('<url>')} ${chalk.yellow('[opções]')}
  ${chalk.cyan('node sentinela.mjs done')}
  ${chalk.cyan('node sentinela.mjs status')}
  ${chalk.cyan('node sentinela.mjs sessions')}
  ${chalk.cyan('node sentinela.mjs resume')} ${chalk.gray('<session-id>')}
  ${chalk.cyan('node sentinela.mjs report')} ${chalk.gray('[session-id]')}
  ${chalk.cyan('node sentinela.mjs cancel')}

${chalk.white.bold('OPÇÕES (start):')}
  ${chalk.yellow('--active')}         Modo ativo (IDOR, rate limit, enumeração, redirect, arquivos sensíveis)
  ${chalk.yellow('--second-account')} IDOR com 2 contas reais (--active). PAUSA e pede um 2º login humano.
  ${chalk.yellow('--crawl')}          Crawl automático de links internos
  ${chalk.yellow('--login-only')}     Auditar só a página de login
  ${chalk.yellow('--timeout 60')}     Timeout em minutos (padrão: 60)
  ${chalk.yellow('--on-orphan X')}    Sessão órfã: report | resume | discard | fail
                   (sem TTY o padrão é 'report' — não pergunta nada)

${chalk.white.bold('WHITE-LABEL (start):')}
  ${chalk.yellow('--company X')}      Nome da consultoria no relatório
  ${chalk.yellow('--client X')}       Nome do cliente auditado
  ${chalk.yellow('--logo CAMINHO')}   Logo a embutir no relatório

${chalk.white.bold('AUTOMAÇÃO / IA:')}
  ${chalk.yellow('--json')}           Saída de UMA linha JSON, sem cor/emoji (todos os comandos)
  ${chalk.gray('Exit codes:')}     0=ok  1=erro  2=HIGH  3=CRITICAL  4=sem sessão

${chalk.white.bold('EXEMPLOS:')}
  node sentinela.mjs start https://meusite.com
  node sentinela.mjs start https://10.4.0.20:8443/login --active --timeout 30
  node sentinela.mjs report --json          ${chalk.gray('# gera relatório do disco, sem browser')}
  node sentinela.mjs status --json
  node sentinela.mjs done
  curl -X POST http://localhost:3141/finalize   ${chalk.gray('# via WSL / outro terminal')}
`);
}

// ── Comando: start ────────────────────────────────────────────

async function cmdStart(targetUrl) {
  if (!targetUrl || !targetUrl.startsWith('http')) {
    console.error(chalk.red('❌ URL inválida. Use: node sentinela.mjs start https://...'));
    process.exit(1);
  }

  const scope = hasFlag('--login-only') ? 'login'
    : hasFlag('--crawl') ? 'crawl'
    : 'navigate';

  const activeMode = hasFlag('--active');
  // IDOR com 2 contas reais — pausa a auditoria pra você logar com uma 2ª
  // conta. Opt-in explícito, só some efeito junto com --active.
  const secondAccount = hasFlag('--second-account');
  const timeoutMin = parseInt(getFlag('--timeout') || '60', 10);
  const timeoutMs = timeoutMin * 60 * 1000;
  const company = getFlag('--company');
  const client = getFlag('--client');
  const logo = getFlag('--logo');
  // O que fazer se houver sessão IN_PROGRESS órfã: report|resume|discard|fail.
  // Sem a flag e sem TTY, o daemon assume 'report' (ver handleCrashRecovery).
  const onOrphan = getFlag('--on-orphan');

  printBanner();
  console.log(chalk.white(`\n🎯 Alvo: ${chalk.cyan.bold(targetUrl)}`));
  console.log(chalk.white(`📂 Escopo: ${scope}${activeMode ? chalk.magenta(' + ATIVO') : ''}`));
  if (company || client) {
    console.log(chalk.white(`🏢 White-Label: ${chalk.green(company || 'Consultoria')} → ${chalk.yellow(client || 'Cliente')}`));
  }
  console.log(chalk.white(`⏱️  Timeout: ${timeoutMin} minutos`));
  console.log(chalk.gray('\n  → Controle ao vivo: http://localhost:3141'));
  console.log(chalk.gray('  → Finalizar: node sentinela.mjs done'));
  console.log(chalk.gray('  → Ou: curl -X POST http://localhost:3141/finalize\n'));

  const { startDaemon } = await import('./src/daemon/sentinela-daemon.mjs');
  await startDaemon(targetUrl, { scope, activeMode, secondAccount, timeoutMs, company, client, logo, onOrphan });
}

// ── Comando: done ─────────────────────────────────────────────

async function cmdDone() {
  // Primeiro tenta via HTTP (mais rápido se daemon estiver rodando)
  try {
    const res = await fetch('http://localhost:3141/finalize', { method: 'POST', signal: AbortSignal.timeout(2000) });
    if (res.ok) {
      emit({ ok: true, command: 'done', via: 'http' }, () =>
        console.log(chalk.green('✅ Sinal de finalização enviado via HTTP. O relatório será gerado em instantes.')));
      return;
    }
  } catch { /* daemon não está rodando em HTTP */ }

  // Fallback: criar arquivo .finalize na sessão ativa
  const { findActiveSession, signalFinalize } = await import('./src/daemon/session-store.mjs');
  const active = findActiveSession();
  if (!active) {
    emit({ ok: false, command: 'done', error: 'no_session' }, () => {
      console.log(chalk.yellow('⚠️  Nenhuma sessão ativa encontrada.'));
      console.log(chalk.gray('  Use: node sentinela.mjs sessions — para ver todas as sessões'));
    });
    process.exit(EXIT.NO_SESSION);
  }

  signalFinalize(active.id);
  emit({ ok: true, command: 'done', via: 'file', session: active.id }, () => {
    console.log(chalk.green(`✅ Arquivo .finalize criado para sessão ${active.id}`));
    console.log(chalk.gray('  O daemon irá detectar e finalizar em até 2 segundos.'));
  });
}

// ── Comando: status ───────────────────────────────────────────

async function cmdStatus() {
  // Tentar via HTTP primeiro
  try {
    const res = await fetch('http://localhost:3141/status', { signal: AbortSignal.timeout(2000) });
    if (res.ok) {
      const data = await res.json();
      const meta = data.meta;
      if (meta) {
        const elapsed = Math.round((Date.now() - new Date(meta.startedAt).getTime()) / 1000);
        emit({
          ok: true, command: 'status', source: 'daemon', active: true, daemonAlive: true,
          session: meta.id, target: meta.target, status: meta.status,
          elapsedSeconds: elapsed, findings: meta.findingsCount, routes: meta.routesCount,
          control: 'http://localhost:3141',
        }, () => {
          console.log(chalk.cyan.bold('\n🛡️  Sentinela — Sessão Ativa (via HTTP)\n'));
          console.log(`  Sessão:   ${meta.id}`);
          console.log(`  Alvo:     ${meta.target}`);
          console.log(`  Status:   ${meta.status}`);
          console.log(`  Duração:  ${Math.floor(elapsed / 60)}m ${elapsed % 60}s`);
          console.log(`  Achados:  ${meta.findingsCount}`);
          console.log(`  Rotas:    ${meta.routesCount}`);
          console.log(`  Controle: http://localhost:3141\n`);
        });
        return;
      }
    }
  } catch { /* daemon não rodando */ }

  // Fallback: ler do disco
  const { findActiveSession } = await import('./src/daemon/session-store.mjs');
  const active = findActiveSession();
  if (!active) {
    emit({ ok: true, command: 'status', active: null }, () =>
      console.log(chalk.yellow('\n⚠️  Nenhuma sessão ativa no momento.\n')));
    process.exit(EXIT.NO_SESSION);
  }
  emit({
    ok: true, command: 'status', source: 'disk', active: true,
    session: active.id, target: active.target, status: active.status,
    findings: active.findingsCount, routes: active.routesCount,
  }, () => {
    console.log(chalk.cyan.bold('\n🛡️  Sentinela — Última sessão ativa (disco)\n'));
    console.log(`  Sessão:  ${active.id}`);
    console.log(`  Alvo:    ${active.target}`);
    console.log(`  Status:  ${active.status}`);
    console.log(`  Achados: ${active.findingsCount}`);
    console.log(`  Rotas:   ${active.routesCount}\n`);
  });
}

// ── Comando: sessions ─────────────────────────────────────────

async function cmdSessions() {
  const { listSessions } = await import('./src/daemon/session-store.mjs');
  const sessions = listSessions();

  if (sessions.length === 0) {
    emit({ ok: true, command: 'sessions', sessions: [] }, () =>
      console.log(chalk.yellow('\n  Nenhuma sessão encontrada.\n')));
    process.exit(EXIT.NO_SESSION);
  }

  if (jsonMode) {
    emit({
      ok: true, command: 'sessions',
      sessions: sessions.map(s => ({
        id: s.id, target: s.target, status: s.status, startedAt: s.startedAt,
        findings: s.findingsCount, routes: s.routesCount, pages: s.pagesCount,
      })),
    });
    return;
  }

  console.log(chalk.cyan.bold('\n🗂️  Sessões de Auditoria\n'));
  const statusIcon = { IN_PROGRESS: '🟢', DONE: '✅', CANCELLED: '❌' };
  for (const s of sessions) {
    const icon = statusIcon[s.status] || '❓';
    const date = new Date(s.startedAt).toLocaleString('pt-BR');
    console.log(`  ${icon} ${chalk.white(s.id)}`);
    console.log(`     ${chalk.gray(s.target)} | ${date}`);
    console.log(`     ${s.findingsCount} achados | ${s.routesCount} rotas | ${s.pagesCount} páginas\n`);
  }
}

// ── Comando: resume ───────────────────────────────────────────

async function cmdResume(sessionId) {
  const { getSessionMeta } = await import('./src/daemon/session-store.mjs');
  const meta = getSessionMeta(sessionId);

  if (!meta) {
    console.error(chalk.red(`❌ Sessão ${sessionId} não encontrada.`));
    process.exit(1);
  }

  console.log(chalk.cyan(`\n🔄 Retomando sessão: ${sessionId}`));
  console.log(chalk.gray(`   Alvo: ${meta.target} | ${meta.findingsCount} achados salvos\n`));

  const { startDaemon } = await import('./src/daemon/sentinela-daemon.mjs');
  await startDaemon(meta.target, { ...meta.options, sessionId });
}

// ── Comando: report ───────────────────────────────────────────

async function cmdReport(sessionId) {
  const store = await import('./src/daemon/session-store.mjs');

  let targetId = sessionId;
  if (!targetId) {
    const active = store.findActiveSession();
    if (active) targetId = active.id;
    else {
      // Mais recente concluída (listSessions vem ordenado do mais novo p/ o mais antigo)
      const all = store.listSessions().filter(s => s.status === 'DONE' || s.status === 'CANCELLED');
      if (all.length === 0) {
        emit({ ok: false, command: 'report', error: 'no_session' }, () =>
          console.log(chalk.yellow('\n⚠️  Nenhuma sessão encontrada.\n')));
        process.exit(EXIT.NO_SESSION);
      }
      targetId = all[0].id;
    }
  }

  if (!store.loadSession(targetId)) {
    emit({ ok: false, command: 'report', error: 'session_not_found', session: targetId }, () =>
      console.error(chalk.red(`❌ Sessão ${targetId} não encontrada no disco.`)));
    process.exit(EXIT.NO_SESSION);
  }

  if (!jsonMode) console.log(chalk.cyan(`\n📝 Gerando relatório para sessão ${targetId}...`));

  // Gera de verdade a partir do que já está em disco — sem reabrir o browser e
  // sem exigir humano. É o caminho principal para automação/IA.
  const { generateFromSession } = await import('./src/daemon/sentinela-daemon.mjs');
  const paths = await generateFromSession(targetId);
  store.markDone(targetId, paths);

  const counts = paths.counts || {};
  emit({
    ok: true,
    command: 'report',
    session: targetId,
    score: paths.scoreBreakdown?.totalScore ?? null,
    grade: paths.scoreBreakdown?.grade ?? null,
    counts,
    reports: {
      html: paths.htmlPath, md: paths.mdPath, json: paths.jsonPath,
      pdf: paths.pdfPath, summary: paths.summaryPath,
    },
  }, () => {
    console.log(chalk.green(`\n✅ Relatório gerado:`));
    console.log(`   🌐 ${paths.htmlPath}`);
    console.log(`   📄 ${paths.mdPath}`);
    console.log(`   📁 ${paths.jsonPath}`);
    if (paths.summaryPath) console.log(chalk.gray(`   🤖 ${paths.summaryPath}  (resumo enxuto p/ IA)`));
    console.log('');
  });

  process.exit(exitCodeFor(counts));
}

// ── Comando: cancel ───────────────────────────────────────────

async function cmdCancel() {
  const { findActiveSession, markCancelled } = await import('./src/daemon/session-store.mjs');
  const active = findActiveSession();
  if (!active) {
    emit({ ok: false, command: 'cancel', error: 'no_session' }, () =>
      console.log(chalk.yellow('\n⚠️  Nenhuma sessão ativa.\n')));
    process.exit(EXIT.NO_SESSION);
  }
  markCancelled(active.id);
  emit({ ok: true, command: 'cancel', session: active.id }, () =>
    console.log(chalk.yellow(`\n🚫 Sessão ${active.id} marcada como CANCELADA.\n`)));
}

// ── Dispatcher ────────────────────────────────────────────────

(async () => {
  try {
    switch (command) {
      case 'start':
        await cmdStart(param);
        break;
      case 'done':
      case 'finalize':
        await cmdDone();
        break;
      case 'status':
        await cmdStatus();
        break;
      case 'sessions':
      case 'list':
        await cmdSessions();
        break;
      case 'resume':
        if (!param) { console.error(chalk.red('❌ Informe o session-id: node sentinela.mjs resume <id>')); process.exit(1); }
        await cmdResume(param);
        break;
      case 'report':
        await cmdReport(param);
        break;
      case 'cancel':
        await cmdCancel();
        break;
      case 'help':
      default:
        printHelp();
    }
  } catch (err) {
    emit({ ok: false, command, error: 'exception', message: err.message }, () => {
      console.error(chalk.red(`\n❌ Erro: ${err.message}`));
      if (process.env.DEBUG) console.error(err.stack);
    });
    process.exit(EXIT.ERROR);
  }
})();
