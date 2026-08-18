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
const getFlag = (f) => { const i = args.indexOf(f); return i !== -1 && args[i + 1] ? args[i + 1] : null; };

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
  ${chalk.yellow('--active')}         Modo ativo (IDOR, redirect, arquivos sensíveis)
  ${chalk.yellow('--crawl')}          Crawl automático de links internos
  ${chalk.yellow('--login-only')}     Auditar só a página de login
  ${chalk.yellow('--timeout 60')}     Timeout em minutos (padrão: 60)

${chalk.white.bold('EXEMPLOS:')}
  node sentinela.mjs start https://meusite.com
  node sentinela.mjs start https://10.4.0.20:8443/login --active --timeout 30
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
  const timeoutMin = parseInt(getFlag('--timeout') || '60', 10);
  const timeoutMs = timeoutMin * 60 * 1000;

  printBanner();
  console.log(chalk.white(`\n🎯 Alvo: ${chalk.cyan.bold(targetUrl)}`));
  console.log(chalk.white(`📂 Escopo: ${scope}${activeMode ? chalk.magenta(' + ATIVO') : ''}`));
  console.log(chalk.white(`⏱️  Timeout: ${timeoutMin} minutos`));
  console.log(chalk.gray('\n  → Controle ao vivo: http://localhost:3141'));
  console.log(chalk.gray('  → Finalizar: node sentinela.mjs done'));
  console.log(chalk.gray('  → Ou: curl -X POST http://localhost:3141/finalize\n'));

  const { startDaemon } = await import('./src/daemon/sentinela-daemon.mjs');
  await startDaemon(targetUrl, { scope, activeMode, timeoutMs });
}

// ── Comando: done ─────────────────────────────────────────────

async function cmdDone() {
  // Primeiro tenta via HTTP (mais rápido se daemon estiver rodando)
  try {
    const res = await fetch('http://localhost:3141/finalize', { method: 'POST', signal: AbortSignal.timeout(2000) });
    if (res.ok) {
      console.log(chalk.green('✅ Sinal de finalização enviado via HTTP. O relatório será gerado em instantes.'));
      return;
    }
  } catch { /* daemon não está rodando em HTTP */ }

  // Fallback: criar arquivo .finalize na sessão ativa
  const { findActiveSession, signalFinalize } = await import('./src/daemon/session-store.mjs');
  const active = findActiveSession();
  if (!active) {
    console.log(chalk.yellow('⚠️  Nenhuma sessão ativa encontrada.'));
    console.log(chalk.gray('  Use: node sentinela.mjs sessions — para ver todas as sessões'));
    return;
  }

  signalFinalize(active.id);
  console.log(chalk.green(`✅ Arquivo .finalize criado para sessão ${active.id}`));
  console.log(chalk.gray('  O daemon irá detectar e finalizar em até 2 segundos.'));
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
        console.log(chalk.cyan.bold('\n🛡️  Sentinela — Sessão Ativa (via HTTP)\n'));
        console.log(`  Sessão:   ${meta.id}`);
        console.log(`  Alvo:     ${meta.target}`);
        console.log(`  Status:   ${meta.status}`);
        console.log(`  Duração:  ${Math.floor(elapsed / 60)}m ${elapsed % 60}s`);
        console.log(`  Achados:  ${meta.findingsCount}`);
        console.log(`  Rotas:    ${meta.routesCount}`);
        console.log(`  Controle: http://localhost:3141\n`);
        return;
      }
    }
  } catch { /* daemon não rodando */ }

  // Fallback: ler do disco
  const { findActiveSession } = await import('./src/daemon/session-store.mjs');
  const active = findActiveSession();
  if (!active) {
    console.log(chalk.yellow('\n⚠️  Nenhuma sessão ativa no momento.\n'));
    return;
  }
  console.log(chalk.cyan.bold('\n🛡️  Sentinela — Última sessão ativa (disco)\n'));
  console.log(`  Sessão:  ${active.id}`);
  console.log(`  Alvo:    ${active.target}`);
  console.log(`  Status:  ${active.status}`);
  console.log(`  Achados: ${active.findingsCount}`);
  console.log(`  Rotas:   ${active.routesCount}\n`);
}

// ── Comando: sessions ─────────────────────────────────────────

async function cmdSessions() {
  const { listSessions } = await import('./src/daemon/session-store.mjs');
  const sessions = listSessions();

  if (sessions.length === 0) {
    console.log(chalk.yellow('\n  Nenhuma sessão encontrada.\n'));
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
  const { listSessions, findActiveSession, loadSession } = await import('./src/daemon/session-store.mjs');

  let targetId = sessionId;
  if (!targetId) {
    const active = findActiveSession();
    if (active) targetId = active.id;
    else {
      const all = listSessions().filter(s => s.status === 'DONE');
      if (all.length === 0) { console.log(chalk.yellow('\n⚠️  Nenhuma sessão encontrada.\n')); return; }
      targetId = all[0].id; // Mais recente DONE
    }
  }

  console.log(chalk.cyan(`\n📝 Gerando relatório para sessão ${targetId}...`));
  const { generateFromSession: gen } = await import('./src/daemon/sentinela-daemon.mjs');

  // Usar função interna do daemon
  const { startDaemon: _, generateFromSession } = await import('./src/daemon/sentinela-daemon.mjs');
  // fallback: importar diretamente
  const store = await import('./src/daemon/session-store.mjs');
  const session = store.loadSession(targetId);
  if (!session) { console.error(chalk.red('❌ Sessão não encontrada no disco.')); return; }

  console.log(chalk.green(`\n✅ Use: node sentinela.mjs resume ${targetId}`));
  console.log(chalk.gray('   Para gerar relatório da sessão salva.\n'));
}

// ── Comando: cancel ───────────────────────────────────────────

async function cmdCancel() {
  const { findActiveSession, markCancelled } = await import('./src/daemon/session-store.mjs');
  const active = findActiveSession();
  if (!active) { console.log(chalk.yellow('\n⚠️  Nenhuma sessão ativa.\n')); return; }
  markCancelled(active.id);
  console.log(chalk.yellow(`\n🚫 Sessão ${active.id} marcada como CANCELADA.\n`));
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
    console.error(chalk.red(`\n❌ Erro: ${err.message}`));
    if (process.env.DEBUG) console.error(err.stack);
    process.exit(1);
  }
})();
