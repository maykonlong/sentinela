/**
 * Session Store — Persistência contínua de sessões de auditoria
 *
 * Usa NDJSON append-only para garantir que cada finding seja
 * gravado no disco imediatamente — sem perda em caso de crash.
 *
 * Estrutura de diretórios:
 *   sessions/<session-id>/
 *     meta.json          — target, status, timestamps, contadores
 *     findings.ndjson    — 1 finding por linha (append-only)
 *     routes.ndjson      — 1 rota por linha (append-only)
 *     timeline.ndjson    — eventos da sessão (append-only)
 *     infra.json         — dados de infraestrutura (GeoIP, TCP, timing)
 *     screenshots/       — PNGs individuais por página
 */

import {
  mkdirSync, writeFileSync, appendFileSync, readFileSync,
  existsSync, readdirSync, renameSync,
} from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SESSIONS_DIR = join(__dirname, '..', '..', 'sessions');

function ensureDir(dir) {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}

function sessionDir(sessionId) {
  return join(SESSIONS_DIR, sessionId);
}

// ── Criar sessão ──────────────────────────────────────────────

/**
 * Cria uma nova sessão de auditoria no disco.
 * @param {string} target - URL alvo
 * @param {object} options - Opções (scope, activeMode, timeout, etc.)
 * @returns {string} sessionId gerado
 */
export function createSession(target, options = {}) {
  ensureDir(SESSIONS_DIR);

  const id = `sess-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
  const dir = sessionDir(id);
  mkdirSync(join(dir, 'screenshots'), { recursive: true });

  const meta = {
    id,
    target,
    status: 'IN_PROGRESS',
    startedAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    options,
    findingsCount: 0,
    routesCount: 0,
    pagesCount: 0,
    timelineCount: 0,
    lastUrl: target,
  };

  writeFileSync(join(dir, 'meta.json'), JSON.stringify(meta, null, 2), 'utf8');

  return id;
}

// ── Leitura de meta ───────────────────────────────────────────

export function getSessionMeta(sessionId) {
  const path = join(sessionDir(sessionId), 'meta.json');
  if (!existsSync(path)) return null;
  try { return JSON.parse(readFileSync(path, 'utf8')); } catch { return null; }
}

function updateMeta(sessionId, patch) {
  const path = join(sessionDir(sessionId), 'meta.json');
  try {
    const meta = JSON.parse(readFileSync(path, 'utf8'));
    Object.assign(meta, patch, { updatedAt: new Date().toISOString() });
    writeFileSync(path, JSON.stringify(meta, null, 2), 'utf8');
    return meta;
  } catch { return null; }
}

// ── Append atômico ────────────────────────────────────────────

/**
 * Grava um finding no disco imediatamente (append-only).
 * Thread-safe via sincronização (Node.js é single-threaded).
 */
export function appendFinding(sessionId, finding) {
  try {
    appendFileSync(
      join(sessionDir(sessionId), 'findings.ndjson'),
      JSON.stringify(finding) + '\n',
      'utf8'
    );
    updateMeta(sessionId, { findingsCount: (getSessionMeta(sessionId)?.findingsCount || 0) + 1 });
  } catch { /* disco cheio ou diretório removido — ignorar */ }
}

/**
 * Grava uma rota capturada no disco imediatamente.
 */
export function appendRoute(sessionId, route) {
  try {
    appendFileSync(
      join(sessionDir(sessionId), 'routes.ndjson'),
      JSON.stringify(route) + '\n',
      'utf8'
    );
    updateMeta(sessionId, { routesCount: (getSessionMeta(sessionId)?.routesCount || 0) + 1 });
  } catch { /* ignorar */ }
}

/**
 * Grava um evento na timeline da sessão.
 */
export function appendTimeline(sessionId, text, type = 'info') {
  try {
    const event = { time: new Date().toLocaleTimeString('pt-BR'), text, type };
    appendFileSync(
      join(sessionDir(sessionId), 'timeline.ndjson'),
      JSON.stringify(event) + '\n',
      'utf8'
    );
    updateMeta(sessionId, { timelineCount: (getSessionMeta(sessionId)?.timelineCount || 0) + 1 });
  } catch { /* ignorar */ }
}

/**
 * Salva um screenshot PNG no disco.
 */
export function saveScreenshot(sessionId, url, buffer) {
  try {
    const safe = url.replace(/[^a-zA-Z0-9]/g, '_').slice(0, 80);
    const filename = `${Date.now()}-${safe}.png`;
    writeFileSync(join(sessionDir(sessionId), 'screenshots', filename), buffer);
    updateMeta(sessionId, {
      pagesCount: (getSessionMeta(sessionId)?.pagesCount || 0) + 1,
      lastUrl: url,
    });
  } catch { /* ignorar */ }
}

/**
 * Salva dados de infraestrutura (GeoIP, TCP, timing).
 */
export function saveInfra(sessionId, infraData) {
  try {
    writeFileSync(
      join(sessionDir(sessionId), 'infra.json'),
      JSON.stringify(infraData, null, 2),
      'utf8'
    );
  } catch { /* ignorar */ }
}

// ── Leitura e reconstrução ────────────────────────────────────

/**
 * Lê todos os findings de uma sessão do disco.
 */
export function loadFindings(sessionId) {
  const path = join(sessionDir(sessionId), 'findings.ndjson');
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map(line => { try { return JSON.parse(line); } catch { return null; } })
    .filter(Boolean);
}

/**
 * Lê todas as rotas de uma sessão do disco.
 */
export function loadRoutes(sessionId) {
  const path = join(sessionDir(sessionId), 'routes.ndjson');
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map(line => { try { return JSON.parse(line); } catch { return null; } })
    .filter(Boolean);
}

/**
 * Lê a timeline de uma sessão do disco.
 */
export function loadTimeline(sessionId) {
  const path = join(sessionDir(sessionId), 'timeline.ndjson');
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map(line => { try { return JSON.parse(line); } catch { return null; } })
    .filter(Boolean);
}

/**
 * Lê screenshots de uma sessão (retorna lista de paths absolutos).
 */
export function loadScreenshots(sessionId) {
  const dir = join(sessionDir(sessionId), 'screenshots');
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter(f => f.endsWith('.png'))
    .sort()
    .map(f => join(dir, f));
}

/**
 * Carrega dados de infra de uma sessão.
 */
export function loadInfra(sessionId) {
  const path = join(sessionDir(sessionId), 'infra.json');
  if (!existsSync(path)) return null;
  try { return JSON.parse(readFileSync(path, 'utf8')); } catch { return null; }
}

/**
 * Reconstrói todo o estado de uma sessão a partir do disco.
 */
export function loadSession(sessionId) {
  const meta = getSessionMeta(sessionId);
  if (!meta) return null;
  return {
    meta,
    findings: loadFindings(sessionId),
    routes: loadRoutes(sessionId),
    timeline: loadTimeline(sessionId),
    screenshotPaths: loadScreenshots(sessionId),
    infra: loadInfra(sessionId),
  };
}

// ── Gerenciamento de sessões ──────────────────────────────────

/**
 * Lista todas as sessões existentes, ordenadas por data (mais recente primeiro).
 */
export function listSessions() {
  ensureDir(SESSIONS_DIR);
  return readdirSync(SESSIONS_DIR)
    .filter(name => name.startsWith('sess-'))
    .map(name => getSessionMeta(name))
    .filter(Boolean)
    .sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt));
}

/**
 * Retorna a sessão IN_PROGRESS mais recente (se existir).
 */
export function findActiveSession() {
  return listSessions().find(s => s.status === 'IN_PROGRESS') || null;
}

/**
 * Marca a sessão como DONE (relatório já gerado).
 */
export function markDone(sessionId, reportPaths = {}) {
  updateMeta(sessionId, {
    status: 'DONE',
    finishedAt: new Date().toISOString(),
    reportPaths,
  });
}

/**
 * Marca a sessão como CANCELLED.
 */
export function markCancelled(sessionId) {
  updateMeta(sessionId, { status: 'CANCELLED', finishedAt: new Date().toISOString() });
}

/**
 * Arquiva a sessão (move para sessions/archived/).
 */
export function archiveSession(sessionId) {
  const src = sessionDir(sessionId);
  const archiveDir = join(SESSIONS_DIR, 'archived');
  ensureDir(archiveDir);
  try { renameSync(src, join(archiveDir, sessionId)); } catch { /* ignorar */ }
}

/**
 * Sinaliza finalização via arquivo sentinela (compatível com WSL/outros terminais).
 * O daemon faz polling e encerra ao detectar este arquivo.
 */
export function signalFinalize(sessionId) {
  const path = join(sessionDir(sessionId), '.finalize');
  writeFileSync(path, new Date().toISOString(), 'utf8');
}

/**
 * Verifica se o sinal de finalização foi dado.
 */
export function isFinalizeSigned(sessionId) {
  return existsSync(join(sessionDir(sessionId), '.finalize'));
}

/**
 * Remove o arquivo de sinal de finalização.
 */
export function clearFinalizeSignal(sessionId) {
  const path = join(sessionDir(sessionId), '.finalize');
  if (existsSync(path)) {
    try { import('fs').then(fs => fs.unlinkSync(path)); } catch { /* ok */ }
  }
}
