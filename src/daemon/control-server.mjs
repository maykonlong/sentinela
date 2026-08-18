/**
 * Control Server — HTTP local na porta 3141
 *
 * Interface de controle da sessão de auditoria.
 * Usa apenas http nativo do Node.js (zero dependências extras).
 *
 * Endpoints:
 *   GET  /           → UI HTML ao vivo (auto-refresh a cada 3s)
 *   GET  /status     → JSON com estado atual da sessão
 *   GET  /findings   → SSE stream de findings em tempo real
 *   POST /finalize   → Encerrar sessão e gerar relatório
 *   POST /screenshot → Solicitar screenshot manual
 *   GET  /report     → Redirect para o HTML gerado
 *   GET  /health     → health check simples
 */

import { createServer } from 'http';
import { readFileSync, existsSync } from 'fs';
import { EventEmitter } from 'events';

export const controlEvents = new EventEmitter();
controlEvents.setMaxListeners(50);

const PORT = 3141;

function json(res, data, code = 200) {
  res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(JSON.stringify(data));
}

function html(res, body) {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(body);
}

function buildStatusPage(state) {
  const { meta, findings = [] } = state;
  const elapsed = meta ? Math.round((Date.now() - new Date(meta.startedAt).getTime()) / 1000) : 0;
  const mins = String(Math.floor(elapsed / 60)).padStart(2, '0');
  const secs = String(elapsed % 60).padStart(2, '0');

  const sevCount = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  findings.filter(f => !f.thirdParty).forEach(f => { sevCount[f.severity] = (sevCount[f.severity] || 0) + 1; });

  const statusColor = meta?.status === 'IN_PROGRESS' ? '#2f9e44' : meta?.status === 'DONE' ? '#1c7ed6' : '#c92a2a';
  const statusLabel = meta?.status === 'IN_PROGRESS' ? '🟢 EM ANDAMENTO' : meta?.status === 'DONE' ? '✅ CONCLUÍDA' : meta?.status || '?';

  const reportLink = meta?.reportPaths?.html
    ? `<a href="file:///${meta.reportPaths.html.replace(/\\/g, '/')}" target="_blank" style="color:#1c7ed6;margin-left:12px">📄 Abrir Relatório</a>`
    : '';

  const findingRows = findings.slice(-20).reverse().map(f => {
    const color = { CRITICAL: '#c92a2a', HIGH: '#e8590c', MEDIUM: '#f08c00', LOW: '#1c7ed6', INFO: '#868e96' };
    return `<tr>
      <td><span style="background:${color[f.severity]||'#868e96'};color:#fff;padding:1px 7px;border-radius:10px;font-size:11px">${f.severity}</span></td>
      <td style="font-size:12px">${(f.label || f.type || '').slice(0, 80)}</td>
      <td style="font-size:11px;color:#868e96">${f.phase || ''}</td>
    </tr>`;
  }).join('');

  return `<!doctype html><html lang="pt-BR"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>🛡️ Sentinela — Sessão Ativa</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:Inter,sans-serif;background:#0f1117;color:#c9d1d9;padding:24px;min-height:100vh}
  .wrap{max-width:800px;margin:0 auto}
  h1{font-size:20px;margin-bottom:4px;color:#fff}
  .sub{font-size:13px;color:#868e96;margin-bottom:20px}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:20px}
  .card{background:#161b22;border-radius:10px;padding:14px;text-align:center;border:1px solid #21262d}
  .card .n{font-size:28px;font-weight:700}
  .card .l{font-size:11px;color:#868e96;margin-top:3px}
  .status{background:#161b22;border-radius:10px;padding:16px;margin-bottom:16px;border:1px solid #21262d}
  .status .row{display:flex;justify-content:space-between;margin:4px 0;font-size:13px}
  .status .key{color:#868e96}
  table{width:100%;border-collapse:collapse;font-size:12px;background:#161b22;border-radius:10px;overflow:hidden;border:1px solid #21262d}
  th,td{padding:8px 10px;border-bottom:1px solid #21262d;text-align:left}
  th{color:#868e96;font-size:11px;text-transform:uppercase}
  .actions{display:flex;gap:12px;margin:16px 0;flex-wrap:wrap}
  .btn{padding:10px 20px;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;border:none;text-decoration:none}
  .btn-red{background:#c92a2a;color:#fff}
  .btn-red:hover{background:#a61e1e}
  .btn-gray{background:#21262d;color:#c9d1d9}
  .btn-gray:hover{background:#30363d}
  .badge{padding:2px 10px;border-radius:20px;font-size:11px;font-weight:700}
</style>
<meta http-equiv="refresh" content="4">
</head><body><div class="wrap">
  <h1>🛡️ Sentinela</h1>
  <div class="sub">Sessão: ${meta?.id || '?'} &nbsp;|&nbsp; <span style="color:${statusColor}">${statusLabel}</span> ${reportLink}</div>

  <div class="status">
    <div class="row"><span class="key">Alvo</span><span>${meta?.target || '?'}</span></div>
    <div class="row"><span class="key">Iniciado</span><span>${meta?.startedAt ? new Date(meta.startedAt).toLocaleString('pt-BR') : '?'}</span></div>
    <div class="row"><span class="key">Duração</span><span>${mins}:${secs}</span></div>
    <div class="row"><span class="key">Última URL</span><span style="word-break:break-all">${meta?.lastUrl || '?'}</span></div>
    <div class="row"><span class="key">Páginas</span><span>${meta?.pagesCount || 0}</span></div>
  </div>

  <div class="cards">
    <div class="card"><div class="n" style="color:#c92a2a">${sevCount.CRITICAL}</div><div class="l">🔴 CRITICAL</div></div>
    <div class="card"><div class="n" style="color:#e8590c">${sevCount.HIGH}</div><div class="l">🟠 HIGH</div></div>
    <div class="card"><div class="n" style="color:#f08c00">${sevCount.MEDIUM}</div><div class="l">🟡 MEDIUM</div></div>
    <div class="card"><div class="n" style="color:#1c7ed6">${sevCount.LOW}</div><div class="l">🔵 LOW</div></div>
    <div class="card"><div class="n" style="color:#fff">${meta?.routesCount || 0}</div><div class="l">📡 Rotas</div></div>
  </div>

  ${meta?.status === 'IN_PROGRESS' ? `<div class="actions">
    <button class="btn btn-red" onclick="finalize()">🔴 Finalizar e Gerar Relatório</button>
    <button class="btn btn-gray" onclick="screenshot()">📸 Capturar Screenshot</button>
  </div>` : `<div style="color:#2f9e44;font-size:14px;margin-bottom:16px">✅ Sessão finalizada. ${reportLink}</div>`}

  ${findingRows ? `<h3 style="font-size:14px;margin-bottom:8px;color:#c9d1d9">Últimos achados</h3>
  <table><thead><tr><th>Severidade</th><th>Achado</th><th>Fase</th></tr></thead><tbody>${findingRows}</tbody></table>` : ''}

  <script>
    async function finalize(){
      if(!confirm('Finalizar a sessão e gerar o relatório?')) return;
      await fetch('/finalize',{method:'POST'});
      location.reload();
    }
    async function screenshot(){
      await fetch('/screenshot',{method:'POST'});
      alert('Screenshot solicitado!');
    }
  </script>
</div></body></html>`;
}

let _state = { meta: null, findings: [], sessionId: null, finalizeCallback: null, screenshotCallback: null };
let _reportPath = null;

/** Atualiza o estado interno do servidor com os dados mais recentes. */
export function updateServerState(state) {
  Object.assign(_state, state);
}

/** Define o path do relatório gerado (para o link na UI). */
export function setReportPath(htmlPath) {
  _reportPath = htmlPath;
}

/**
 * Inicia o servidor HTTP de controle na porta 3141.
 * @param {Function} onFinalize - Callback chamado quando /finalize é requisitado
 * @param {Function} onScreenshot - Callback chamado quando /screenshot é requisitado
 * @returns {object} servidor http
 */
export function startControlServer(onFinalize, onScreenshot) {
  _state.finalizeCallback = onFinalize;
  _state.screenshotCallback = onScreenshot;

  const server = createServer(async (req, res) => {
    const url = new URL(req.url, `http://localhost:${PORT}`);
    const path = url.pathname;

    // ── CORS ──
    res.setHeader('Access-Control-Allow-Origin', '127.0.0.1');
    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

    // ── Health check ──
    if (path === '/health') {
      json(res, { ok: true, sessionId: _state.sessionId });
      return;
    }

    // ── Status JSON ──
    if (path === '/status' && req.method === 'GET') {
      json(res, {
        sessionId: _state.sessionId,
        meta: _state.meta,
        findingsCount: _state.findings.length,
        reportPath: _reportPath,
      });
      return;
    }

    // ── UI HTML ──
    if (path === '/' && req.method === 'GET') {
      html(res, buildStatusPage(_state));
      return;
    }

    // ── SSE: findings em tempo real ──
    if (path === '/findings' && req.method === 'GET') {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
      });
      // Enviar todos os findings atuais
      _state.findings.forEach(f => res.write(`data: ${JSON.stringify(f)}\n\n`));
      // Escutar novos findings
      const onNew = (f) => res.write(`data: ${JSON.stringify(f)}\n\n`);
      controlEvents.on('finding', onNew);
      req.on('close', () => controlEvents.off('finding', onNew));
      return;
    }

    // ── Finalizar ──
    if (path === '/finalize' && req.method === 'POST') {
      json(res, { ok: true, message: 'Finalizando sessão...' });
      if (_state.finalizeCallback) setImmediate(_state.finalizeCallback);
      return;
    }

    // ── Screenshot ──
    if (path === '/screenshot' && req.method === 'POST') {
      json(res, { ok: true, message: 'Screenshot solicitado.' });
      if (_state.screenshotCallback) setImmediate(_state.screenshotCallback);
      return;
    }

    // ── Redirect para relatório ──
    if (path === '/report' && req.method === 'GET') {
      if (_reportPath) {
        res.writeHead(302, { Location: `file:///${_reportPath.replace(/\\/g, '/')}` });
        res.end();
      } else {
        json(res, { error: 'Relatório ainda não gerado.' }, 404);
      }
      return;
    }

    // ── 404 ──
    json(res, { error: 'Not found' }, 404);
  });

  server.listen(PORT, '127.0.0.1', () => {
    // Servidor escuta apenas em localhost — não exposto na rede
  });

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.error(`⚠️  Porta ${PORT} já em uso — controle web indisponível.`);
    }
  });

  return server;
}
