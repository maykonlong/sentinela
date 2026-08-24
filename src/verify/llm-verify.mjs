/**
 * Verificação adversarial por LLM (opt-in) — a "revisão por IA" no estilo blindar.
 *
 * Para cada achado, pede a um modelo que TENTE REFUTÁ-LO (é real e explorável, ou
 * é provável falso-positivo?) e devolva um veredito estruturado. O resultado
 * ANOTA o achado (`llm: {...}`) — nunca apaga: um "refutado" fica marcado, não some.
 *
 * Princípio de ouro do projeto: ausência de evidência não é evidência.
 *   - Sem ANTHROPIC_API_KEY  → NÃO roda, marca tudo como `verified:false` +
 *     nota "sem API key". Jamais inventa um "confirmado".
 *   - Erro de rede/parse num achado → aquele achado fica `verified:false`, sem
 *     alterar severidade. O silêncio da IA nunca vira aprovação nem reprovação.
 *
 * Zero-deps: usa fetch nativo contra a Messages API da Anthropic. Modelo padrão
 * Haiku (tier de triagem, barato); override por SENTINELA_LLM_MODEL.
 */

const API_URL = 'https://api.anthropic.com/v1/messages';
const DEFAULT_MODEL = 'claude-haiku-4-5-20251001'; // triagem barata; suba via env se precisar
const MAX_FINDINGS = 40; // teto de custo por execução

/** Monta o prompt de refutação para UM achado. Exportado para teste. */
export function buildRefutePrompt(f) {
  const campos = [
    `tipo: ${f.type}`,
    `severidade_atual: ${f.severity}`,
    `titulo: ${f.label || ''}`,
    f.url ? `url: ${String(f.url).replace(/\s.*$/, '')}` : null,
    f.currentValue ? `evidencia: ${String(f.currentValue).slice(0, 400)}` : null,
    f.risk ? `risco: ${String(f.risk).slice(0, 400)}` : null,
    f.owasp ? `owasp: ${f.owasp}` : null,
  ].filter(Boolean).join('\n');

  return [
    'Você é um revisor de segurança adversarial. Sua tarefa é TENTAR REFUTAR o achado abaixo,',
    'produzido por um scanner automático. Decida se ele é uma vulnerabilidade REAL e explorável',
    'ou um provável FALSO-POSITIVO. Na dúvida, seja cético, mas não descarte evidência concreta',
    '(ex.: mensagem de erro de banco real indica SQLi real).',
    '',
    'ACHADO:',
    campos,
    '',
    'Responda SOMENTE com um JSON válido, sem texto fora dele, no formato:',
    '{"real": true|false, "confianca": "baixa|media|alta", "severidade_ajustada": "CRITICAL|HIGH|MEDIUM|LOW|INFO", "motivo": "uma frase curta"}',
  ].join('\n');
}

/** Extrai o veredito do texto do modelo. Exportado para teste. Tolera cercas ```json. */
export function parseVerdict(text) {
  if (!text) return null;
  const m = String(text).match(/\{[\s\S]*\}/);
  if (!m) return null;
  let o;
  try { o = JSON.parse(m[0]); } catch { return null; }
  const sev = String(o.severidade_ajustada || '').toUpperCase();
  const validSev = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  return {
    real: o.real === true,
    confianca: ['baixa', 'media', 'alta'].includes(String(o.confianca).toLowerCase()) ? String(o.confianca).toLowerCase() : 'baixa',
    severidadeAjustada: validSev.includes(sev) ? sev : null,
    motivo: typeof o.motivo === 'string' ? o.motivo.slice(0, 300) : '',
  };
}

/** Uma chamada à Messages API. Injetável (fetchImpl) para teste. */
async function callModel(prompt, { apiKey, model, fetchImpl, timeoutMs = 20000 }) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await (fetchImpl || fetch)(API_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model, max_tokens: 300, messages: [{ role: 'user', content: prompt }] }),
      signal: ctrl.signal,
    });
    if (!res.ok) return null;
    const data = await res.json();
    const text = Array.isArray(data.content) ? (data.content.find(c => c.type === 'text')?.text || '') : '';
    return parseVerdict(text);
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

/**
 * Anota cada achado com `llm`. Não muta a lista original.
 * @returns {{findings: object[], summary: {ran:boolean, model?:string, confirmados:number, refutados:number, naoVerificados:number, motivo?:string}}}
 */
export async function verifyFindingsWithLlm(findings, opts = {}) {
  const apiKey = opts.apiKey || process.env.ANTHROPIC_API_KEY;
  const model = opts.model || process.env.SENTINELA_LLM_MODEL || DEFAULT_MODEL;
  const list = Array.isArray(findings) ? findings : [];

  // Sem API key → não roda. Marca honestamente e devolve.
  if (!apiKey) {
    return {
      findings: list.map(f => ({ ...f, llm: { verified: false, note: 'não verificado por IA (sem ANTHROPIC_API_KEY)' } })),
      summary: { ran: false, confirmados: 0, refutados: 0, naoVerificados: list.length, motivo: 'ANTHROPIC_API_KEY ausente' },
    };
  }

  const targets = list.slice(0, MAX_FINDINGS);
  const rest = list.slice(MAX_FINDINGS);
  let confirmados = 0, refutados = 0, naoVerificados = 0;

  const verified = [];
  for (const f of targets) {
    const verdict = await callModel(buildRefutePrompt(f), { apiKey, model, fetchImpl: opts.fetchImpl });
    if (!verdict) {
      naoVerificados++;
      verified.push({ ...f, llm: { verified: false, note: 'IA não respondeu (erro/timeout) — mantido sem alteração' } });
      continue;
    }
    if (verdict.real) confirmados++; else refutados++;
    verified.push({
      ...f,
      llm: {
        verified: true,
        real: verdict.real,
        confianca: verdict.confianca,
        severidadeSugerida: verdict.severidadeAjustada,
        motivo: verdict.motivo,
      },
    });
  }
  // Os que passaram do teto ficam explicitamente não-verificados.
  for (const f of rest) {
    naoVerificados++;
    verified.push({ ...f, llm: { verified: false, note: `acima do teto de ${MAX_FINDINGS} achados por execução` } });
  }

  return { findings: verified, summary: { ran: true, model, confirmados, refutados, naoVerificados } };
}
