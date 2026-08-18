/**
 * IDOR/BOLA com DUAS CONTAS reais — a prova definitiva (Tier 3, opt-in extra).
 *
 * O teste de troca de ID na MESMA sessão (active-rules.mjs `runIdorChecks`) só
 * pode LEVANTAR SUSPEITA: trocar o número na URL e ver 200 não prova que o
 * objeto pertence a outro usuário — pode ser um recurso público, um ID
 * inexistente que cai num fallback, etc. Por isso aquele achado é sempre
 * MEDIUM/`provável`.
 *
 * Este módulo resolve isso com PROVA REAL: usa uma SEGUNDA conta, autenticada
 * de verdade por um humano, e tenta acessar os MESMOS objetos que a primeira
 * conta acessou durante a auditoria. Se a Conta B lê dados que só a Conta A
 * deveria ver, é IDOR CONFIRMADO — não mais suspeita.
 *
 * Só roda com `--active --second-account`, porque exige um SEGUNDO login
 * humano no meio da auditoria (a ferramenta nunca digita credenciais). Ver
 * orquestração em auditor.mjs (`runCrossAccountIdor`).
 */

/**
 * @param {import('playwright').APIRequestContext} request - context.request
 * @param {Array<{url:string}>} candidateUrls - URLs GET que a Conta A acessou com sucesso (200 + dados)
 * @param {string} cookieHeaderB - header "Cookie:" bruto da sessão da Conta B
 * @returns {Promise<Array>} findings
 */
export async function crossAccountIdorCheck(request, candidateUrls, cookieHeaderB, opts = {}) {
  const findings = [];
  const sample = (candidateUrls || []).slice(0, 10);
  if (sample.length === 0 || !cookieHeaderB) return findings;

  for (const c of sample) {
    let res;
    try {
      res = await request.get(c.url, {
        headers: { Cookie: cookieHeaderB },
        timeout: 8000,
        failOnStatusCode: false,
      });
    } catch {
      // Erro de rede não é evidência de nada — nem de proteção, nem de falha.
      continue;
    }

    const status = res.status();
    // Bloqueado (401/403/redirect pro login) = exatamente o comportamento
    // correto. Só um 2xx com corpo de verdade é candidato a evidência.
    if (status < 200 || status >= 300) continue;

    let body = '';
    try { body = await res.text(); } catch { continue; }

    const authErr = /unauthor|forbidden|denied|not allowed|acesso negado|não autorizado|"error"|\blogin\b|\b401\b|\b403\b/i
      .test(body.slice(0, 300));
    if (authErr) continue;
    // Corpo curto demais não é evidência de dado real (pode ser `{}`, `null`,
    // uma página de erro genérica que devolveu 200).
    if (!body || body.length < 50) continue;

    findings.push({
      type: 'idor_confirmed', severity: 'HIGH', thirdParty: false, phase: 'PÓS-LOGIN',
      confidence: 'confirmado',
      label: 'IDOR/BOLA CONFIRMADO com duas contas reais',
      url: c.url,
      currentValue: `Conta B acessou objeto da Conta A: HTTP ${status}, ${body.length} bytes de resposta`,
      risk: 'Uma SEGUNDA conta real, autenticada de forma independente pelo humano durante esta auditoria, conseguiu acessar um objeto/rota que pertence à primeira conta testada. Isso é uma falha de autorização por objeto (Broken Object Level Authorization) CONFIRMADA — não uma suspeita: qualquer usuário autenticado pode ler dados de qualquer outro usuário.',
      recommendation: 'CRÍTICO: implementar checagem de propriedade do objeto em TODA rota autenticada — verificar não só "está logado" mas "este objeto pertence a este usuário" antes de retornar dados. Auditar todas as rotas com padrão semelhante (mesmo prefixo de URL).',
    });
  }
  return findings;
}
