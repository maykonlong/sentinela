/**
 * Deduplicação de achados — FONTE ÚNICA para os dois pipelines de relatório.
 *
 * Existem dois caminhos que geram relatório:
 *   1. src/auditor.mjs → generateReport()          (execução ao vivo)
 *   2. src/daemon/sentinela-daemon.mjs → generateFromSession()  (a partir do disco)
 * O caminho (2) NÃO deduplicava, e por isso o mesmo relatório saía com 351
 * achados pelo daemon e 41 pelo auditor — o `findings.ndjson` guarda o fluxo
 * BRUTO (um achado por resposta HTTP), então "Sem COOP" aparecia 27x, uma por
 * URL. Toda contagem, nota e seção do relatório herdava essa inflação.
 * Por isso a lógica vive aqui e é importada pelos dois.
 *
 * A dedup NÃO joga informação fora: `occurrences`/`occurrenceCount` preservam
 * onde cada problema foi visto, para o relatório poder dizer "27 páginas
 * afetadas" sem contar 27 problemas distintos.
 */

/**
 * Chave de deduplicação. Problemas "de site" (headers, cookies, código, storage)
 * são colapsados ENTRE fases — o mesmo header ausente não deve contar 3x
 * (pré-login + login + pós-login). Eventos de rede/diff do login mantêm a fase.
 */
export function dedupKey(f) {
  const t = f.type;
  if (['missing_security_header', 'weak_security_header', 'information_disclosure_header',
       'cors_wildcard', 'cors_credentials', 'no_https'].includes(t)) {
    // Postura por ORIGEM, não por URL: o mesmo header ausente em 27 páginas do
    // mesmo host é UM problema. Mas a origem entra na chave porque o fluxo de
    // login costuma passar por outro host (ex.: Keycloak/IdP) — colapsar os dois
    // atribuiria o achado de um host à URL do outro, que é justamente o que faz
    // o leitor testar a URL errada e concluir "falso positivo".
    return `${t}|${f.header || ''}|${originOf(f.url)}`;
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
  if (t === 'browser_issue') {
    // Issue do painel do DevTools (CSP/CORS/SameSite/deprecação). O navegador
    // emite uma por RECURSO afetado, então a mesma configuração errada de CORS
    // aparecia 5x, uma por URL. É uma configuração só — as URLs afetadas ficam
    // em `occurrences`. A origem entra na chave para não misturar app e IdP.
    return `${t}|${f.code || f.label || ''}|${originOf(f.url)}`;
  }
  // Demais (rede durante login, diffs, inventário): mantém a fase.
  return `${t}|${f.phase || ''}|${f.key || f.cookieName || f.header || f.label || ''}|${f.storage || f.match || f.url || ''}`;
}

function originOf(url) {
  try { return new URL(String(url)).origin; } catch { return ''; }
}

/**
 * Colapsa achados equivalentes, preservando onde cada um foi observado.
 * O achado mantido é o primeiro visto, acrescido de:
 *   - occurrences:     [{ url, phase }] de TODAS as ocorrências (limitado)
 *   - occurrenceCount: total real de ocorrências
 */
export function deduplicateFindings(findings) {
  const byKey = new Map();

  for (const f of findings || []) {
    const key = dedupKey(f);
    const seen = byKey.get(key);

    if (!seen) {
      byKey.set(key, { ...f, occurrences: [{ url: f.url, phase: f.phase }], occurrenceCount: 1 });
      continue;
    }

    seen.occurrenceCount++;
    // Guardar só URLs distintas e com teto — é evidência de alcance, não um log.
    if (seen.occurrences.length < 25 && !seen.occurrences.some(o => o.url === f.url)) {
      seen.occurrences.push({ url: f.url, phase: f.phase });
    }
  }

  return [...byKey.values()];
}
