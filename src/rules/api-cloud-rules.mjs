/**
 * Módulo de Auditoria de APIs, Nuvem e Isolamento — Sentinela Enterprise
 * 
 * 1. GraphQL Introspection Check (/graphql, /api/graphql) — implementação ÚNICA
 *    do projeto (a cópia em recon-rules.mjs foi removida)
 * 2. Inventário de Buckets de Nuvem referenciados (S3, GCS, Azure Blobs) — INFO,
 *    apenas referência encontrada; a permissão do bucket NÃO é testada
 * 3. Segurança de WebSockets (ws:// em contexto HTTPS / sem WSS)
 * 4. [desativado] Isolamento Cross-Origin (COOP/COEP) — duplicava header-rules.mjs
 */

const CLOUD_BUCKET_REGEX = /(?:[a-z0-9.-]+\.s3(?:-[a-z0-9-]+)?\.amazonaws\.com|storage\.googleapis\.com\/[a-z0-9.-]+|[a-z0-9.-]+\.blob\.core\.windows\.net)/gi;

/**
 * Inspeciona GraphQL Introspection em rotas de API.
 *
 * IMPLEMENTAÇÃO ÚNICA do projeto: a checagem também existia em recon-rules.mjs
 * (`/graphql` apenas, MEDIUM) e as duas juntas faziam o MESMO endpoint aparecer
 * DUAS vezes no relatório com severidades divergentes (MEDIUM vs HIGH). Ficou
 * esta (testa 4 endpoints), emitindo o tipo `graphql_introspection`, que é o
 * mapeado em owasp-map.mjs.
 */
export async function checkGraphQlIntrospection(requestContext, originUrl) {
  const findings = [];
  const candidateEndpoints = ['/graphql', '/api/graphql', '/v1/graphql', '/query'];
  const base = new URL(originUrl).origin;

  for (const ep of candidateEndpoints) {
    try {
      const target = `${base}${ep}`;
      const resp = await requestContext.post(target, {
        data: { query: '{ __schema { types { name } } }' },
        headers: { 'Content-Type': 'application/json' },
        timeout: 4000,
      });

      if (resp.status() !== 200) continue;
      const body = await resp.text();

      // EVIDÊNCIA POSITIVA: a resposta precisa ser um schema DE VERDADE.
      // A checagem antiga (`body.includes('__schema') && body.includes('types')`)
      // gerava 2 FPs concretos:
      //   1. resposta de ERRO que ecoa a query enviada, ex.:
      //      {"errors":[{"message":"Syntax error","query":"{ __schema { types { name } } }"}]}
      //      — status 200 e as duas substrings presentes, mas introspection
      //      pode estar DESLIGADA (ou o endpoint nem ser GraphQL).
      //   2. SPA com rota catch-all: POST /graphql devolve 200 com o index.html
      //      do app; se a página tiver a palavra "types" em algum script, casa.
      // Agora exijo estrutura: data.__schema.types tem que ser um array não vazio.
      let json;
      try { json = JSON.parse(body); } catch { continue; }   // não é JSON → não é resposta GraphQL
      const types = json && json.data && json.data.__schema ? json.data.__schema.types : null;
      if (!Array.isArray(types) || types.length === 0) continue;

      findings.push({
        type: 'graphql_introspection',
        // MEDIUM, não HIGH: introspection ligada é information disclosure
        // (entrega o mapa da API), não uma falha explorável por si só.
        severity: 'MEDIUM',
        thirdParty: false,
        phase: 'PRÉ-LOGIN',
        label: `Introspeção GraphQL Ativa em ${ep}`,
        url: target,
        currentValue: `schema retornado com ${types.length} tipo(s)`,
        risk: `O endpoint GraphQL em ${ep} está com Introspeção ativada e devolveu um schema válido com ${types.length} tipos. Atacantes conseguem extrair a estrutura completa de tipos, campos, mutações e relacionamentos expostos pela API.`,
        recommendation: 'Desabilitar Introspeção GraphQL em ambiente de produção (ex.: no Apollo Server: `introspection: false`).',
        owasp: 'A05:2021 – Security Misconfiguration',
        cwe: 'CWE-200',
        confidence: 'confirmado'   // estrutura do schema validada, não só substring
      });
      break; // Achou um ativo
    } catch {
      // Endpoint não existe ou erro de conexão
    }
  }

  return findings;
}

/**
 * Inventaria buckets de nuvem REFERENCIADOS pela aplicação.
 *
 * INFO, não MEDIUM: isto é um INVENTÁRIO, não um achado de risco. A função só
 * faz regex no HTML/URLs capturadas — nunca testa se o bucket é listável. FP
 * concreto evitado: qualquer asset legítimo de terceiro servido de S3/GCS
 * (logo de parceiro, SDK, imagem de CDN) virava "Bucket de Nuvem exposto
 * MEDIUM", ou seja, "não testei" apresentado como risco.
 *
 * Por que NÃO faço o teste real (`GET ?list-type=2` e exigir `ListBucketResult`):
 *   1. a função é SÍNCRONA e o chamador (src/auditor.mjs, ~2623) espalha o
 *      retorno direto num array (`...bucketFindings`); torná-la async quebraria
 *      esse arquivo, que não é meu.
 *   2. o teste bateria em host de TERCEIRO, fora do alvo autorizado — teria de
 *      ficar atrás de --active e de uma autorização que não temos para o bucket.
 * Se quiser o teste real, peço para expor uma função async separada e o auditor
 * passar a aguardá-la.
 */
export function checkCloudBucketExposure(htmlContent, capturedUrls, pageUrl) {
  const findings = [];
  const textToScan = `${htmlContent} ${(capturedUrls || []).join(' ')}`;
  const matches = Array.from(new Set(textToScan.match(CLOUD_BUCKET_REGEX) || []));

  if (matches.length > 0) {
    findings.push({
      type: 'cloud_bucket_detected',
      severity: 'INFO',
      thirdParty: false,
      phase: 'PRÉ-LOGIN',
      label: `${matches.length} bucket(s) de nuvem (S3/GCP/Azure) referenciados — não testados`,
      url: pageUrl,
      buckets: matches.slice(0, 10),
      currentValue: matches.slice(0, 5).join('  '),
      risk: `A aplicação faz referência a buckets de nuvem (${matches.slice(0, 3).join(', ')}). Isto é um INVENTÁRIO: o Sentinela NÃO testou a permissão desses buckets. Vale revisar manualmente se algum está com ACL "Public Read"/"List", o que exporia arquivos ou backups.`,
      recommendation: 'Revisar manualmente a política de cada bucket listado (Block Public Access ativo) e servir arquivos privados via URLs assinadas com expiração curta.',
      owasp: 'A05:2021 – Security Misconfiguration',
      cwe: 'CWE-732',
      confidence: 'provável'
    });
  }

  return findings;
}

/**
 * Audita conexões WebSocket capturadas na rede.
 */
export function checkWebSocketSecurity(capturedRoutes, targetUrl) {
  const findings = [];
  const isHttps = targetUrl.startsWith('https:');
  const wsRoutes = capturedRoutes.filter(r => r.url && (r.url.startsWith('ws:') || r.url.startsWith('wss:')));

  for (const r of wsRoutes) {
    if (isHttps && r.url.startsWith('ws:')) {
      findings.push({
        type: 'insecure_websocket',
        severity: 'HIGH',
        thirdParty: false,
        phase: 'PRÉ-LOGIN',
        label: 'WebSocket Não Criptografado (ws:// em site HTTPS)',
        url: r.url,
        risk: 'A aplicação utiliza WebSocket sem criptografia (ws://) em uma página HTTPS. Dados trafegados via WebSocket podem ser interceptados em texto claro (Man-in-the-Middle).',
        recommendation: 'Usar exclusivamente WebSockets seguros criptografados com TLS (wss://).',
        owasp: 'A02:2021 – Cryptographic Failures',
        cwe: 'CWE-319',
        confidence: 'confirmado'
      });
    }
  }

  return findings;
}

/**
 * [DESATIVADA — duplicata] Auditoria de COOP/COEP.
 *
 * COOP e COEP JÁ são verificados em src/rules/header-rules.mjs (SECURITY_HEADERS,
 * entradas 'Cross-Origin-Opener-Policy' e 'Cross-Origin-Embedder-Policy'), que
 * emite exatamente o mesmo `type: 'missing_security_header'` com o mesmo campo
 * `header` — ou seja, a MESMA chave de dedup
 * (`missing_security_header|<header>|<origem>`, ver src/report/dedup.mjs).
 *
 * FP concreto evitado: como o dedup mantém o PRIMEIRO achado visto, o mesmo
 * problema chegava duas vezes com severidades diferentes e a que sobrevivia no
 * relatório dependia da ordem de execução — header-rules está sendo rebaixado
 * para INFO, e esta cópia (LOW) podia vencer a corrida e reportar o mesmo header
 * ausente com gravidade maior. Fonte única agora: header-rules.mjs.
 *
 * A função continua exportada e com a mesma assinatura porque src/auditor.mjs
 * (~2627) a importa e chama; ela só passou a não produzir achados.
 */
export function checkCrossOriginIsolation(_headers, _targetUrl) {
  return [];
}
