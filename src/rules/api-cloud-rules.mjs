/**
 * Módulo de Auditoria de APIs, Nuvem e Isolamento — Sentinela Enterprise
 * 
 * 1. GraphQL Introspection Check (/graphql, /api/graphql)
 * 2. Exposição de Buckets de Nuvem (Amazon S3, Google Cloud Storage, Azure Blobs)
 * 3. Segurança de WebSockets (ws:// em contexto HTTPS / sem WSS)
 * 4. Cabeçalhos de Isolamento Cross-Origin (COOP, COEP, CORP)
 */

const CLOUD_BUCKET_REGEX = /(?:[a-z0-9.-]+\.s3(?:-[a-z0-9-]+)?\.amazonaws\.com|storage\.googleapis\.com\/[a-z0-9.-]+|[a-z0-9.-]+\.blob\.core\.windows\.net)/gi;

/**
 * Inspeciona GraphQL Introspection em rotas de API.
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

      if (resp.status() === 200) {
        const body = await resp.text();
        if (body.includes('__schema') && body.includes('types')) {
          findings.push({
            type: 'graphql_introspection_enabled',
            severity: 'HIGH',
            thirdParty: false,
            phase: 'PRÉ-LOGIN',
            label: `Introspeção GraphQL Ativa em ${ep}`,
            url: target,
            risk: `O endpoint GraphQL em ${ep} está com Introspeção ativada. Atacantes conseguem extrair a estrutura completa de todas as tabelas, campos, mutações e relacionamentos do banco de dados da aplicação.`,
            recommendation: 'Desabilitar Introspeção GraphQL em ambiente de produção (ex.: no Apollo Server: `introspection: false`).',
            owasp: 'A05:2021 – Security Misconfiguration',
            cwe: 'CWE-200',
            confidence: 'confirmado'
          });
          break; // Achou um ativo
        }
      }
    } catch {
      // Endpoint não existe ou erro de conexão
    }
  }

  return findings;
}

/**
 * Detecta buckets de nuvem expostos no código-fonte ou respostas.
 */
export function checkCloudBucketExposure(htmlContent, capturedUrls, pageUrl) {
  const findings = [];
  const textToScan = `${htmlContent} ${(capturedUrls || []).join(' ')}`;
  const matches = Array.from(new Set(textToScan.match(CLOUD_BUCKET_REGEX) || []));

  if (matches.length > 0) {
    findings.push({
      type: 'cloud_bucket_detected',
      severity: 'MEDIUM',
      thirdParty: false,
      phase: 'PRÉ-LOGIN',
      label: `${matches.length} Bucket(s) de Nuvem (S3/GCP/Azure) identificados`,
      url: pageUrl,
      buckets: matches.slice(0, 10),
      risk: `A aplicação faz referência direta a buckets de nuvem (${matches.slice(0, 3).join(', ')}). Se a ACL ou política de permissões do bucket estiver como "Public Read" ou "List", arquivos confidenciais ou backups podem estar expostos.`,
      recommendation: 'Garantir que a política do Bucket esteja configurada como Privada (Block Public Access) e que o acesso ocorra via URLs assinadas (Pre-signed URLs) com tempo de expiração curto.',
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
 * Audita cabeçalhos de Isolamento Cross-Origin (COOP, COEP, CORP).
 */
export function checkCrossOriginIsolation(headers, targetUrl) {
  const findings = [];
  const coop = headers['cross-origin-opener-policy'];
  const coep = headers['cross-origin-embedder-policy'];

  if (!coop) {
    findings.push({
      type: 'missing_security_header',
      severity: 'LOW',
      thirdParty: false,
      phase: 'PRÉ-LOGIN',
      header: 'Cross-Origin-Opener-Policy',
      label: 'Cabeçalho Cross-Origin-Opener-Policy (COOP) Ausente',
      url: targetUrl,
      risk: 'Sem COOP, janelas/popups abertas a partir do seu site podem manter referência de window.opener para interagir com a aplicação.',
      recommendation: 'Adicionar o cabeçalho "Cross-Origin-Opener-Policy: same-origin" nas respostas HTTP.',
      owasp: 'A05:2021 – Security Misconfiguration',
      cwe: 'CWE-693',
      confidence: 'confirmado'
    });
  }

  if (!coep) {
    findings.push({
      type: 'missing_security_header',
      severity: 'LOW',
      thirdParty: false,
      phase: 'PRÉ-LOGIN',
      header: 'Cross-Origin-Embedder-Policy',
      label: 'Cabeçalho Cross-Origin-Embedder-Policy (COEP) Ausente',
      url: targetUrl,
      risk: 'Sem COEP, recursos cross-origin podem ser carregados sem a permissão explícita (CORP/CORS), reduzindo a proteção do processo de renderização.',
      recommendation: 'Configurar "Cross-Origin-Embedder-Policy: require-corp" em aplicações de alta segurança.',
      owasp: 'A05:2021 – Security Misconfiguration',
      cwe: 'CWE-693',
      confidence: 'confirmado'
    });
  }

  return findings;
}
