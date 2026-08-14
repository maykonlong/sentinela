/**
 * Regras de detecção para requisições de rede (XHR, Fetch, WebSocket)
 * Monitora chamadas de API e detecta padrões inseguros
 */

const SENSITIVE_URL_PATTERNS = [
  { regex: /[?&](?:token|key|secret|password|passwd|api_key|apikey|access_token|auth)=([^&]+)/gi, label: 'Credencial na query string', severity: 'CRITICAL' },
  { regex: /[?&](?:cpf|cnpj|email|phone|telefone|celular)=([^&]+)/gi, label: 'PII na query string', severity: 'HIGH' },
];

const SENSITIVE_BODY_PATTERNS = [
  { regex: /"(?:password|passwd|senha|secret|api_key|apikey|token|credit_card|cvv|cpf|cnpj)"\s*:\s*"[^"]+"/gi, label: 'Dado sensível no body' },
];

/**
 * Analisa uma requisição de rede interceptada
 */
export function analyzeRequest(request) {
  const findings = [];
  const url = request.url;
  const method = request.method;
  const headers = request.headers || {};
  const postData = request.postData || '';

  // Credenciais na query string
  for (const rule of SENSITIVE_URL_PATTERNS) {
    const matches = url.match(rule.regex);
    if (matches) {
      findings.push({
        type: 'sensitive_in_url',
        severity: rule.severity,
        label: rule.label,
        url: maskUrl(url),
        method,
        risk: `${rule.label} na URL (query string). URLs são logadas em servidores, proxies, analytics, browser history, e podem aparecer no header Referer enviado a outros sites.`,
        recommendation: 'Enviar dados sensíveis no body (POST) ou em headers (Authorization). NUNCA na URL.',
      });
    }
  }

  // Authorization header com token exposto no log
  if (headers['authorization'] || headers['Authorization']) {
    const authHeader = headers['authorization'] || headers['Authorization'];
    findings.push({
      type: 'auth_header_detected',
      severity: 'INFO',
      label: 'Authorization header detectado',
      url: maskUrl(url),
      method,
      scheme: authHeader.split(' ')[0],
      note: 'Authorization header está presente. Verificar se é enviado apenas via HTTPS e se o token tem expiração curta.',
    });

    // Bearer sem HTTPS
    if (url.startsWith('http://') && !url.includes('localhost') && !url.includes('127.0.0.1')) {
      findings.push({
        type: 'auth_over_http',
        severity: 'CRITICAL',
        label: 'Token de autenticação enviado via HTTP',
        url: maskUrl(url),
        method,
        risk: 'Token enviado sem criptografia. Qualquer pessoa na rede pode interceptar e se autenticar como o usuário.',
        recommendation: 'Usar HTTPS para todas as requisições autenticadas. Nunca enviar tokens via HTTP.',
      });
    }
  }

  // Dados sensíveis no body
  if (postData) {
    for (const rule of SENSITIVE_BODY_PATTERNS) {
      const matches = postData.match(rule.regex);
      if (matches) {
        findings.push({
          type: 'sensitive_in_body',
          severity: 'INFO',
          label: rule.label,
          url: maskUrl(url),
          method,
          note: 'Dado sensível no body da requisição. Isso é esperado para login/cadastro, mas verificar se a conexão é HTTPS.',
        });
      }
    }
  }

  // Requisição para domínio externo com credenciais
  const pageOrigin = request.pageOrigin;
  if (pageOrigin) {
    try {
      const reqHost = new URL(url).hostname;
      const pageHost = new URL(pageOrigin).hostname;

      if (reqHost !== pageHost && (headers['authorization'] || headers['Authorization'] || headers['cookie'])) {
        findings.push({
          type: 'cross_origin_auth',
          severity: 'MEDIUM',
          label: 'Credenciais enviadas para domínio externo',
          url: maskUrl(url),
          pageOrigin,
          method,
          risk: 'Tokens/cookies estão sendo enviados para um domínio diferente. Verificar se este domínio é confiável.',
          recommendation: 'Validar que requisições autenticadas vão apenas para domínios sob seu controle.',
        });
      }
    } catch {
      // URL inválida
    }
  }

  return findings;
}

/**
 * Analisa uma resposta de rede
 */
export function analyzeResponse(response) {
  const findings = [];

  // Verificar se API retorna dados sensíveis desnecessários
  if (response.body) {
    try {
      const body = typeof response.body === 'string' ? JSON.parse(response.body) : response.body;

      // Checar se a API retorna a senha do usuário
      if (body.password || body.passwd || body.senha) {
        findings.push({
          type: 'password_in_response',
          severity: 'CRITICAL',
          url: maskUrl(response.url),
          risk: 'API retorna a senha do usuário na resposta! Isso NUNCA deve acontecer. Qualquer script na página pode ler essa resposta.',
          recommendation: 'NUNCA retornar senhas nas respostas da API. Remover campo password/senha de todos os endpoints.',
        });
      }

      // Checar se retorna tokens em respostas não-auth
      if (body.token || body.accessToken || body.access_token || body.refreshToken || body.refresh_token) {
        if (!response.url.includes('login') && !response.url.includes('auth') && !response.url.includes('token')) {
          findings.push({
            type: 'token_in_non_auth_response',
            severity: 'HIGH',
            url: maskUrl(response.url),
            risk: 'Token retornado em endpoint que não é de autenticação. Tokens devem ser retornados apenas em fluxos de login/refresh.',
            recommendation: 'Retornar tokens apenas nos endpoints de autenticação. Outros endpoints devem validar o token, não retorná-lo.',
          });
        }
      }

      // Checar se retorna dados de outros usuários
      if (Array.isArray(body) || (body.data && Array.isArray(body.data))) {
        const items = Array.isArray(body) ? body : body.data;
        if (items.length > 0 && items[0]) {
          const sampleItem = items[0];
          const sensitiveFields = [];
          if (sampleItem.email) sensitiveFields.push('email');
          if (sampleItem.cpf) sensitiveFields.push('cpf');
          if (sampleItem.phone || sampleItem.telefone) sensitiveFields.push('telefone');
          if (sampleItem.password || sampleItem.senha) sensitiveFields.push('SENHA (!)');

          if (sensitiveFields.length > 1) {
            findings.push({
              type: 'excessive_data_exposure',
              severity: 'MEDIUM',
              url: maskUrl(response.url),
              fieldsExposed: sensitiveFields,
              itemCount: items.length,
              risk: `API retorna lista com ${items.length} itens contendo campos sensíveis: ${sensitiveFields.join(', ')}. Se o endpoint não filtra por permissão, qualquer usuário pode acessar dados de outros (IDOR/BOLA).`,
              recommendation: 'Implementar: 1) Paginação 2) Filtro por permissão (Row Level Security) 3) Selecionar apenas campos necessários (projection) 4) Mascarar dados sensíveis em listagens.',
            });
          }
        }
      }
    } catch {
      // Body não é JSON
    }
  }

  return findings;
}

// ─── Helpers ───────────────────────────────────────────────

function maskUrl(url) {
  try {
    const parsed = new URL(url);
    // Mascarar valores de query params sensíveis
    for (const [key] of parsed.searchParams) {
      if (/token|key|secret|password|auth|cpf|cnpj/i.test(key)) {
        parsed.searchParams.set(key, '***');
      }
    }
    return parsed.toString();
  } catch {
    return url;
  }
}
