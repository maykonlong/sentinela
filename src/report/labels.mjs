/**
 * Títulos legíveis dos achados — FONTE ÚNICA para HTML e Markdown.
 *
 * Por que este arquivo existe: 83% dos achados de uma sessão real (293 de 351)
 * chegam ao relatório SEM o campo `label`. As regras que os produzem
 * (header-rules, storage-rules, o bloco de formulários do auditor) descrevem o
 * problema em campos estruturados — `header`, `cookieName`, `formIndex` — e
 * deixam o `label` de fora. O fallback antigo era `f.label || f.type`, que
 * imprimia o slug técnico (`cookie_insecure_flags`) como TÍTULO EXECUTIVO no
 * relatório entregue à diretoria.
 *
 * A informação boa já existe no achado; só faltava compor. `titleOf()` junta
 * um rótulo em português (TYPE_LABELS) com o "sujeito" do achado:
 *   cookie_insecure_flags + cookieName=AUTH_SESSION_ID
 *     → "Cookie sem flags seguras — AUTH_SESSION_ID"
 *   missing_security_header + header=Content-Security-Policy
 *     → "Header de segurança ausente — Content-Security-Policy"
 *
 * Regras que JÁ preenchem `label` continuam mandando: `titleOf()` respeita o
 * label e só acrescenta o sujeito quando ele ainda não aparece no texto.
 */

/**
 * Rótulo em português por tipo de achado.
 * Mantenha em sincronia com os `type:` de src/rules/*, src/auditor.mjs,
 * src/infra/* e src/generators/*. Tipo desconhecido cai no humanize().
 */
export const TYPE_LABELS = {
  // ── Headers HTTP ──
  missing_security_header:       'Header de segurança ausente',
  weak_security_header:          'Header de segurança mal configurado',
  information_disclosure_header: 'Header expõe tecnologia/versão',
  cors_wildcard:                 'CORS liberado para qualquer origem (*)',
  cors_credentials:              'CORS aceita envio de credenciais',
  cors_reflected:                'CORS reflete origem arbitrária',
  cache_control_sensitive:       'Página autenticada sem Cache-Control: no-store',
  no_https:                      'Site servido sem HTTPS',
  http_downgrade:                'Conteúdo também servido via HTTP',

  // ── Cookies ──
  cookie_insecure_flags:         'Cookie sem flags seguras',
  cookie_sensitive_no_httponly:  'Cookie sensível sem httpOnly',
  cookie_missing_secure_prefix:  'Cookie de sessão sem prefixo __Host-/__Secure-',
  cookie_consent_violation:      'Cookies de rastreio sem consentimento prévio',
  cookie_inventory:              'Inventário de cookies',
  session_fixation:              'Possível session fixation',

  // ── Storage do navegador ──
  storage_sensitive_data:        'Dado sensível no storage do navegador',
  storage_jwt_exposed:           'JWT exposto no storage do navegador',
  storage_inventory:             'Inventário de storage',

  // ── Código-fonte / front-end ──
  exposed_key:                   'Chave ou segredo exposto no código',
  dangerous_code:                'Padrão de código perigoso',
  source_map_exposed:            'Source map exposto',
  source_map_content_exposed:    'Source map baixado — código-fonte original vazado',
  source_map_internal_routes:    'Rotas/paths internos revelados pelo source map',
  global_variable_sensitive:     'Variável global com dado sensível',
  missing_sri:                   'Script externo sem Subresource Integrity (SRI)',
  frontend_role_definition:      'Regra de permissão definida no front-end',
  vulnerable_library:            'Biblioteca com vulnerabilidade conhecida',
  vulnerable_library_osv:        'Biblioteca com CVE catalogada (OSV.dev)',
  console_sensitive:             'Dado sensível impresso no console',
  console_error:                 'Erros de JavaScript no console',
  browser_issue:                 'Alerta de segurança do navegador',
  target_blank_noopener:         'Link target="_blank" sem rel="noopener"',

  // ── Formulários ──
  form_no_csrf:                  'Formulário POST sem token CSRF',
  form_get_sensitive:            'Formulário envia dado sensível via GET',
  password_autocomplete:         'Campo de senha com autocomplete habilitado',

  // ── Fluxo de login ──
  login_no_csrf:                      'Login sem token CSRF',
  login_no_form_tag:                  'Login sem tag <form>',
  login_form_action:                  'Destino do formulário de login',
  login_form_get:                     'Login via GET (senha vai na URL)',
  login_form_http:                    'Login enviado via HTTP (sem criptografia)',
  login_password_no_name:             'Campo de senha sem name/id',
  login_password_autocomplete:        'Campo de senha sem autocomplete definido',
  login_password_maxlength:           'Senha com limite de tamanho (maxlength)',
  login_password_visible:             'Campo de senha em texto visível',
  login_password_example_placeholder: 'Placeholder com exemplo de senha fraca',
  login_password_in_url:              'Senha na URL durante o login',
  login_password_in_response:         'Senha retornada na resposta de login',
  login_forgot_password_http:         'Recuperação de senha via HTTP',
  login_credentials_sent:             'Credenciais enviadas no login',
  login_token_in_url:                 'Token ou código na URL durante o login',
  login_token_in_response:            'Token retornado na resposta de login',
  login_role_in_response:             'Role/permissão na resposta de login',
  login_redirect_with_token:          'Redirect de login com token na URL',
  login_cookie_added:                 'Cookie criado pelo login',
  login_cookie_removed:               'Cookie removido pelo login',
  login_storage_added:                'Chave adicionada ao storage no login',
  login_storage_changed:              'Chave alterada no storage durante o login',
  login_storage_removed:              'Chave removida do storage no login',

  // ── Rede e API ──
  mixed_content:                 'Mixed content (recurso HTTP em página HTTPS)',
  sensitive_in_url:              'Dado sensível na URL',
  sensitive_in_body:             'Dado sensível no corpo da requisição',
  auth_header_detected:          'Header Authorization detectado',
  auth_over_http:                'Token de autenticação enviado via HTTP',
  cross_origin_auth:             'Credenciais enviadas para domínio externo',
  password_in_response:          'Senha retornada pela API',
  token_in_non_auth_response:    'Token retornado por endpoint que não é de autenticação',
  excessive_data_exposure:       'API expõe dados em excesso',
  insecure_websocket:            'WebSocket sem criptografia (ws://)',
  graphql_introspection:         'GraphQL com introspection habilitada',
  graphql_introspection_enabled: 'Introspecção GraphQL ativa',
  api_docs_exposed:              'Documentação de API exposta',
  openid_config_exposed:         'Configuração OpenID Connect exposta',
  cloud_bucket_detected:         'Bucket de nuvem referenciado no código',

  // ── Recon e controle de acesso ──
  robots_disclosure:             'robots.txt expõe caminhos internos',
  sitemap_disclosure:            'sitemap.xml lista URLs',
  verbose_error:                 'Página de erro vaza stack trace / tecnologia',
  broken_access_control:         'Caminho sensível acessível sem login',
  privilege_escalation:          'Área administrativa acessível',
  open_redirect:                 'Open redirect',
  backup_file_exposed:           'Arquivo de backup exposto',
  exposed_sensitive_file:        'Arquivo sensível exposto',
  http_method_enabled:           'Métodos HTTP perigosos habilitados',
  missing_security_txt:          'Sem /.well-known/security.txt',
  idor_suspected:                'Possível IDOR/BOLA (acesso a objeto de outro usuário)',
  idor_confirmed:                'IDOR/BOLA CONFIRMADO (testado com 2 contas reais)',
  tech_fingerprint:              'Tecnologia identificada (fingerprint)',

  // ── TLS, DNS e infraestrutura ──
  weak_tls:                      'Protocolo TLS obsoleto',
  cert_expired:                  'Certificado TLS expirado',
  cert_expiring:                 'Certificado TLS próximo do vencimento',
  cert_self_signed:              'Certificado auto-assinado / CA não confiável',
  exposed_port:                  'Porta TCP aberta',
  ip_blacklisted:                'IP em blacklist (DNSBL)',
  missing_spf_record:            'Sem registro SPF (anti-spoofing)',
  missing_dmarc_record:          'Sem registro DMARC (anti-phishing)',
  missing_caa_record:            'Sem registro CAA (autorização de CA)',
  missing_ptr_record:            'Sem registro DNS reverso (PTR)',

  // ── LGPD / privacidade ──
  pii_in_url:                    'Dado pessoal em parâmetro de URL',
  pii_in_url_value:              'Documento pessoal no valor de parâmetro da URL',
  pii_in_storage:                'Dado pessoal no storage do navegador',
  pii_in_storage_value:          'Documento pessoal gravado no storage',
  missing_privacy_policy:        'Sem link visível para Política de Privacidade',
  missing_form_optin:            'Formulário sem opt-in explícito',

  // ── Genérico ──
  info:                          'Informação',
};

/** Corta strings longas para caberem num título sem quebrar o layout. */
function clip(v, max = 70) {
  const s = String(v).trim();
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

/**
 * "Sujeito" do achado: o QUE exatamente foi encontrado (qual header, qual
 * cookie, qual porta). É o dado que já vinha no achado mas não era exibido.
 * Retorna '' quando o tipo não tem um sujeito curto e útil.
 */
export function subjectOf(f) {
  if (!f) return '';

  switch (f.type) {
    case 'missing_security_header':
    case 'weak_security_header':
    case 'information_disclosure_header':
    case 'cors_wildcard':
    case 'cors_credentials':
    case 'cache_control_sensitive':
      return f.header ? clip(f.header) : '';

    case 'cookie_insecure_flags':
    case 'cookie_sensitive_no_httponly':
    case 'session_fixation':
    case 'login_cookie_added':
    case 'login_cookie_removed':
      return f.cookieName ? clip(f.cookieName) : '';

    case 'storage_sensitive_data':
    case 'storage_jwt_exposed':
    case 'pii_in_storage':
    case 'pii_in_storage_value':
    case 'login_storage_added':
    case 'login_storage_changed':
    case 'login_storage_removed':
      // O par storage+chave é o que identifica o achado (localStorage["token"]).
      if (f.storage && f.key) return clip(`${f.storage}["${f.key}"]`);
      return f.key ? clip(f.key) : (f.storage ? clip(f.storage) : '');

    case 'storage_inventory':
      return f.storage ? clip(f.storage) : '';

    case 'form_no_csrf':
    case 'form_get_sensitive':
      // `action` é o destino real do POST; formIndex é o desempate quando o
      // form não declara action (envio por JS para a própria URL).
      if (f.action) return clip(f.action, 60);
      return Number.isInteger(f.formIndex) ? `formulário #${f.formIndex + 1}` : '';

    case 'password_autocomplete':
      return f.inputName ? clip(f.inputName) : '';

    case 'exposed_port':
      return f.port ? clip(`porta ${f.port}${f.service ? ` (${f.service})` : ''}`) : '';

    case 'vulnerable_library':
      return f.library ? clip(f.library) : '';

    case 'missing_sri':
      return f.src ? clip(f.src, 60) : '';

    case 'missing_spf_record':
    case 'missing_dmarc_record':
    case 'missing_caa_record':
    case 'missing_ptr_record':
      return f.host ? clip(f.host) : '';

    case 'pii_in_url':
    case 'pii_in_url_value':
    case 'open_redirect':
      return f.param || f.key ? clip(f.param || f.key) : '';

    case 'http_method_enabled':
      return Array.isArray(f.methods) ? clip(f.methods.join(', ')) : '';

    default:
      return '';
  }
}

/** Slug → texto legível. Último recurso para um `type` fora do dicionário. */
function humanize(type) {
  if (!type) return 'Achado sem tipo';
  const s = String(type).replace(/_/g, ' ');
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/**
 * Título executivo de um achado. Usado por HTML e Markdown — nunca imprima
 * `f.label || f.type` direto no relatório.
 */
export function titleOf(f) {
  if (!f || typeof f !== 'object') return 'Achado sem tipo';

  const subject = subjectOf(f);
  const label = typeof f.label === 'string' ? f.label.trim() : '';

  // Sem label próprio: dicionário (ou slug humanizado) + sujeito.
  if (!label) {
    const head = TYPE_LABELS[f.type] || humanize(f.type);
    return subject ? `${head} — ${subject}` : head;
  }

  // Com label: respeita o texto da regra e só acrescenta o sujeito se ele
  // ainda não estiver lá (comparação sem caixa: "Porta 5432" vs "porta 5432").
  if (subject && !label.toLowerCase().includes(subject.toLowerCase())) {
    return `${label} — ${subject}`;
  }
  return label;
}

/**
 * Resumo de alcance a partir dos campos que `dedup.mjs` acrescenta.
 * Substitui a antiga repetição do mesmo achado uma vez por URL.
 * Retorna null quando o achado só foi visto uma vez (nada a dizer).
 *
 * @returns {{count:number, urls:string[], text:string}|null}
 */
export function reachOf(f) {
  const count = Number(f?.occurrenceCount) || 0;
  if (count <= 1) return null;

  // `occurrences` já vem sem URLs repetidas e com teto de 25 (ver dedup.mjs).
  const urls = (Array.isArray(f.occurrences) ? f.occurrences : [])
    .map(o => o && o.url)
    .filter(Boolean);

  const parts = [`observado ${count}×`];
  if (urls.length > 1) parts.push(`em ${urls.length}${count > urls.length ? '+' : ''} URL(s) distintas`);

  return { count, urls, text: parts.join(' ') };
}

/* ────────────────────────────────────────────────────────────────────────────
 * Estados de verificação de infraestrutura
 *
 * Princípio: NADA é afirmado como "ok"/"limpo"/"ausente" sem evidência
 * positiva. Os scanners de infra passaram a distinguir "ausente" (consulta
 * respondeu, o registro não existe) de "não verificado" (a consulta falhou) e
 * de "não aplicável" (não faz sentido testar). O relatório tratava qualquer
 * valor falsy como "⚠️ Ausente" e qualquer não-blacklist como "✅ Limpo" —
 * ou seja, transformava falha de consulta em afirmação. Estes helpers existem
 * para que HTML e MD renderizem os quatro estados do mesmo jeito.
 * ──────────────────────────────────────────────────────────────────────────── */

const DNS_STATE = {
  ok:             { text: '✅ Configurado',   color: '#2f9e44' },
  ausente:        { text: '⚠️ Ausente',       color: '#f08c00' },
  nao_verificado: { text: '❔ Não verificado (falha de consulta DNS)', color: '#868e96' },
  nao_aplicavel:  { text: '➖ Não se aplica',  color: '#868e96' },
};

/**
 * Estado de um registro DNS de segurança (SPF/DMARC/CAA/PTR).
 * @param {object} dnsSec - objeto `infraData.dnsSecurity`
 * @param {'SPF'|'DMARC'|'CAA'|'PTR'} record
 * @returns {{state:string, text:string, color:string}}
 */
export function dnsRecordState(dnsSec, record) {
  const sec = dnsSec || {};
  const summary = sec.summary || {};
  const key = String(record).toLowerCase();
  const raw = summary[`${key}_state`];

  if (raw && DNS_STATE[raw]) {
    const base = { state: raw, ...DNS_STATE[raw] };
    // Motivo mais comum de "não se aplica": o domínio não recebe e-mail, então
    // cobrar SPF/DMARC dele seria falso positivo.
    if (raw === 'nao_aplicavel' && sec.has_mx === false) {
      return { ...base, text: '➖ Não se aplica (domínio sem MX)' };
    }
    return base;
  }

  // Fallback para scanners antigos, que só expunham `has_*` (booleano). Aqui
  // ainda não dá para distinguir ausente de não verificado — assumimos o
  // comportamento histórico, mas só neste caminho legado.
  const legacy = summary[`has_${key}`];
  return legacy
    ? { state: 'ok', ...DNS_STATE.ok }
    : { state: 'ausente', ...DNS_STATE.ausente };
}

/**
 * Estado da reputação do IP (DNSBL). "✅ Limpo" exige `status === 'PASS'`:
 * com IP privado ou consulta falhada não há base para afirmar nada.
 * @returns {{state:string, text:string, color:string, detail:string}}
 */
export function reputationState(rep) {
  const r = rep || {};
  const flagged = Array.isArray(r.blacklists_flagged) ? r.blacklists_flagged : [];

  if (r.is_blacklisted || flagged.length > 0) {
    return {
      state: 'blacklisted',
      text: '❌ Blacklisted',
      color: '#c92a2a',
      detail: flagged.length ? flagged.join(', ') : '',
    };
  }

  if (r.not_applicable) {
    return {
      state: 'nao_aplicavel',
      text: '➖ Não se aplica (IP privado/reservado)',
      color: '#868e96',
      detail: r.note || '',
    };
  }

  if (r.status === 'PASS') {
    return { state: 'ok', text: '✅ Limpo', color: '#2f9e44', detail: r.note || '' };
  }

  // Inclui status INFO/ausente: consultas inconclusivas não viram "limpo".
  const unknown = Array.isArray(r.blacklists_unknown) ? r.blacklists_unknown : [];
  return {
    state: 'nao_verificado',
    text: '❔ Não verificado',
    color: '#868e96',
    detail: r.note || (unknown.length
      ? `${unknown.length} lista(s) sem resposta conclusiva: ${unknown.map(u => u.bl || u).join(', ')}`
      : ''),
  };
}

/**
 * Confiança numa porta reportada como aberta. O scanner faz dupla passagem:
 * `confirmed` só é true se as duas concordaram; `inconsistent` marca as que
 * divergiram (abriram numa passagem e não na outra).
 * @returns {{text:string, color:string}|null} null quando confirmada.
 */
export function portConfidence(p) {
  if (!p || p.confirmed) return null;
  if (p.inconsistent) {
    return { text: '⚠️ não confirmada (resultado divergiu entre as 2 passagens)', color: '#f08c00' };
  }
  return { text: '❔ não confirmada (2ª passagem não validou)', color: '#868e96' };
}

/** Aviso quando o scan TCP inteiro foi inconclusivo (`status: 'INFO'`). */
export function tcpScanNotice(tcp) {
  if (!tcp || tcp.status !== 'INFO') return '';
  return 'Varredura TCP inconclusiva: nenhuma porta respondeu de forma definitiva '
       + '(timeouts/filtragem). A ausência de portas listadas abaixo NÃO significa que estejam fechadas.';
}
