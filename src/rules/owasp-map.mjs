/**
 * Mapeia cada tipo de achado para OWASP Top 10 (2021), CWE e nível de confiança.
 * Usado no relatório para dar linguagem de mercado e priorização (Tier 4).
 *
 * confiança:
 *   'confirmado'  = checagem determinística (header/cookie/lib/tls/DNS/rede observada)
 *   'provável'    = heurística/regex que pode ter falso-positivo (código, roles)
 *   'informativo' = achado de inventário (severity INFO); não é vulnerabilidade,
 *                   é contexto/prova de coleta. Só renderizado como texto.
 *
 * REGRA DE OURO: todo `type:` produzido por src/rules/, src/infra/ ou
 * src/auditor.mjs precisa estar em MAP. O DEFAULT abaixo existe só como rede de
 * segurança para o relatório não quebrar — ele NÃO deve ser atingido em produção,
 * porque marca tudo como 'provável' e apagava a confiança de checagens
 * determinísticas (SPF/DMARC/CAA são fato binário do DNS, não palpite).
 * O teste `test/owasp-map-coverage.mjs` falha se algum type escapar daqui.
 */

const MAP = {
  // A01 – Broken Access Control
  frontend_role_definition:   { owasp: 'A01:2021 – Broken Access Control', cwe: 'CWE-602', confidence: 'provável' },
  login_role_in_response:     { owasp: 'A01:2021 – Broken Access Control', cwe: 'CWE-602', confidence: 'confirmado' },
  excessive_data_exposure:    { owasp: 'A01:2021 – Broken Access Control', cwe: 'CWE-213', confidence: 'provável' },
  form_no_csrf:               { owasp: 'A01:2021 – Broken Access Control', cwe: 'CWE-352', confidence: 'provável' },
  login_no_csrf:              { owasp: 'A01:2021 – Broken Access Control', cwe: 'CWE-352', confidence: 'provável' },

  // A02 – Cryptographic Failures
  no_https:                   { owasp: 'A02:2021 – Cryptographic Failures', cwe: 'CWE-319', confidence: 'confirmado' },
  mixed_content:              { owasp: 'A02:2021 – Cryptographic Failures', cwe: 'CWE-319', confidence: 'confirmado' },
  weak_tls:                   { owasp: 'A02:2021 – Cryptographic Failures', cwe: 'CWE-326', confidence: 'confirmado' },
  cert_expired:               { owasp: 'A02:2021 – Cryptographic Failures', cwe: 'CWE-295', confidence: 'confirmado' },
  cert_expiring:              { owasp: 'A02:2021 – Cryptographic Failures', cwe: 'CWE-295', confidence: 'confirmado' },
  cert_self_signed:           { owasp: 'A02:2021 – Cryptographic Failures', cwe: 'CWE-295', confidence: 'confirmado' },
  exposed_key:                { owasp: 'A02:2021 – Cryptographic Failures', cwe: 'CWE-798', confidence: 'provável' },
  storage_sensitive_data:     { owasp: 'A02:2021 – Cryptographic Failures', cwe: 'CWE-522', confidence: 'confirmado' },
  storage_jwt_exposed:        { owasp: 'A02:2021 – Cryptographic Failures', cwe: 'CWE-522', confidence: 'confirmado' },
  token_in_non_auth_response: { owasp: 'A02:2021 – Cryptographic Failures', cwe: 'CWE-522', confidence: 'confirmado' },
  login_token_in_response:    { owasp: 'A02:2021 – Cryptographic Failures', cwe: 'CWE-522', confidence: 'confirmado' },
  login_token_in_url:         { owasp: 'A02:2021 – Cryptographic Failures', cwe: 'CWE-598', confidence: 'confirmado' },
  login_redirect_with_token:  { owasp: 'A02:2021 – Cryptographic Failures', cwe: 'CWE-598', confidence: 'confirmado' },
  sensitive_in_url:           { owasp: 'A02:2021 – Cryptographic Failures', cwe: 'CWE-598', confidence: 'confirmado' },
  password_in_response:       { owasp: 'A02:2021 – Cryptographic Failures', cwe: 'CWE-256', confidence: 'confirmado' },
  login_password_in_response: { owasp: 'A02:2021 – Cryptographic Failures', cwe: 'CWE-256', confidence: 'confirmado' },
  auth_over_http:             { owasp: 'A02:2021 – Cryptographic Failures', cwe: 'CWE-319', confidence: 'confirmado' },
  login_form_http:            { owasp: 'A02:2021 – Cryptographic Failures', cwe: 'CWE-319', confidence: 'confirmado' },
  login_credentials_sent:     { owasp: 'A02:2021 – Cryptographic Failures', cwe: 'CWE-319', confidence: 'confirmado' },

  // A03 – Injection
  dangerous_code:             { owasp: 'A03:2021 – Injection (XSS)', cwe: 'CWE-79', confidence: 'provável' },

  // A05 – Security Misconfiguration
  missing_security_header:    { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-693', confidence: 'confirmado' },
  weak_security_header:       { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-693', confidence: 'confirmado' },
  information_disclosure_header: { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-200', confidence: 'confirmado' },
  cors_wildcard:              { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-942', confidence: 'confirmado' },
  cors_credentials:           { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-942', confidence: 'confirmado' },
  global_variable_sensitive:  { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-200', confidence: 'provável' },
  cookie_insecure_flags:      { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-614 / CWE-1004', confidence: 'confirmado' },
  cookie_sensitive_no_httponly: { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-1004', confidence: 'confirmado' },
  source_map_exposed:         { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-540', confidence: 'confirmado' },
  // source_map_content_exposed: severidade escala com o que foi achado dentro
  // (pode chegar a segredo real, daí 'provável' — só é 'confirmado' quando o
  // finding tem evidência de segredo, mas o campo de confiança aqui é o piso).
  source_map_content_exposed: { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-540', confidence: 'provável' },
  source_map_internal_routes: { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-200', confidence: 'confirmado' },
  cookie_missing_secure_prefix: { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-1004', confidence: 'provável' },
  cache_control_sensitive:    { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-525', confidence: 'confirmado' },
  duplicate_security_header:  { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-436', confidence: 'confirmado' },
  target_blank_noopener:      { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-1022', confidence: 'confirmado' },
  http_method_enabled:        { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-650', confidence: 'confirmado' },
  exposed_sensitive_file:     { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-538', confidence: 'confirmado' },
  missing_security_txt:       { owasp: 'A05:2021 – Security Misconfiguration', cwe: '—', confidence: 'confirmado' },
  browser_issue:              { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-693', confidence: 'confirmado' },

  // A06 – Vulnerable and Outdated Components
  vulnerable_library:         { owasp: 'A06:2021 – Vulnerable and Outdated Components', cwe: 'CWE-1104', confidence: 'confirmado' },
  // Mesma categoria do achado hardcoded acima, mas via consulta viva ao
  // OSV.dev — CVE catalogada de verdade, não heurística de regex.
  vulnerable_library_osv:     { owasp: 'A06:2021 – Vulnerable and Outdated Components', cwe: 'CWE-1104', confidence: 'confirmado' },

  // A01 – Broken Access Control (IDOR/BOLA, access diff, open redirect)
  idor_suspected:             { owasp: 'A01:2021 – Broken Access Control', cwe: 'CWE-639', confidence: 'provável' },
  // Diferente do suspected: veio de uma 2ª conta real acessando o objeto da
  // 1ª — prova, não heurística de troca de ID.
  idor_confirmed:             { owasp: 'A01:2021 – Broken Access Control', cwe: 'CWE-639', confidence: 'confirmado' },
  broken_access_control:      { owasp: 'A01:2021 – Broken Access Control', cwe: 'CWE-284', confidence: 'provável' },
  privilege_escalation:       { owasp: 'A01:2021 – Broken Access Control', cwe: 'CWE-285', confidence: 'provável' },
  open_redirect:              { owasp: 'A01:2021 – Broken Access Control', cwe: 'CWE-601', confidence: 'confirmado' },

  // Recon / Security Misconfiguration (A05)
  robots_disclosure:          { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-200', confidence: 'confirmado' },
  sitemap_disclosure:         { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-200', confidence: 'confirmado' },
  openid_config_exposed:      { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-200', confidence: 'confirmado' },
  api_docs_exposed:           { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-200', confidence: 'confirmado' },
  graphql_introspection:      { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-200', confidence: 'confirmado' },
  cors_reflected:             { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-942', confidence: 'confirmado' },
  verbose_error:              { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-209', confidence: 'confirmado' },
  http_downgrade:             { owasp: 'A02:2021 – Cryptographic Failures', cwe: 'CWE-319', confidence: 'confirmado' },
  tech_fingerprint:           { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-200', confidence: 'confirmado' },
  backup_file_exposed:        { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-530', confidence: 'confirmado' },

  // A09 – Security Logging and Monitoring Failures
  console_sensitive:          { owasp: 'A09:2021 – Security Logging and Monitoring Failures', cwe: 'CWE-532', confidence: 'confirmado' },

  // A07 – Identification and Authentication Failures
  session_fixation:           { owasp: 'A07:2021 – Identification and Authentication Failures', cwe: 'CWE-384', confidence: 'confirmado' },
  user_enumeration:           { owasp: 'A07:2021 – Identification and Authentication Failures', cwe: 'CWE-204', confidence: 'provável' },
  no_rate_limit:              { owasp: 'A07:2021 – Identification and Authentication Failures', cwe: 'CWE-307', confidence: 'provável' },
  weak_password_policy:       { owasp: 'A07:2021 – Identification and Authentication Failures', cwe: 'CWE-521', confidence: 'confirmado' },
  login_password_maxlength:   { owasp: 'A07:2021 – Identification and Authentication Failures', cwe: 'CWE-521', confidence: 'confirmado' },

  // A08 – Software and Data Integrity Failures
  missing_sri:                { owasp: 'A08:2021 – Software and Data Integrity Failures', cwe: 'CWE-353', confidence: 'confirmado' },

  // ───────────────────────────────────────────────────────────────────────────
  // DNS / e-mail — checagens 100% determinísticas (registro existe ou não).
  // Ficavam no DEFAULT e saíam como 'provável', subestimando achados que são
  // fato verificável com um `dig`.
  // ───────────────────────────────────────────────────────────────────────────
  missing_spf_record:         { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-290', confidence: 'confirmado' },
  missing_dmarc_record:       { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-290', confidence: 'confirmado' },
  missing_caa_record:         { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-295', confidence: 'confirmado' },
  missing_ptr_record:         { owasp: 'A05:2021 – Security Misconfiguration', cwe: '—',       confidence: 'confirmado' },

  // ───────────────────────────────────────────────────────────────────────────
  // LGPD / Privacidade — penalizavam a nota na categoria `lgpd` mas apareciam
  // sem OWASP/CWE no relatório. Como a base legal é mais forte que o CWE aqui,
  // cada um cita o artigo da Lei 13.709/2018 no campo `lgpd`.
  // ───────────────────────────────────────────────────────────────────────────
  missing_privacy_policy:     { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-359', confidence: 'confirmado', lgpd: 'LGPD Art. 9º — transparência sobre o tratamento' },
  missing_form_optin:         { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-359', confidence: 'confirmado', lgpd: 'LGPD Art. 8º — consentimento livre e informado' },
  cookie_consent_violation:   { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-359', confidence: 'confirmado', lgpd: 'LGPD Art. 8º — consentimento prévio a cookies não essenciais' },
  pii_in_url:                 { owasp: 'A02:2021 – Cryptographic Failures',    cwe: 'CWE-598', confidence: 'confirmado', lgpd: 'LGPD Art. 46 — segurança no tratamento' },
  pii_in_url_value:           { owasp: 'A02:2021 – Cryptographic Failures',    cwe: 'CWE-598', confidence: 'confirmado', lgpd: 'LGPD Art. 46 — segurança no tratamento' },
  pii_in_storage:             { owasp: 'A02:2021 – Cryptographic Failures',    cwe: 'CWE-922', confidence: 'confirmado', lgpd: 'LGPD Art. 46 — segurança no tratamento' },
  pii_in_storage_value:       { owasp: 'A02:2021 – Cryptographic Failures',    cwe: 'CWE-922', confidence: 'confirmado', lgpd: 'LGPD Art. 46 — segurança no tratamento' },

  // ───────────────────────────────────────────────────────────────────────────
  // Infra / rede exposta
  // ───────────────────────────────────────────────────────────────────────────
  exposed_port:               { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-1327', confidence: 'confirmado' },
  ip_blacklisted:             { owasp: 'A05:2021 – Security Misconfiguration', cwe: '—',        confidence: 'confirmado' },
  cloud_bucket_detected:      { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-200',  confidence: 'provável' },
  graphql_introspection_enabled: { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-200', confidence: 'confirmado' },
  insecure_websocket:         { owasp: 'A02:2021 – Cryptographic Failures',    cwe: 'CWE-319',  confidence: 'confirmado' },

  // ───────────────────────────────────────────────────────────────────────────
  // Autenticação / sessão (A07) e segredos em trânsito (A02)
  // ───────────────────────────────────────────────────────────────────────────
  cross_origin_auth:          { owasp: 'A07:2021 – Identification and Authentication Failures', cwe: 'CWE-346', confidence: 'confirmado' },
  login_password_visible:     { owasp: 'A07:2021 – Identification and Authentication Failures', cwe: 'CWE-549', confidence: 'confirmado' },
  password_autocomplete:      { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-200', confidence: 'confirmado' },
  login_password_autocomplete:{ owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-200', confidence: 'confirmado' },
  form_get_sensitive:         { owasp: 'A02:2021 – Cryptographic Failures', cwe: 'CWE-598', confidence: 'confirmado' },
  login_form_get:             { owasp: 'A02:2021 – Cryptographic Failures', cwe: 'CWE-598', confidence: 'confirmado' },
  login_password_in_url:      { owasp: 'A02:2021 – Cryptographic Failures', cwe: 'CWE-598', confidence: 'confirmado' },
  login_forgot_password_http: { owasp: 'A02:2021 – Cryptographic Failures', cwe: 'CWE-319', confidence: 'confirmado' },
  sensitive_in_body:          { owasp: 'A02:2021 – Cryptographic Failures', cwe: 'CWE-359', confidence: 'provável' },

  // A09 – Logging: erro de JS no console vaza stack/rota interna ao usuário final.
  console_error:              { owasp: 'A09:2021 – Security Logging and Monitoring Failures', cwe: 'CWE-532', confidence: 'confirmado' },

  // ───────────────────────────────────────────────────────────────────────────
  // Inventário (severity INFO) — não são vulnerabilidades: são a PROVA de que a
  // coleta rodou. Precisam existir aqui para não caírem no DEFAULT e aparecerem
  // no relatório como "Diversos / provável", o que sugere problema onde não há.
  // ───────────────────────────────────────────────────────────────────────────
  cookie_inventory:            { owasp: 'Inventário — evidência de coleta', cwe: '—', confidence: 'informativo' },
  storage_inventory:           { owasp: 'Inventário — evidência de coleta', cwe: '—', confidence: 'informativo' },
  auth_header_detected:        { owasp: 'Inventário — evidência de coleta', cwe: '—', confidence: 'informativo' },
  login_cookie_added:          { owasp: 'Inventário — diff de login',       cwe: '—', confidence: 'informativo' },
  login_cookie_removed:        { owasp: 'Inventário — diff de login',       cwe: '—', confidence: 'informativo' },
  login_storage_added:         { owasp: 'Inventário — diff de login',       cwe: '—', confidence: 'informativo' },
  login_storage_changed:       { owasp: 'Inventário — diff de login',       cwe: '—', confidence: 'informativo' },
  login_storage_removed:       { owasp: 'Inventário — diff de login',       cwe: '—', confidence: 'informativo' },
  login_form_action:           { owasp: 'Inventário — contexto do login',   cwe: '—', confidence: 'informativo' },
  login_no_form_tag:           { owasp: 'Inventário — contexto do login',   cwe: '—', confidence: 'informativo' },
  login_password_no_name:      { owasp: 'Inventário — contexto do login',   cwe: '—', confidence: 'informativo' },
  login_password_example_placeholder: { owasp: 'Inventário — contexto do login', cwe: '—', confidence: 'informativo' },
};

const DEFAULT = { owasp: 'Diversos / Boas práticas', cwe: '—', confidence: 'provável' };

/**
 * Types que aparecem como `type:` no código mas NÃO são achados — são entradas
 * de timeline/UI (`auditTimeline.push({..., type: 'info' })`). O scanner de
 * cobertura precisa ignorá-los, senão exige mapeamento OWASP para um ícone.
 */
export const NON_FINDING_TYPES = new Set(['info', 'success', 'warn', 'error', 'warning']);

/** Lista (ordenada) de todos os types com mapeamento OWASP/CWE explícito. */
export function listMappedTypes() {
  return Object.keys(MAP).sort();
}

/** true se o type tem mapeamento explícito (i.e. não cai no DEFAULT). */
export function isMapped(type) {
  return Object.prototype.hasOwnProperty.call(MAP, type);
}

/**
 * Dada uma lista de types observados, devolve os que cairiam no DEFAULT.
 * Usado por test/owasp-map-coverage.mjs para transformar o fallback silencioso
 * (que hoje esconde achados reais) em falha de teste.
 */
export function findUnmappedTypes(types) {
  return [...new Set(types)]
    .filter(t => t && !NON_FINDING_TYPES.has(t) && !isMapped(t))
    .sort();
}

/** Retorna {owasp, cwe, confidence, lgpd} para um finding. */
export function mapFinding(finding) {
  const base = MAP[finding.type] || DEFAULT;
  // Confiança pode ser reforçada: chave de formato específico é confirmada.
  let confidence = base.confidence;
  if (finding.type === 'exposed_key' && /AWS|Google|Stripe|GitHub|Slack|Twilio|SendGrid|credenciais/i.test(finding.label || '')) {
    confidence = 'confirmado';
  }
  // `lgpd` é opcional (só nos achados com base legal direta) e ADITIVO: quem
  // consome só {owasp, cwe, confidence} continua funcionando igual.
  return { owasp: base.owasp, cwe: base.cwe, confidence, lgpd: base.lgpd || null };
}
