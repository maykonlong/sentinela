/**
 * Mapeia cada tipo de achado para OWASP Top 10 (2021), CWE e nível de confiança.
 * Usado no relatório para dar linguagem de mercado e priorização (Tier 4).
 *
 * confiança:
 *   'confirmado' = checagem determinística (header/cookie/lib/tls/rede observada)
 *   'provável'   = heurística/regex que pode ter falso-positivo (código, roles)
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
  cache_control_sensitive:    { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-525', confidence: 'confirmado' },
  target_blank_noopener:      { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-1022', confidence: 'confirmado' },
  http_method_enabled:        { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-650', confidence: 'confirmado' },
  exposed_sensitive_file:     { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-538', confidence: 'confirmado' },
  missing_security_txt:       { owasp: 'A05:2021 – Security Misconfiguration', cwe: '—', confidence: 'confirmado' },
  browser_issue:              { owasp: 'A05:2021 – Security Misconfiguration', cwe: 'CWE-693', confidence: 'confirmado' },

  // A06 – Vulnerable and Outdated Components
  vulnerable_library:         { owasp: 'A06:2021 – Vulnerable and Outdated Components', cwe: 'CWE-1104', confidence: 'confirmado' },

  // A01 – Broken Access Control (IDOR/BOLA, access diff, open redirect)
  idor_suspected:             { owasp: 'A01:2021 – Broken Access Control', cwe: 'CWE-639', confidence: 'provável' },
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
};

const DEFAULT = { owasp: 'Diversos / Boas práticas', cwe: '—', confidence: 'provável' };

/** Retorna {owasp, cwe, confidence} para um finding. */
export function mapFinding(finding) {
  const base = MAP[finding.type] || DEFAULT;
  // Confiança pode ser reforçada: chave de formato específico é confirmada.
  let confidence = base.confidence;
  if (finding.type === 'exposed_key' && /AWS|Google|Stripe|GitHub|Slack|Twilio|SendGrid|credenciais/i.test(finding.label || '')) {
    confidence = 'confirmado';
  }
  return { owasp: base.owasp, cwe: base.cwe, confidence };
}
