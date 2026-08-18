import { enrichWithVerification, getManualVerification } from '../src/generators/manual-verification.mjs';

const testFindings = [
  { type: 'missing_security_header', header: 'Content-Security-Policy', url: 'https://10.4.0.20:8443' },
  { type: 'weak_security_header', header: 'X-Frame-Options', currentValue: 'SAMEORIGIN', url: 'https://10.4.0.20:8443' },
  { type: 'cookie_sensitive_no_httponly', cookieName: 'session_id', url: 'https://10.4.0.20:8443' },
  { type: 'storage_sensitive_data', storage: 'localStorage', key: 'user_data' },
  { type: 'storage_jwt_exposed', storage: 'localStorage', key: 'auth_token' },
  { type: 'dangerous_code', match: 'innerHTML', url: 'https://10.4.0.20:8443/static/busca.js' },
  { type: 'missing_sri', src: 'https://cdn.example.com/app.js', url: 'https://10.4.0.20:8443' },
  { type: 'exposed_port', port: 5432, host: '10.4.0.20', service: 'PostgreSQL Database' },
  { type: 'form_no_csrf', url: 'https://10.4.0.20:8443/login' },
  { type: 'password_autocomplete', url: 'https://10.4.0.20:8443/login' },
  { type: 'missing_privacy_policy', url: 'https://10.4.0.20:8443' },
  { type: 'missing_form_optin', url: 'https://10.4.0.20:8443/cadastro' },
  { type: 'cookie_consent_violation', url: 'https://10.4.0.20:8443' },
  { type: 'graphql_exposed', url: 'https://10.4.0.20:8443/graphql' },
  { type: 'swagger_exposed', url: 'https://10.4.0.20:8443/api/docs' },
  { type: 'open_redirect', url: 'https://10.4.0.20:8443/login' },
  { type: 'missing_security_txt', url: 'https://10.4.0.20:8443' },
];

console.log('🧪 Testando todos os geradores de verificação manual...');
const enriched = enrichWithVerification(testFindings, 'https://10.4.0.20:8443');

let errors = 0;
enriched.forEach((f, idx) => {
  const mv = f.manualVerification;
  if (!mv || !mv.title || !mv.steps || mv.steps.length === 0) {
    console.error(`❌ [ERRO] Gerador falhou para tipo: ${f.type}`);
    errors++;
  } else {
    console.log(`✅ [OK ${idx + 1}/${enriched.length}] ${f.type} -> ${mv.title}`);
  }
});

if (errors === 0) {
  console.log('\n🎉 TODOS OS 17 GERADORES FORAM TESTADOS E VALIDADOS COM SUCESSO!');
} else {
  console.error(`\n❌ ${errors} geradores apresentaram erros.`);
  process.exit(1);
}
