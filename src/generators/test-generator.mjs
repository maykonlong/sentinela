/**
 * Test Generator — Gera código de teste e snippets de correção
 * Reimplementação em Node.js do generator_checker.py do URL Checker.
 *
 * Gera: Playwright (.spec.ts), Postman collection, cURL, Python, Go,
 * e snippets de correção para Nginx e Apache.
 */

import { URL } from 'url';

/**
 * Gera teste Playwright TypeScript para verificar headers e status.
 */
function generatePlaywrightTest(targetUrl, findings = []) {
  const parsed = new URL(targetUrl);
  const host = parsed.hostname;

  const headerChecks = findings
    .filter(f => f.type === 'missing_security_header' && f.header)
    .map(f => `
    expect(headers['${f.header.toLowerCase()}']).toBeTruthy();
    console.log(\`[CHECK] ${f.header}: \${headers['${f.header.toLowerCase()}'] || 'MISSING'}\`);`)
    .join('');

  return `import { test, expect } from '@playwright/test';

test.describe('Sentinela — Verificação de Segurança: ${host}', () => {
  test('Status 200 e tempo de resposta < 1500ms', async ({ request }) => {
    const start = Date.now();
    const response = await request.get('${targetUrl}', {
      headers: { 'User-Agent': 'Sentinela-QA-Test/1.0' }
    });
    const responseTime = Date.now() - start;

    expect(response.status()).toBe(200);
    expect(responseTime).toBeLessThan(1500);
    console.log(\`[PASS] Status: \${response.status()} | Tempo: \${responseTime}ms\`);
  });

  test('Headers de Segurança obrigatórios', async ({ request }) => {
    const response = await request.get('${targetUrl}');
    const headers = response.headers();

    // Headers obrigatórios
    expect(headers['strict-transport-security']).toBeTruthy();
    expect(headers['x-content-type-options']).toBeTruthy();
    expect(headers['x-frame-options']).toBeTruthy();${headerChecks}
  });

  test('Cookies com flags seguras', async ({ request }) => {
    const response = await request.get('${targetUrl}');
    const setCookies = response.headersArray().filter(h => h.name.toLowerCase() === 'set-cookie');
    
    for (const cookie of setCookies) {
      const val = cookie.value.toLowerCase();
      console.log(\`[COOKIE] \${cookie.value.split('=')[0]}: httpOnly=\${val.includes('httponly')}, secure=\${val.includes('secure')}, sameSite=\${val.includes('samesite')}\`);
      
      // Cookies de sessão devem ter flags seguras
      if (/session|token|auth|jwt/i.test(cookie.value.split('=')[0])) {
        expect(val).toContain('httponly');
        expect(val).toContain('secure');
      }
    }
  });
});
`;
}

/**
 * Gera coleção Postman v2.1 com testes de segurança.
 */
function generatePostmanCollection(targetUrl, findings = []) {
  const parsed = new URL(targetUrl);
  const host = parsed.hostname;

  return {
    info: {
      _postman_id: `sentinela-${host}`,
      name: `Sentinela Security Test Suite — ${host}`,
      description: 'Testes de segurança gerados automaticamente pelo Sentinela.',
      schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json',
    },
    item: [
      {
        name: `GET ${targetUrl} — Status & Headers`,
        event: [{
          listen: 'test',
          script: {
            exec: [
              'pm.test("Status code is 200", function () {',
              '    pm.response.to.have.status(200);',
              '});',
              'pm.test("Response time < 1000ms", function () {',
              '    pm.expect(pm.response.responseTime).to.be.below(1000);',
              '});',
              'pm.test("HSTS header present", function () {',
              '    pm.response.to.have.header("Strict-Transport-Security");',
              '});',
              'pm.test("X-Content-Type-Options present", function () {',
              '    pm.response.to.have.header("X-Content-Type-Options");',
              '});',
              'pm.test("X-Frame-Options present", function () {',
              '    pm.response.to.have.header("X-Frame-Options");',
              '});',
              'pm.test("Server header hidden", function () {',
              '    var server = pm.response.headers.get("Server");',
              '    pm.expect(server).to.not.include("/");',
              '});',
            ],
            type: 'text/javascript',
          },
        }],
        request: {
          method: 'GET',
          header: [{ key: 'User-Agent', value: 'Sentinela-Postman-Test/1.0' }],
          url: { raw: targetUrl, protocol: parsed.protocol.replace(':', ''), host: [host], path: parsed.pathname.split('/').filter(Boolean) },
        },
        response: [],
      },
    ],
  };
}

/**
 * Gera snippets de código para testar a URL em várias linguagens.
 */
function generateCodeSnippets(targetUrl) {
  return {
    curl: `curl -i -L -A "Sentinela/1.0" "${targetUrl}"`,

    python: `import requests

url = "${targetUrl}"
headers = {"User-Agent": "Sentinela-Python/1.0"}

try:
    response = requests.get(url, headers=headers, timeout=5.0)
    print(f"Status: {response.status_code}")
    print(f"Latência: {response.elapsed.total_seconds() * 1000:.2f} ms")
    
    # Verificar headers de segurança
    security_headers = ["Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy"]
    for h in security_headers:
        val = response.headers.get(h, "AUSENTE ❌")
        print(f"  {h}: {val}")
except Exception as e:
    print(f"Erro: {e}")
`,

    javascript: `// Node.js 18+ (fetch nativo)
async function testSecurity() {
  const start = performance.now();
  try {
    const res = await fetch('${targetUrl}', {
      headers: { 'User-Agent': 'Sentinela-JS/1.0' }
    });
    const latency = (performance.now() - start).toFixed(2);
    console.log(\`Status: \${res.status} | Latência: \${latency}ms\`);
    
    ['strict-transport-security', 'x-content-type-options', 'x-frame-options', 'content-security-policy']
      .forEach(h => console.log(\`  \${h}: \${res.headers.get(h) || 'AUSENTE ❌'}\`));
  } catch (err) {
    console.error('Erro:', err);
  }
}
testSecurity();
`,

    go: `package main

import (
	"fmt"
	"net/http"
	"time"
)

func main() {
	client := &http.Client{Timeout: 5 * time.Second}
	start := time.Now()
	
	req, _ := http.NewRequest("GET", "${targetUrl}", nil)
	req.Header.Set("User-Agent", "Sentinela-Go/1.0")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Erro:", err)
		return
	}
	defer resp.Body.Close()

	elapsed := time.Since(start)
	fmt.Printf("Status: %d | Latência: %v\\n", resp.StatusCode, elapsed)
	
	headers := []string{"Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options"}
	for _, h := range headers {
		val := resp.Header.Get(h)
		if val == "" { val = "AUSENTE ❌" }
		fmt.Printf("  %s: %s\\n", h, val)
	}
}
`,
  };
}

/**
 * Gera snippets de correção para Nginx e Apache baseado nos findings.
 */
function generateServerSnippets(findings = []) {
  const missingHeaders = findings
    .filter(f => f.type === 'missing_security_header')
    .map(f => f.header);

  const nginxLines = [
    '# ──────────────────────────────────────────────────────────',
    '# Correção de Security Headers — Nginx',
    '# Adicione ao bloco server {} do seu site',
    '# ──────────────────────────────────────────────────────────',
    '',
    '# HSTS — Força HTTPS por 1 ano',
    'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
    '',
    '# Previne MIME type sniffing',
    'add_header X-Content-Type-Options "nosniff" always;',
    '',
    '# Previne Clickjacking',
    'add_header X-Frame-Options "DENY" always;',
    '',
    '# Controla o que o header Referer envia',
    'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
    '',
    '# CSP básico (ajustar conforme a aplicação)',
    "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' https:;\" always;",
    '',
    '# Permissions Policy',
    'add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;',
    '',
    '# Ocultar versão do servidor',
    'server_tokens off;',
    '',
    '# Cache-Control para páginas autenticadas',
    '# (adicionar no location das rotas autenticadas)',
    '# add_header Cache-Control "no-store, no-cache, must-revalidate" always;',
  ];

  const apacheLines = [
    '# ──────────────────────────────────────────────────────────',
    '# Correção de Security Headers — Apache (.htaccess ou httpd.conf)',
    '# ──────────────────────────────────────────────────────────',
    '',
    '<IfModule mod_headers.c>',
    '    # HSTS',
    '    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
    '',
    '    # Previne MIME type sniffing',
    '    Header always set X-Content-Type-Options "nosniff"',
    '',
    '    # Previne Clickjacking',
    '    Header always set X-Frame-Options "DENY"',
    '',
    '    # Referer Policy',
    '    Header always set Referrer-Policy "strict-origin-when-cross-origin"',
    '',
    '    # Permissions Policy',
    '    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"',
    '</IfModule>',
    '',
    '# Ocultar versão',
    'ServerSignature Off',
    'ServerTokens Prod',
  ];

  return {
    nginx: nginxLines.join('\n'),
    apache: apacheLines.join('\n'),
    missing_headers: missingHeaders,
  };
}

/**
 * Gera todos os artefatos de teste e correção.
 * @param {string} targetUrl - URL do alvo
 * @param {object[]} findings - Achados do Sentinela
 * @returns {object} Testes e snippets gerados
 */
export function generateTestArtifacts(targetUrl, findings = []) {
  return {
    playwright: generatePlaywrightTest(targetUrl, findings),
    postman: generatePostmanCollection(targetUrl, findings),
    code_snippets: generateCodeSnippets(targetUrl),
    server_fix: generateServerSnippets(findings),
  };
}
