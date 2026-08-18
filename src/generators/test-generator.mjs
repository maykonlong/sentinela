/**
 * Test Generator — Gera código de teste e snippets de correção
 * Reimplementação em Node.js do generator_checker.py do URL Checker.
 *
 * Gera: Playwright (.spec.ts), Postman collection, cURL, Python, Go,
 * e snippets de correção para Nginx e Apache.
 */

import { URL } from 'url';

/**
 * Headers já cobertos por asserts fixos no template do Playwright — não devem
 * ser repetidos na parte dinâmica.
 */
const BASELINE_HEADERS = ['strict-transport-security', 'x-content-type-options', 'x-frame-options'];

/**
 * Extrai a lista DISTINTA de headers ausentes.
 *
 * Por que dedup: os achados vêm por resposta HTTP (mesmo com dedup.mjs, uma
 * origem diferente gera outro achado do mesmo header). Sem `Set`, uma auditoria
 * real com 174 achados de `missing_security_header` sobre 8-9 headers distintos
 * gerava um .spec.ts de ~29 KB com 177 `expect()` repetidos e um
 * `server_fix.missing_headers` com 174 entradas — artefato ilegível e inútil
 * para quem vai corrigir. O que interessa é o CONJUNTO de headers a adicionar.
 */
function distinctMissingHeaders(findings = []) {
  return [...new Set(
    findings
      .filter(f => f.type === 'missing_security_header' && f.header)
      .map(f => String(f.header).trim())
      .filter(Boolean)
  )].sort((a, b) => a.localeCompare(b));
}

/**
 * Gera teste Playwright TypeScript para verificar headers e status.
 */
function generatePlaywrightTest(targetUrl, findings = []) {
  const parsed = new URL(targetUrl);
  const host = parsed.hostname;

  const headerChecks = distinctMissingHeaders(findings)
    .filter(h => !BASELINE_HEADERS.includes(h.toLowerCase()))
    .map(h => `
    expect(headers['${h.toLowerCase()}']).toBeTruthy();
    console.log(\`[CHECK] ${h}: \${headers['${h.toLowerCase()}'] || 'MISSING'}\`);`)
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
 * Catálogo de correção por header: valor recomendado + o porquê.
 * A chave é o nome do header em minúsculas (como vem do finding).
 */
const HEADER_FIXES = {
  'strict-transport-security':     { canonical: 'Strict-Transport-Security',     value: 'max-age=31536000; includeSubDomains; preload', why: 'HSTS — força HTTPS por 1 ano' },
  'x-content-type-options':        { canonical: 'X-Content-Type-Options',        value: 'nosniff',                                     why: 'Previne MIME type sniffing' },
  'x-frame-options':               { canonical: 'X-Frame-Options',               value: 'DENY',                                        why: 'Previne Clickjacking' },
  'referrer-policy':               { canonical: 'Referrer-Policy',               value: 'strict-origin-when-cross-origin',             why: 'Controla o que o header Referer envia' },
  'content-security-policy':       { canonical: 'Content-Security-Policy',       value: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' https:;", why: 'CSP básico — AJUSTAR conforme a aplicação antes de aplicar' },
  'permissions-policy':            { canonical: 'Permissions-Policy',            value: 'camera=(), microphone=(), geolocation=()',    why: 'Bloqueia APIs sensíveis do browser' },
  'cross-origin-opener-policy':    { canonical: 'Cross-Origin-Opener-Policy',    value: 'same-origin',                                 why: 'Isola o browsing context (proteção XS-Leaks)' },
  'cross-origin-resource-policy':  { canonical: 'Cross-Origin-Resource-Policy',  value: 'same-origin',                                 why: 'Impede que outros sites carreguem seus recursos' },
  'cross-origin-embedder-policy':  { canonical: 'Cross-Origin-Embedder-Policy',  value: 'require-corp',                                why: 'Exige opt-in de recursos cross-origin' },
  'x-permitted-cross-domain-policies': { canonical: 'X-Permitted-Cross-Domain-Policies', value: 'none',                                why: 'Bloqueia crossdomain.xml (Flash/Acrobat legado)' },
  'cache-control':                 { canonical: 'Cache-Control',                 value: 'no-store, no-cache, must-revalidate',         why: 'Evita cache de páginas autenticadas' },
  'x-xss-protection':              { canonical: 'X-XSS-Protection',              value: '0',                                           why: 'Desliga o filtro legado (recomendação atual: 0 + CSP)' },
};

/** Valor genérico quando o header não está no catálogo. */
function fixFor(header) {
  const key = String(header).toLowerCase();
  return HEADER_FIXES[key] || { canonical: header, value: 'AJUSTAR', why: 'Header ausente detectado pelo Sentinela — defina o valor adequado' };
}

/**
 * Gera snippets de correção para Nginx e Apache baseado nos findings.
 *
 * Antes esta função calculava `missingHeaders` e IGNORAVA o resultado: nginx e
 * apache eram strings estáticas, idênticas em toda auditoria. Consequência
 * prática: o relatório mandava "adicione X-Frame-Options" mesmo quando o alvo
 * já tinha X-Frame-Options, e omitia headers ausentes que não estavam na lista
 * fixa (COOP/CORP/COEP, por exemplo). Agora as linhas saem da lista REAL de
 * headers ausentes — se nada está faltando, o snippet diz isso em vez de
 * sugerir configuração desnecessária.
 */
function generateServerSnippets(findings = []) {
  const missingHeaders = distinctMissingHeaders(findings);
  // Só sugere esconder a versão do servidor se o Sentinela realmente viu
  // vazamento de versão (Server:/X-Powered-By).
  const leaksVersion = findings.some(f => f.type === 'information_disclosure_header');
  const cacheSensitive = findings.some(f => f.type === 'cache_control_sensitive');

  const nginxLines = [
    '# ──────────────────────────────────────────────────────────',
    '# Correção de Security Headers — Nginx',
    '# Adicione ao bloco server {} do seu site',
    `# Gerado a partir dos ${missingHeaders.length} header(s) AUSENTE(S) neste alvo.`,
    '# ──────────────────────────────────────────────────────────',
    '',
  ];

  if (!missingHeaders.length) {
    nginxLines.push('# ✅ Nenhum header de segurança ausente foi detectado neste alvo.');
    nginxLines.push('#    Nada a adicionar aqui.');
  } else {
    for (const h of missingHeaders) {
      const fix = fixFor(h);
      nginxLines.push(`# ${fix.why}`);
      nginxLines.push(`add_header ${fix.canonical} "${fix.value}" always;`);
      nginxLines.push('');
    }
  }

  if (leaksVersion) {
    nginxLines.push('# Ocultar versão do servidor (Server:/X-Powered-By detectado)');
    nginxLines.push('server_tokens off;');
    nginxLines.push('');
  }
  if (cacheSensitive) {
    nginxLines.push('# Cache-Control para páginas autenticadas');
    nginxLines.push('# (adicionar no location das rotas autenticadas)');
    nginxLines.push('add_header Cache-Control "no-store, no-cache, must-revalidate" always;');
  }

  const apacheLines = [
    '# ──────────────────────────────────────────────────────────',
    '# Correção de Security Headers — Apache (.htaccess ou httpd.conf)',
    `# Gerado a partir dos ${missingHeaders.length} header(s) AUSENTE(S) neste alvo.`,
    '# ──────────────────────────────────────────────────────────',
    '',
  ];

  if (!missingHeaders.length) {
    apacheLines.push('# ✅ Nenhum header de segurança ausente foi detectado neste alvo.');
  } else {
    apacheLines.push('<IfModule mod_headers.c>');
    for (const h of missingHeaders) {
      const fix = fixFor(h);
      apacheLines.push(`    # ${fix.why}`);
      apacheLines.push(`    Header always set ${fix.canonical} "${fix.value}"`);
      apacheLines.push('');
    }
    apacheLines.push('</IfModule>');
  }

  if (leaksVersion) {
    apacheLines.push('');
    apacheLines.push('# Ocultar versão (Server:/X-Powered-By detectado)');
    apacheLines.push('ServerSignature Off');
    apacheLines.push('ServerTokens Prod');
  }

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
