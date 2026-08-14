/**
 * Regras de detecção para código JavaScript exposto
 * Detecta chaves de API, tokens hardcoded, roles/permissões no frontend, eval(), etc.
 */

import { isMinified } from './context-rules.mjs';

// confidence: 'strong' = formato específico, ~0 falso-positivo, roda até em minificado.
//             'weak'   = baseado em rótulo (ex.: "password:"), dispara FP em código
//                        minificado/empacotado → só roda em código legível (1ª parte).
const API_KEY_PATTERNS = [
  // AWS
  { regex: /AKIA[0-9A-Z]{16}/g, label: 'AWS Access Key', severity: 'CRITICAL', confidence: 'strong' },
  { regex: /(?:aws).{0,20}(?:secret|key).{0,20}['"`]([A-Za-z0-9/+=]{40})['"`]/gi, label: 'AWS Secret Key', severity: 'CRITICAL', confidence: 'strong' },

  // Google
  { regex: /AIza[0-9A-Za-z_-]{35}/g, label: 'Google API Key', severity: 'CRITICAL', confidence: 'strong' },
  { regex: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g, label: 'Google OAuth Client ID', severity: 'HIGH', confidence: 'strong' },

  // Firebase
  { regex: /(?:firebase|firebaseio)\.com[^\s'"`)]+/gi, label: 'Firebase URL', severity: 'HIGH', confidence: 'weak' },
  { regex: /(?:apiKey|authDomain|databaseURL|projectId|storageBucket|messagingSenderId|appId|measurementId)\s*[:=]\s*['"`]([^'"`]+)['"`]/gi, label: 'Firebase Config', severity: 'HIGH', confidence: 'weak' },

  // Stripe
  { regex: /sk_live_[0-9a-zA-Z]{24,}/g, label: 'Stripe Secret Key (LIVE)', severity: 'CRITICAL', confidence: 'strong' },
  { regex: /pk_live_[0-9a-zA-Z]{24,}/g, label: 'Stripe Publishable Key (live)', severity: 'MEDIUM', confidence: 'strong' },
  { regex: /sk_test_[0-9a-zA-Z]{24,}/g, label: 'Stripe Secret Key (test)', severity: 'HIGH', confidence: 'strong' },

  // GitHub
  { regex: /gh[pousr]_[A-Za-z0-9_]{36,}/g, label: 'GitHub Token', severity: 'CRITICAL', confidence: 'strong' },

  // Slack
  { regex: /xox[baprs]-[0-9a-zA-Z-]+/g, label: 'Slack Token', severity: 'CRITICAL', confidence: 'strong' },

  // Twilio
  { regex: /SK[0-9a-fA-F]{32}/g, label: 'Twilio API Key', severity: 'CRITICAL', confidence: 'strong' },

  // SendGrid
  { regex: /SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}/g, label: 'SendGrid API Key', severity: 'CRITICAL', confidence: 'strong' },

  // Supabase
  { regex: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, label: 'Supabase/JWT anon key', severity: 'HIGH', confidence: 'strong' },

  // Chaves genéricas (baseadas em rótulo)
  { regex: /(?:api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|access[_-]?key|private[_-]?key)\s*[:=]\s*['"`]([A-Za-z0-9_\-/+=]{16,})['"`]/gi, label: 'Chave de API genérica', severity: 'HIGH', confidence: 'weak' },
  { regex: /(?:password|passwd|pwd)\s*[:=]\s*['"`]([^'"`]{4,})['"`]/gi, label: 'Senha hardcoded', severity: 'CRITICAL', confidence: 'weak' },

  // Tokens genéricos em variáveis
  { regex: /(?:const|let|var)\s+\w*(?:token|secret|key|password|apiKey)\w*\s*=\s*['"`]([^'"`]{8,})['"`]/gi, label: 'Token/segredo em variável JS', severity: 'HIGH', confidence: 'weak' },

  // URL com credenciais embutidas (user:senha@host) — estrita + validada para
  // evitar casar coisas como "https://x)||y@media" em código minificado.
  {
    regex: /\bhttps?:\/\/[A-Za-z0-9._~%+-]+:[^@\s'"`)<>]{1,64}@[A-Za-z0-9.-]+/g,
    label: 'URL com credenciais embutidas',
    severity: 'CRITICAL',
    confidence: 'strong',
    validate: (m) => {
      try { const u = new URL(m); return !!u.username && !!u.password; }
      catch { return false; }
    },
  },
];

const ROLE_PATTERNS = [
  // Definição de roles/permissões no frontend
  { regex: /(?:role|papel)\s*[:=]=?\s*['"`](admin|administrator|root|superuser|manager|gerente)['"`]/gi, label: 'Role de admin hardcoded', severity: 'HIGH' },
  { regex: /isAdmin\s*[:=]=?\s*(?:true|false)/gi, label: 'Flag isAdmin no frontend', severity: 'HIGH' },
  { regex: /(?:user|usuario)\.(?:role|tipo|type|papel|permission|permissao)\s*[:=]=?\s*/gi, label: 'Atribuição de role no frontend', severity: 'HIGH' },
  { regex: /if\s*\(\s*(?:user|usuario|currentUser)\.(?:role|tipo|type|isAdmin|permission)\s*(?:===?|!==?|==)\s*['"`]?(admin|root|superuser|manager)['"`]?\s*\)/gi, label: 'Checagem de role no frontend', severity: 'MEDIUM' },
  { regex: /(?:canEdit|canDelete|canCreate|canManage|hasPermission)\s*[:=]=?\s*(?:true|false)/gi, label: 'Permissão hardcoded', severity: 'HIGH' },

  // Menus/rotas baseados em role no frontend
  { regex: /(?:adminRoutes|protectedRoutes|restrictedRoutes)\s*[:=]\s*\[/gi, label: 'Rotas admin definidas no frontend', severity: 'MEDIUM' },
  { regex: /(?:role|permission)\s*:\s*\[['"`](?:admin|manager|superuser)['"`]/gi, label: 'Array de roles privilegiados', severity: 'MEDIUM' },
];

const DANGEROUS_PATTERNS = [
  // eval e similares
  { regex: /\beval\s*\(/g, label: 'Uso de eval()', severity: 'CRITICAL', risk: 'eval() executa código arbitrário. Atacante pode injetar código via inputs que passam pelo eval.' },
  { regex: /\bnew\s+Function\s*\(/g, label: 'new Function() - eval disfarçado', severity: 'CRITICAL', risk: 'Equivalente a eval(). Mesmo risco de execução de código arbitrário.' },
  { regex: /\.innerHTML\s*=/g, label: 'innerHTML assignment', severity: 'HIGH', risk: 'innerHTML sem sanitização é vetor de XSS. Atacante pode injetar <script> ou event handlers.' },
  { regex: /document\.write\s*\(/g, label: 'document.write()', severity: 'HIGH', risk: 'document.write() pode substituir toda a página. Vulnerável a XSS.' },
  { regex: /dangerouslySetInnerHTML/g, label: 'React dangerouslySetInnerHTML', severity: 'HIGH', risk: 'Renderiza HTML raw no React, bypassing sanitização. Vetor de XSS se o conteúdo vier de input do usuário.' },
  { regex: /v-html\s*=/g, label: 'Vue v-html directive', severity: 'HIGH', risk: 'Equivalente ao innerHTML no Vue. Vetor de XSS se conteúdo não for sanitizado.' },

  // Fetch/XHR com URLs hardcoded
  { regex: /fetch\s*\(\s*['"`]https?:\/\/[^'"`]+['"`]/g, label: 'Fetch com URL hardcoded', severity: 'LOW', risk: 'URLs hardcoded podem expor endpoints internos e dificultar mudanças de ambiente.' },

  // Console.log com dados potencialmente sensíveis
  { regex: /console\.\w+\s*\([^)]*(?:token|password|secret|key|auth|session|user|credit|cpf|cnpj)[^)]*\)/gi, label: 'Console.log com dados sensíveis', severity: 'MEDIUM', risk: 'Dados sensíveis no console são visíveis para qualquer pessoa com DevTools aberto.' },

  // Postmessage sem verificação de origem
  { regex: /window\.addEventListener\s*\(\s*['"`]message['"`]/g, label: 'postMessage listener', severity: 'MEDIUM', risk: 'Se o event listener não verificar event.origin, qualquer site pode enviar mensagens maliciosas.' },
];

/**
 * Analisa código-fonte JavaScript/HTML para vulnerabilidades
 */
export function analyzeSourceCode(source, url, opts = {}) {
  const findings = [];
  const minified = opts.minified !== undefined ? !!opts.minified : isMinified(source, url);
  const thirdParty = !!opts.thirdParty;
  const vendor = opts.vendor || null;
  const tag = (f) => {
    f.thirdParty = thirdParty;
    if (vendor) f.vendor = vendor;
    return f;
  };

  // Buscar chaves de API e tokens.
  // Em código minificado/empacotado, rodar SÓ padrões de alta confiança
  // (formatos específicos), pois os baseados em rótulo geram falso-positivo.
  for (const rule of API_KEY_PATTERNS) {
    if (minified && rule.confidence !== 'strong') continue;
    const matches = source.match(rule.regex);
    if (!matches) continue;

    const seen = new Set();
    for (const match of matches) {
      if (rule.validate && !rule.validate(match)) continue; // valida user:senha@host real
      if (seen.has(match)) continue;
      seen.add(match);
      if (seen.size > 5) break; // limitar a 5 ocorrências distintas

      findings.push(tag({
        type: 'exposed_key',
        severity: rule.severity,
        label: rule.label,
        match: maskMatch(match),
        url,
        risk: `${rule.label} exposta no código-fonte do frontend. Qualquer pessoa pode ver via DevTools > Sources. Bots automatizados varrem repositórios e sites buscando esse padrão.`,
        recommendation: 'Mover para variáveis de ambiente no backend. Usar proxy/BFF para chamadas a APIs externas. NUNCA expor chaves secretas no frontend.',
      }));
    }
  }

  // Regras baseadas em rótulo (role, código perigoso) só fazem sentido em
  // código LEGÍVEL. Em minificado disparam falso-positivo em massa.
  if (!minified) {
    // Buscar definições de role/permissão
    for (const rule of ROLE_PATTERNS) {
      const matches = source.match(rule.regex);
      if (matches) {
        for (const match of matches.slice(0, 3)) {
          findings.push(tag({
            type: 'frontend_role_definition',
            severity: rule.severity,
            label: rule.label,
            match: match.trim(),
            url,
            risk: `${rule.label} encontrado no código frontend. Usuário pode alterar esses valores via DevTools/console para escalar privilégios. O frontend NUNCA deve ser a fonte de verdade para permissões.`,
            recommendation: 'Controle de acesso deve ser 100% no backend. Frontend usa roles apenas para UX (mostrar/esconder elementos), mas o backend DEVE validar em TODA requisição.',
            attackExample: `Abrir DevTools > Console > digitar: localStorage.setItem("userRole", "admin") ou alterar a variável no debugger. Se o backend não validar, o atacante terá acesso admin.`,
          }));
        }
      }
    }

    // Buscar padrões perigosos
    for (const rule of DANGEROUS_PATTERNS) {
      const matches = source.match(rule.regex);
      if (matches) {
        findings.push(tag({
          type: 'dangerous_code',
          severity: rule.severity,
          label: rule.label,
          occurrences: matches.length,
          url,
          risk: rule.risk,
          recommendation: getDangerousCodeRecommendation(rule.label),
        }));
      }
    }
  }

  // Source map exposto (vaza código-fonte original). Vale em minificado também.
  const smMatch = source.match(/\/\/[#@]\s*sourceMappingURL=(\S+)/);
  if (smMatch && !/^data:/i.test(smMatch[1])) {
    findings.push(tag({
      type: 'source_map_exposed',
      severity: 'LOW',
      label: 'Source map exposto',
      match: smMatch[1].slice(0, 80),
      url,
      risk: 'O script referencia um source map (.map) externo. Se acessível, ele expõe o código-fonte original (não minificado), com comentários e lógica interna, facilitando a análise por atacantes.',
      recommendation: 'Não publicar arquivos .map em produção, ou restringir o acesso (apenas ambiente interno/observabilidade).',
    }));
  }

  return findings;
}

/**
 * Analisa scripts inline no HTML
 */
export function analyzeInlineScripts(html, url, opts = {}) {
  const findings = [];
  const thirdParty = !!opts.thirdParty;
  const scriptRegex = /<script[^>]*>([\s\S]*?)<\/script>/gi;
  let match;
  let scriptIndex = 0;

  while ((match = scriptRegex.exec(html)) !== null) {
    const scriptContent = match[1].trim();
    if (!scriptContent) continue;

    scriptIndex++;

    // Verificar se o script inline contém dados sensíveis (minificado auto-detectado)
    const scriptFindings = analyzeSourceCode(scriptContent, `${url} (inline script #${scriptIndex})`, { thirdParty });

    // Variáveis globais com dado sensível: só em script legível (evita FP em minificado)
    if (!isMinified(scriptContent)) {
      const globalVarRegex = /(?:window|globalThis)\.\w*(?:token|key|secret|auth|password|user|config)\w*\s*=\s*/gi;
      const globalMatches = scriptContent.match(globalVarRegex);
      if (globalMatches) {
        for (const gm of globalMatches.slice(0, 5)) {
          findings.push({
            type: 'global_variable_sensitive',
            severity: 'HIGH',
            thirdParty,
            label: 'Variável global com dado sensível',
            match: gm.trim(),
            url: `${url} (inline script #${scriptIndex})`,
            risk: 'Variáveis globais (window.*) são acessíveis por qualquer script na página, incluindo scripts de terceiros e XSS.',
            recommendation: 'Não expor dados sensíveis em variáveis globais. Usar closure ou módulos ES para encapsular dados.',
          });
        }
      }
    }

    findings.push(...scriptFindings);
  }

  // Script tags com src externo sem integrity (SRI)
  const externalScriptRegex = /<script[^>]+src\s*=\s*['"]([^'"]+)['"][^>]*>/gi;
  while ((match = externalScriptRegex.exec(html)) !== null) {
    const fullTag = match[0];
    const src = match[1];

    // Ignorar scripts locais
    if (src.startsWith('/') || src.startsWith('./') || src.startsWith('../')) continue;

    if (!fullTag.includes('integrity')) {
      findings.push({
        type: 'missing_sri',
        severity: 'MEDIUM',
        label: 'Script externo sem Subresource Integrity (SRI)',
        src,
        url,
        risk: 'Script externo carregado sem verificação de integridade. Se o CDN/servidor externo for comprometido, código malicioso será executado na sua página.',
        recommendation: 'Adicionar atributo integrity="sha384-..." e crossorigin="anonymous" em todos os scripts externos.',
      });
    }
  }

  return findings;
}

// ─── Helpers ───────────────────────────────────────────────

function maskMatch(match) {
  if (match.length <= 12) return '***';
  return match.substring(0, 6) + '...' + match.substring(match.length - 4);
}

function getDangerousCodeRecommendation(label) {
  const recs = {
    'Uso de eval()': 'Remover eval(). Usar JSON.parse() para dados, ou lógica estruturada para condicionais dinâmicas.',
    'new Function() - eval disfarçado': 'Substituir por funções nomeadas ou maps de funções.',
    'innerHTML assignment': 'Usar textContent para texto. Se precisar de HTML, usar DOMPurify para sanitizar.',
    'document.write()': 'Substituir por DOM API (createElement, appendChild).',
    'React dangerouslySetInnerHTML': 'Usar DOMPurify para sanitizar antes de renderizar: dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }}',
    'Vue v-html directive': 'Sanitizar com DOMPurify antes de usar v-html. Ou usar v-text quando possível.',
    'Console.log com dados sensíveis': 'Remover console.log com dados sensíveis antes de deploy. Usar logger configurável que só loga em desenvolvimento.',
    'postMessage listener': 'Sempre verificar event.origin no handler: if (event.origin !== "https://seu-dominio.com") return;',
  };
  return recs[label] || 'Avaliar necessidade e substituir por alternativa segura.';
}
