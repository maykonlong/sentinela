/**
 * Regras de detecção para código JavaScript exposto
 * Detecta chaves de API, tokens hardcoded, roles/permissões no frontend, eval(), etc.
 */

import { isMinified, classifyResource } from './context-rules.mjs';

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
  // Firebase Config: `appId`/`projectId`/`measurementId` sozinhos são chaves
  // genéricas usadas por GTM, Sentry e config própria — `{ projectId: "banco-stg",
  // appId: "corner" }` disparava 2 achados HIGH sem nada de Firebase envolvido.
  // Só vale como Firebase se houver ≥3 chaves do SDK na vizinhança OU
  // co-ocorrência de authDomain/firebaseapp.com (exclusivos do Firebase).
  {
    regex: /(?:apiKey|authDomain|databaseURL|projectId|storageBucket|messagingSenderId|appId|measurementId)\s*[:=]\s*['"`]([^'"`]+)['"`]/gi,
    label: 'Firebase Config',
    severity: 'HIGH',
    confidence: 'weak',
    validateCtx: (m, source) => {
      const i = source.indexOf(m);
      const win = source.slice(Math.max(0, i - 300), i + m.length + 300);
      if (/authDomain|firebaseapp\.com/i.test(win)) return true;
      const keys = new Set(
        (win.match(/\b(?:apiKey|authDomain|databaseURL|projectId|storageBucket|messagingSenderId|appId|measurementId)\b\s*[:=]/gi) || [])
          .map(s => s.replace(/\s*[:=]\s*$/, '').trim().toLowerCase())
      );
      return keys.size >= 3;
    },
  },

  // Stripe
  { regex: /sk_live_[0-9a-zA-Z]{24,}/g, label: 'Stripe Secret Key (LIVE)', severity: 'CRITICAL', confidence: 'strong' },
  { regex: /pk_live_[0-9a-zA-Z]{24,}/g, label: 'Stripe Publishable Key (live)', severity: 'MEDIUM', confidence: 'strong' },
  { regex: /sk_test_[0-9a-zA-Z]{24,}/g, label: 'Stripe Secret Key (test)', severity: 'HIGH', confidence: 'strong' },

  // GitHub
  { regex: /gh[pousr]_[A-Za-z0-9_]{36,}/g, label: 'GitHub Token', severity: 'CRITICAL', confidence: 'strong' },

  // Slack
  { regex: /xox[baprs]-[0-9a-zA-Z-]+/g, label: 'Slack Token', severity: 'CRITICAL', confidence: 'strong' },

  // Twilio — com delimitador de palavra nas duas pontas. Sem isso, o padrão
  // "SK + 32 hex" casa pedaços de hash de chunk dentro de bundles minificados
  // (onde esta regra roda, por ser 'strong'), gerando CRITICAL falso.
  { regex: /\bSK[0-9a-fA-F]{32}\b/g, label: 'Twilio API Key', severity: 'CRITICAL', confidence: 'strong' },

  // SendGrid
  { regex: /SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}/g, label: 'SendGrid API Key', severity: 'CRITICAL', confidence: 'strong' },

  // Supabase
  { regex: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, label: 'Supabase/JWT anon key', severity: 'HIGH', confidence: 'strong' },

  // Chaves genéricas (baseadas em rótulo). O valor precisa PARECER segredo:
  // `apiKey: "NEXT_PUBLIC_API_KEY_PLACEHOLDER"` (nome de env var) e outras
  // strings de baixa entropia casavam a regex e viravam HIGH.
  {
    regex: /(?:api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|access[_-]?key|private[_-]?key)\s*[:=]\s*['"`]([A-Za-z0-9_\-/+=]{16,})['"`]/gi,
    label: 'Chave de API genérica',
    severity: 'HIGH',
    confidence: 'weak',
    validate: (m) => {
      const v = extractQuotedValue(m);
      if (!v) return false;
      if (/^[A-Z0-9_]+$/.test(v)) return false;          // SCREAMING_SNAKE_CASE = nome de env var/placeholder
      if (/placeholder|example|changeme|your[_-]?key|dummy|sample/i.test(v)) return false;
      return shannonEntropy(v) > 3.5;                    // segredo real é aleatório; rótulo/slug não é
    },
  },
  // Senha hardcoded. Descarta valores que parecem TEXTO HUMANO: dicionários i18n
  // e mensagens de validação (`{ password: "Senha inválida" }`) disparavam
  // CRITICAL só por conterem a chave "password".
  {
    regex: /(?:password|passwd|pwd)\s*[:=]\s*['"`]([^'"`]{4,})['"`]/gi,
    label: 'Senha hardcoded',
    severity: 'CRITICAL',
    confidence: 'weak',
    validate: (m) => {
      const v = extractQuotedValue(m);
      return !!v && !looksLikeHumanText(v);
    },
  },

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

  // Buscar chaves de API e tokens (lógica extraída para scanForSecrets, que
  // também é reusada por fetchAndAnalyzeSourceMap para escanear sourcesContent).
  for (const f of scanForSecrets(source, url, { minified })) {
    findings.push(tag(f));
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
      // Valor cru, sem truncar — `match` é só para exibição; quem for baixar o
      // .map de verdade (fetchAndAnalyzeSourceMap) precisa da URL completa.
      mapUrl: smMatch[1],
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

  // Script tags com src externo sem integrity (SRI).
  //
  // Três correções em relação à versão antiga:
  //  1. `url` do finding era a PÁGINA, não o script. A classificação automática
  //     em auditor.mjs resolve thirdParty pelo `f.url` → SRI ausente do Google
  //     Tag Manager era contabilizado como problema do CLIENTE (1ª parte).
  //     Agora gravamos `url: src` e classificamos pelo `src`.
  //  2. Script same-origin com URL absoluta não é "externo": SRI ali não protege
  //     de nada (é o mesmo servidor que serve a página). Esses são ignorados.
  //  3. Severidade LOW e um ÚNICO finding por grupo, não N. Para tags de conteúdo
  //     dinâmico (GTM/analytics) o hash muda a cada publicação e SRI é
  //     inexequível — a mitigação real é CSP + confiança no fornecedor.
  const externalScriptRegex = /<script[^>]+src\s*=\s*['"]([^'"]+)['"][^>]*>/gi;
  const sriGroups = new Map(); // 'first'|'third' → { scripts:[], vendors:Set }
  let pageHost = '';
  try { pageHost = new URL(url).host; } catch { /* url pode não ser absoluta */ }

  while ((match = externalScriptRegex.exec(html)) !== null) {
    const fullTag = match[0];
    const rawSrc = match[1];
    if (fullTag.includes('integrity')) continue;

    // Resolver contra a página: cobre caminho relativo e protocol-relative
    // (`//cdn.x.com/a.js`), que o filtro antigo `startsWith('/')` descartava
    // por engano mesmo sendo um CDN externo.
    let abs;
    try { abs = new URL(rawSrc, url); } catch { continue; }
    if (!/^https?:$/.test(abs.protocol)) continue;      // data:/blob: não têm SRI
    if (pageHost && abs.host === pageHost) continue;     // same-origin → SRI é inútil

    const { thirdParty, vendor } = classifyResource(abs.href, url);
    const bucket = thirdParty ? 'third' : 'first';
    if (!sriGroups.has(bucket)) sriGroups.set(bucket, { scripts: [], vendors: new Set() });
    const g = sriGroups.get(bucket);
    if (g.scripts.includes(abs.href)) continue;
    g.scripts.push(abs.href);
    if (vendor) g.vendors.add(vendor);
  }

  for (const [bucket, g] of sriGroups) {
    const isThird = bucket === 'third';
    findings.push({
      type: 'missing_sri',
      severity: 'LOW',
      thirdParty: isThird,
      vendor: isThird ? (Array.from(g.vendors).join(', ') || 'Terceiro') : null,
      label: `Script${g.scripts.length > 1 ? 's' : ''} externo${g.scripts.length > 1 ? 's' : ''} sem Subresource Integrity (SRI)${isThird ? ' — 3ª parte' : ''}`,
      src: g.scripts[0],
      scripts: g.scripts,
      occurrences: g.scripts.length,
      url: g.scripts[0],  // URL do SCRIPT (usada pela classificação 1ª/3ª parte)
      pageUrl: url,
      risk: `${g.scripts.length} script(s) carregado(s) de origem externa sem verificação de integridade: ${g.scripts.slice(0, 8).join(', ')}${g.scripts.length > 8 ? ' …' : ''}. Se o CDN/servidor externo for comprometido, código malicioso é executado na página.`,
      recommendation: isThird
        ? 'Para bibliotecas versionadas em CDN, fixar integrity="sha384-..." + crossorigin="anonymous". Para tags de conteúdo dinâmico (Google Tag Manager, analytics), SRI NÃO é aplicável — o arquivo muda sem aviso; mitigar com CSP (script-src com allowlist) e revisão do fornecedor.'
        : 'Adicionar integrity="sha384-..." e crossorigin="anonymous" nos scripts servidos por origem externa sob seu controle (ex.: CDN próprio).',
    });
  }

  return findings;
}

/**
 * Baixa e analisa um source map (.map) referenciado por um script.
 *
 * Diferente da detecção passiva `source_map_exposed` (que só confirma que a
 * REFERÊNCIA `//# sourceMappingURL=...` existe no fim do script), esta função
 * efetivamente busca o arquivo .map e lê `sourcesContent[]` — que tipicamente
 * contém o código-fonte ORIGINAL não minificado (comentários, nomes reais de
 * variável, chaves que o build ofusca, rotas internas de API).
 *
 * Segue o princípio central do projeto: falha de rede/parse/status não-2xx é
 * "não verificado", NUNCA um achado. Só gera finding com evidência positiva
 * (conteúdo do .map efetivamente lido).
 *
 * @param {import('@playwright/test').APIRequestContext} request - context.request do Playwright.
 * @param {string} mapUrl - valor cru da referência sourceMappingURL (pode ser relativo).
 * @param {string} scriptUrl - URL absoluta do script que referenciou o .map (usada para
 *   resolver mapUrl relativo e como base do rótulo dos achados).
 * @param {object} [opts]
 * @param {boolean} [opts.thirdParty] - script é de terceiro? (repassado aos findings)
 * @param {string|null} [opts.vendor] - nome do fornecedor, se thirdParty.
 * @returns {Promise<object[]>} findings novos (pode ser array vazio; nunca lança).
 */
export async function fetchAndAnalyzeSourceMap(request, mapUrl, scriptUrl, opts = {}) {
  const findings = [];
  const thirdParty = !!opts.thirdParty;
  const vendor = opts.vendor || null;
  const tag = (f) => {
    f.thirdParty = thirdParty;
    if (vendor) f.vendor = vendor;
    return f;
  };

  // Resolver mapUrl relativo contra a URL do script (ex.: "app.js.map" vira
  // "https://site.com/static/app.js.map" quando scriptUrl é
  // "https://site.com/static/app.js").
  let absMapUrl;
  try {
    absMapUrl = new URL(mapUrl, scriptUrl).href;
  } catch {
    return findings; // mapUrl/scriptUrl inválidos → sem evidência, sem achado
  }

  // Baixar com timeout de 8s. Qualquer falha (rede, WAF, timeout, 404, 5xx)
  // é ausência de evidência — não afirma nada, só não gera achado.
  let res;
  try {
    res = await request.get(absMapUrl, { maxRedirects: 0, timeout: 8000, failOnStatusCode: false });
  } catch {
    return findings;
  }
  if (!res || res.status() < 200 || res.status() >= 300) return findings;

  let body = '';
  try {
    body = await res.text();
  } catch {
    return findings;
  }
  if (!body) return findings;

  let map;
  try {
    map = JSON.parse(body);
  } catch {
    return findings; // não é JSON válido → não é um source map de verdade
  }
  if (!map || typeof map !== 'object') return findings;

  const sources = Array.isArray(map.sources) ? map.sources : [];
  const sourcesContent = Array.isArray(map.sourcesContent) ? map.sourcesContent : null;
  const hasRealContent = !!sourcesContent && sourcesContent.some(
    (c) => typeof c === 'string' && c.trim().length > 0
  );

  if (hasRealContent) {
    // Escanear CADA entrada de sourcesContent com os mesmos padrões de segredo
    // usados no código normal. Custo limitado: no máximo 50 arquivos e 200KB
    // por arquivo (source maps de app grande podem ter centenas de módulos e
    // arquivos de dezenas de MB — sem teto isso vira DoS de CPU/memória no
    // próprio auditor).
    const MAX_ENTRIES = 50;
    const MAX_CHARS_PER_ENTRY = 200_000;
    const secretFindings = [];
    for (let i = 0; i < sourcesContent.length && i < MAX_ENTRIES; i++) {
      const content = sourcesContent[i];
      if (typeof content !== 'string' || !content.trim()) continue;
      const truncated = content.length > MAX_CHARS_PER_ENTRY
        ? content.slice(0, MAX_CHARS_PER_ENTRY)
        : content;
      const srcName = sources[i] || `source[${i}]`;
      // sourcesContent é sempre código-fonte ORIGINAL (não minificado) —
      // minified:false para não pular os padrões 'weak' baseados em rótulo.
      const found = scanForSecrets(truncated, `${scriptUrl} (source map: ${srcName})`, { minified: false });
      for (const f of found) secretFindings.push(tag(f));
    }

    // A severidade do achado "conteúdo exposto" acompanha o pior segredo
    // encontrado dentro dele (mesma severidade que o achado de segredo normal
    // já usaria) — senão fica MEDIUM (código-fonte revelado, mas sem segredo
    // confirmado pelos padrões).
    const worstSeverity = secretFindings.reduce(
      (worst, f) => (severityRank(f.severity) > severityRank(worst) ? f.severity : worst),
      'MEDIUM'
    );
    const exampleFiles = sources.filter((s, i) => typeof sourcesContent[i] === 'string' && sourcesContent[i].trim()).slice(0, 10);

    findings.push(tag({
      type: 'source_map_content_exposed',
      severity: worstSeverity,
      label: 'Source map expõe código-fonte original',
      url: absMapUrl,
      scriptUrl,
      sourceCount: sources.length,
      exampleFiles,
      occurrences: sourcesContent.filter((c) => typeof c === 'string' && c.trim()).length,
      risk: `O source map contém ${exampleFiles.length}+ arquivo(s) de código-fonte ORIGINAL não minificado (${exampleFiles.slice(0, 5).join(', ')}${exampleFiles.length > 5 ? ', …' : ''}), incluindo comentários, nomes reais de variável/função e lógica de negócio que o build normalmente oculta.${secretFindings.length ? ' Segredo(s) real(is) foram encontrados dentro do código-fonte revelado — ver achados relacionados.' : ''}`,
      recommendation: 'Não publicar arquivos .map (ou sourcesContent) em produção. Se necessário para observabilidade, restringir acesso ao .map por autenticação/rede interna, ou gerar o map sem sourcesContent (só mapeamento de posição, sem o texto original).',
    }));

    findings.push(...secretFindings);
  } else if (sources.length > 0) {
    // Source map existe e resolve, mas sem sourcesContent embutido — achado
    // mais brando: "existe mas não vaza conteúdo" (ainda revela a árvore de
    // arquivos originais, útil para reconhecimento, mas não o código em si).
    findings.push(tag({
      type: 'source_map_content_exposed',
      severity: 'LOW',
      label: 'Source map acessível sem código-fonte embutido',
      url: absMapUrl,
      scriptUrl,
      sourceCount: sources.length,
      occurrences: 1,
      risk: `O .map foi baixado com sucesso e lista ${sources.length} arquivo(s) de origem, mas sem "sourcesContent" — o código-fonte original não está embutido. Ainda assim revela nomes/estrutura de arquivos internos.`,
      recommendation: 'Idealmente não publicar .map em produção. Se publicado, a ausência de sourcesContent já reduz o risco de vazamento de código, mas os nomes de arquivo ainda ajudam reconhecimento.',
    }));
  }

  // Nomes de arquivo em sources[] que parecem rotas de API/paths internos —
  // achado INFO separado (é informação de reconhecimento, não segredo).
  const routeHints = [];
  for (const s of sources) {
    if (typeof s !== 'string' || !s) continue;
    if (looksLikeInternalRoute(s)) routeHints.push(s);
    if (routeHints.length >= 15) break; // teto para não inflar o relatório
  }
  if (routeHints.length > 0) {
    findings.push(tag({
      type: 'source_map_internal_routes',
      severity: 'INFO',
      label: 'Paths internos/rotas de API revelados pelo source map',
      url: absMapUrl,
      scriptUrl,
      paths: routeHints,
      occurrences: routeHints.length,
      risk: 'O source map revela nomes de arquivo que sugerem rotas de API ou módulos internos (ex.: /api/, /internal/, /admin/, /routes/), ajudando um atacante a mapear a superfície de ataque do backend sem precisar de força-bruta.',
      recommendation: 'Não publicar .map em produção. Alternativamente, evitar nomes de arquivo/pasta que revelem estrutura interna sensível do backend.',
    }));
  }

  return findings;
}

// ─── Helpers ───────────────────────────────────────────────

/**
 * Escaneia um texto (código-fonte JS legível ou minificado) em busca de
 * chaves/segredos usando API_KEY_PATTERNS. Extraído de analyzeSourceCode para
 * ser reusado também no conteúdo original revelado por source maps
 * (fetchAndAnalyzeSourceMap). Não aplica thirdParty/vendor — quem chama tagueia.
 */
function scanForSecrets(source, url, { minified = false } = {}) {
  const findings = [];
  // Em código minificado/empacotado, rodar SÓ padrões de alta confiança
  // (formatos específicos), pois os baseados em rótulo geram falso-positivo.
  for (const rule of API_KEY_PATTERNS) {
    if (minified && rule.confidence !== 'strong') continue;
    const matches = source.match(rule.regex);
    if (!matches) continue;

    const seen = new Set();
    for (const match of matches) {
      if (rule.validate && !rule.validate(match)) continue;              // valida o match isolado
      if (rule.validateCtx && !rule.validateCtx(match, source)) continue; // valida com a vizinhança no arquivo
      if (seen.has(match)) continue;
      seen.add(match);
      if (seen.size > 5) break; // limitar a 5 ocorrências distintas

      findings.push({
        type: 'exposed_key',
        severity: rule.severity,
        label: rule.label,
        match: maskMatch(match),
        url,
        risk: `${rule.label} exposta no código-fonte do frontend. Qualquer pessoa pode ver via DevTools > Sources. Bots automatizados varrem repositórios e sites buscando esse padrão.`,
        recommendation: 'Mover para variáveis de ambiente no backend. Usar proxy/BFF para chamadas a APIs externas. NUNCA expor chaves secretas no frontend.',
      });
    }
  }
  return findings;
}

/**
 * Ranking numérico de severidade para comparação (maior = mais grave).
 */
function severityRank(sev) {
  const order = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
  return order[sev] ?? 0;
}

/**
 * Heurística: o path de um arquivo de source map "parece" uma rota de API ou
 * módulo interno (não claramente componente de UI)? Usada só para o achado
 * INFO source_map_internal_routes — não afeta severidade de segredo nenhum.
 */
function looksLikeInternalRoute(path) {
  if (/\/api\/|\/internal\/|\/admin\/|\/routes\//i.test(path)) return true;
  const segments = path.split('/').filter(Boolean);
  if (segments.length < 3) return false;
  // Extensão/pasta típica de componente de UI → não conta como "rota interna".
  if (/\.(vue|jsx|tsx|css|scss|less|svg|png|jpg|jpeg|gif|json)$/i.test(path)) return false;
  if (/\/(components?|pages?|views?|assets?|styles?|public|static)\//i.test(path)) return false;
  return true;
}

/**
 * Extrai o último valor entre aspas do match (é sempre o lado direito do
 * `chave: "valor"`). As regras usam `source.match(regex)` com /g, que devolve o
 * match inteiro e não o grupo de captura — por isso reextraímos aqui.
 */
function extractQuotedValue(match) {
  const m = String(match).match(/['"`]([^'"`]*)['"`]\s*$/);
  return m ? m[1] : null;
}

/**
 * Entropia de Shannon em bits por caractere. Segredo real (token/hash) fica
 * acima de ~4; slug, nome de env var e palavra do dicionário ficam abaixo de 3.5.
 */
function shannonEntropy(str) {
  if (!str) return 0;
  const freq = new Map();
  for (const ch of str) freq.set(ch, (freq.get(ch) || 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / str.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * O valor parece texto humano / placeholder em vez de credencial?
 * Evita o pior falso-positivo do arquivo: dicionário i18n e mensagem de
 * validação (`password: "Senha inválida"`, `password: "Campo obrigatório"`)
 * eram reportados como senha hardcoded CRITICAL.
 */
function looksLikeHumanText(value) {
  if (/\s/.test(value)) return true;                 // segredo não tem espaço
  if (/[À-ÿ]/.test(value)) return true;              // acento = frase em pt/es/fr
  return /^(senha|password|required|obrigat|\*+|xxx|changeme|<.*>|\{\{|%s|\$\{)/i.test(value);
}

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
