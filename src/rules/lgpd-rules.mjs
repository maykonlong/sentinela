/**
 * Módulo de Auditoria LGPD & Compliance de Privacidade — Sentinela v2.3
 * 
 * Audita a conformidade da aplicação web com a LGPD (Lei Geral de Proteção de Dados - Lei 13.709/2018):
 * 1. Rastreamento e cookies de terceiros sem consentimento prévio
 * 2. Vazamento de PII (Dados Pessoais Identificáveis: CPF, CNPJ, E-mail, Telefone, Cartão) em URLs, storage e console
 * 3. Presença de links obrigatórios para Política de Privacidade e Termos de Uso
 * 4. Opt-in de consentimento em formulários de cadastro
 */

import { mapFinding } from './owasp-map.mjs';

// Expressões regulares para detecção de PII.
// Globais (/g) porque precisamos iterar TODOS os candidatos do texto e validar
// cada um pelo dígito verificador — o primeiro match nem sempre é o documento real.
const REGEX_CPF_G = /\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b/g;
const REGEX_CNPJ_G = /\b\d{2}\.?\d{3}\.?\d{3}\/\d{4}-?\d{2}\b/g;

/**
 * Chaves cujo NOME sugere dado pessoal.
 * Match por TOKEN (delimitado), nunca por substring: a lista contém 'rg' (2
 * caracteres) e o antigo `lowerKey.includes('rg')` casava `orgId`,
 * `targetRoute`, `largeCache` e `i18n-org` — num app Next.js/Keycloak isso
 * gerava vários `pii_in_storage` HIGH puramente falsos.
 */
const PII_KEY_TOKEN_RE = /(?:^|[_.\-])(cpf|cnpj|rg|credit_?card|card_?num(?:ber)?|cvv|password|senha|cellphone|celular|telefone)(?:$|[_.\-])/i;

/**
 * Testa o nome da chave contra PII_KEY_TOKEN_RE.
 * camelCase é normalizado para snake_case antes (`userCpf` → `user_cpf`), senão
 * chaves camelCase legítimas ficariam de fora do match por token.
 */
function matchesPiiKey(key) {
  const normalized = String(key || '').replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
  return PII_KEY_TOKEN_RE.test(normalized);
}

/** Valida dígitos verificadores de CPF (módulo 11). */
function isValidCpf(raw) {
  const d = String(raw).replace(/\D/g, '');
  if (d.length !== 11) return false;
  if (/^(\d)\1{10}$/.test(d)) return false; // 000.000.000-00, 111.111.111-11 etc. não são CPFs
  const dv = (len) => {
    let sum = 0;
    for (let i = 0; i < len; i++) sum += parseInt(d[i], 10) * (len + 1 - i);
    const r = (sum * 10) % 11;
    return r === 10 ? 0 : r;
  };
  return dv(9) === parseInt(d[9], 10) && dv(10) === parseInt(d[10], 10);
}

/** Valida dígitos verificadores de CNPJ (módulo 11 com pesos 2..9 cíclicos). */
function isValidCnpj(raw) {
  const d = String(raw).replace(/\D/g, '');
  if (d.length !== 14) return false;
  if (/^(\d)\1{13}$/.test(d)) return false;
  const dv = (len) => {
    const weights = len === 12
      ? [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
      : [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    let sum = 0;
    for (let i = 0; i < len; i++) sum += parseInt(d[i], 10) * weights[i];
    const r = sum % 11;
    return r < 2 ? 0 : 11 - r;
  };
  return dv(12) === parseInt(d[12], 10) && dv(13) === parseInt(d[13], 10);
}

/**
 * Retorna o primeiro CPF/CNPJ com dígito verificador VÁLIDO no texto, ou null.
 * O checksum é obrigatório porque a regex de CPF tem separadores opcionais e,
 * sozinha, casa QUALQUER sequência de 11 dígitos: telefone `11987654321`,
 * timestamps em milissegundos e IDs numéricos viravam "CPF exposto" HIGH.
 * Ausência de checksum válido = ausência de evidência → não emitir achado.
 */
function findValidDocument(text) {
  if (!text) return null;
  const str = String(text);
  for (const m of str.matchAll(REGEX_CPF_G)) {
    if (isValidCpf(m[0])) return { kind: 'CPF', value: m[0] };
  }
  for (const m of str.matchAll(REGEX_CNPJ_G)) {
    if (isValidCnpj(m[0])) return { kind: 'CNPJ', value: m[0] };
  }
  return null;
}

// Domínios de rastreamento de terceiros conhecidos
const TRACKING_DOMAINS = [
  'google-analytics.com', 'googletagmanager.com', 'facebook.net', 'connect.facebook.net',
  'hotjar.com', 'analytics.tiktok.com', 'clarity.ms', 'licdn.com', 'doubleclick.net'
];

/**
 * Audita vazamento de PII na URL ou parâmetros de busca.
 */
export function analyzeUrlPii(url) {
  const findings = [];
  try {
    const parsed = new URL(url);
    const params = Array.from(parsed.searchParams.entries());

    for (const [key, value] of params) {
      if (matchesPiiKey(key)) {
        findings.push({
          type: 'pii_in_url',
          severity: 'HIGH',
          thirdParty: false,
          label: `Dado pessoal (${key}) exposto no parâmetro da URL`,
          url: url.split('?')[0],
          paramKey: key,
          risk: `O parâmetro "${key}" está sendo passado na URL em texto claro. URLs ficam registradas no histórico do navegador, logs de servidores web, proxies e no cabeçalho Referer enviado a terceiros, violando o Art. 46 da LGPD (Segurança dos Dados).`,
          recommendation: `Remover "${key}" dos parâmetros GET da URL. Enviar dados sensíveis exclusivamente no corpo de requisições POST com HTTPS (payload JSON).`,
          owasp: 'A04:2021 – Insecure Design / LGPD Art. 46',
          cwe: 'CWE-598',
          confidence: 'confirmado'
        });
      }

      // Testar valores de parâmetros para CPF/CNPJ soltos.
      // Só emite com dígito verificador válido (ver findValidDocument).
      const doc = findValidDocument(value);
      if (doc) {
        findings.push({
          type: 'pii_in_url_value',
          severity: 'HIGH',
          thirdParty: false,
          label: `${doc.kind} exposto no valor do parâmetro "${key}" na URL`,
          url: url.split('?')[0],
          paramKey: key,
          risk: `Um número de documento (${doc.kind}, com dígito verificador válido) foi detectado no parâmetro "${key}" da URL. O tráfego de dados pessoais via URL expõe o titular a vazamentos e viola diretamente a LGPD.`,
          recommendation: `Transmitir documentos e dados de identificação somente via payload seguro (HTTP POST com TLS) ou tokens opacos/hasheados.`,
          owasp: 'A04:2021 – Insecure Design / LGPD Art. 46',
          cwe: 'CWE-598',
          confidence: 'confirmado'
        });
      }
    }
  } catch {
    // URL inválida
  }
  return findings;
}

/**
 * Audita dados PII armazenados em localStorage / sessionStorage.
 */
export function analyzeStoragePii(storageData, pageUrl) {
  const findings = [];
  if (!storageData) return findings;

  const inspectStore = (storeObj, storeType) => {
    for (const [key, value] of Object.entries(storeObj || {})) {
      const valStr = typeof value === 'string' ? value : JSON.stringify(value);

      if (matchesPiiKey(key)) {
        findings.push({
          type: 'pii_in_storage',
          severity: 'HIGH',
          thirdParty: false,
          label: `Dado pessoal (${key}) armazenado no ${storeType}`,
          url: pageUrl,
          key,
          storeType,
          risk: `O campo de dado sensível "${key}" está gravado em ${storeType}. Qualquer script (1ª ou 3ª parte) ou extensão de navegador pode ler dados do ${storeType} sem restrição (XSS Vector), violando a LGPD.`,
          recommendation: `Não armazenar senhas, cartões ou CPFs em ${storeType}. Manter transientemente na memória da aplicação ou em cookies HttpOnly + Secure.`,
          owasp: 'A04:2021 – Insecure Design / LGPD Art. 46',
          cwe: 'CWE-922',
          // 'provável': o gatilho é só o NOME da chave — o valor não foi
          // inspecionado, então pode ser um flag/ID e não o dado pessoal em si.
          confidence: 'provável'
        });
      }

      // Aqui sim há evidência positiva no VALOR (documento com checksum válido).
      const doc = findValidDocument(valStr);
      if (doc) {
        findings.push({
          type: 'pii_in_storage_value',
          severity: 'HIGH',
          thirdParty: false,
          label: `${doc.kind} não criptografado gravado no ${storeType} (chave: ${key})`,
          url: pageUrl,
          key,
          storeType,
          risk: `Documento pessoal (${doc.kind}, com dígito verificador válido) encontrado sem criptografia na chave "${key}" do ${storeType}. Risco grave de vazamento de PII em caso de XSS.`,
          recommendation: `Remover dados pessoais identificáveis do ${storeType}. Se estritamente necessário, armazenar apenas identificadores criptografados/hasheados.`,
          owasp: 'A04:2021 – Insecure Design / LGPD Art. 46',
          cwe: 'CWE-922',
          confidence: 'confirmado'
        });
      }
    }
  };

  inspectStore(storageData.localStorage, 'localStorage');
  inspectStore(storageData.sessionStorage, 'sessionStorage');
  return findings;
}

/**
 * Audita a presença de Política de Privacidade e consentimento prévio de cookies.
 */
export async function analyzeLgpdPage(page, url) {
  const findings = [];
  try {
    // 1. Inspecionar links para Política de Privacidade e Termos de Uso
    const privacyCheck = await page.evaluate(() => {
      const links = Array.from(document.querySelectorAll('a[href]'));
      const hasPrivacyLink = links.some(a => {
        const text = (a.innerText || '').toLowerCase();
        const href = (a.getAttribute('href') || '').toLowerCase();
        return text.includes('privacidade') || text.includes('lgpd') ||
               href.includes('privacidade') || href.includes('privacy') || href.includes('lgpd');
      });

      // Checar formulários DE COLETA DE DADOS DE TITULAR sem checkbox de consentimento.
      // "Qualquer <form> com input de texto + botão" casava campo de busca, filtro
      // de tabela e tela de login — nenhum deles exige consentimento LGPD (login é
      // execução de contrato, Art. 7º V, não consentimento). Por isso exigimos um
      // sinal semântico de cadastro/lead e excluímos login/busca/filtro.
      const COLLECT_RE = /cadastr|newsletter|contato|inscri|lead|sign.?up|registr/i;
      const EXCLUDE_RE = /login|entrar|sign.?in|busca|search|filtro|filter/i;

      const forms = Array.from(document.querySelectorAll('form'));
      let formOptinHint = null;
      for (const f of forms) {
        const haystack = [
          f.className || '', f.id || '', f.name || '',
          f.getAttribute('action') || '', (f.innerText || '').slice(0, 400),
        ].join(' ');

        if (EXCLUDE_RE.test(haystack)) continue;   // exclusão tem precedência
        if (!COLLECT_RE.test(haystack)) continue;  // sem sinal de coleta → não é caso de consentimento

        const inputs = Array.from(f.querySelectorAll('input'));
        const hasSubmit = inputs.some(i => i.type === 'submit' || i.type === 'button') || !!f.querySelector('button');
        const hasTextInput = inputs.some(i => ['text', 'email', 'tel'].includes(i.type));
        const hasCheckbox = inputs.some(i => i.type === 'checkbox');
        if (hasSubmit && hasTextInput && !hasCheckbox) {
          formOptinHint = (f.id || f.name || f.className || f.getAttribute('action') || 'form').slice(0, 120);
          break;
        }
      }

      return { hasPrivacyLink, formWithoutOptin: !!formOptinHint, formOptinHint };
    });

    if (!privacyCheck.hasPrivacyLink) {
      findings.push({
        type: 'missing_privacy_policy',
        severity: 'MEDIUM',
        thirdParty: false,
        label: 'Ausência de link visível para Política de Privacidade (LGPD Art. 9º)',
        url,
        risk: 'A página não apresenta um link claro e acessível para a Política de Privacidade. O Art. 9º da LGPD exige o dever de transparência sobre o tratamento de dados pessoais.',
        recommendation: 'Adicionar um link permanente no rodapé da aplicação para a "Política de Privacidade", detalhando quais dados são coletados, finalidade e contatos do Encarregado (DPO).',
        owasp: 'A04:2021 – Insecure Design / LGPD Art. 9º',
        cwe: 'CWE-359',
        confidence: 'confirmado'
      });
    }

    if (privacyCheck.formWithoutOptin) {
      findings.push({
        type: 'missing_form_optin',
        // LOW: o gatilho é heurístico (nome/ação/texto do form sugerem cadastro).
        // Só uma revisão humana confirma se a base legal ali é consentimento.
        severity: 'LOW',
        thirdParty: false,
        label: 'Formulário sem checkbox explícito de aceite/opt-in (LGPD Art. 7º)',
        url,
        formHint: privacyCheck.formOptinHint,
        risk: `Formulário aparentemente de cadastro/contato (${privacyCheck.formOptinHint}) coleta dados sem checkbox de consentimento ativo do usuário. Quando a base legal for consentimento, a LGPD exige que ele seja livre, informado e inequívoco.`,
        recommendation: 'Adicionar um checkbox (não pré-marcado) do tipo "Li e aceito os Termos de Uso e Política de Privacidade" antes do envio do formulário.',
        owasp: 'A04:2021 – Insecure Design / LGPD Art. 7º',
        cwe: 'CWE-359',
        confidence: 'provável'
      });
    }
  } catch {
    // Erro ao avaliar página
  }

  return findings;
}

/**
 * Audita disparos de rastreadores antes de consentimento do usuário.
 */
export function analyzeTrackingBeforeConsent(capturedRoutes, targetUrl) {
  const findings = [];
  const trackingRequests = capturedRoutes.filter(r => 
    TRACKING_DOMAINS.some(td => (r.host || '').includes(td)) && r.phase === 'PRÉ-LOGIN'
  );

  if (trackingRequests.length > 0) {
    const domainsFound = Array.from(new Set(trackingRequests.map(r => r.host)));
    findings.push({
      type: 'cookie_consent_violation',
      severity: 'HIGH',
      thirdParty: false,
      label: 'Cookies e Rastreadores de Terceiros ativados SEM consentimento prévio',
      url: targetUrl,
      domains: domainsFound,
      risk: `Scripts de rastreamento e telemetria (${domainsFound.join(', ')}) foram executados e coletaram dados ANTES do consentimento explícito do usuário. Violação direta da LGPD (Art. 7º - Hipóteses de tratamento) e diretrizes da ANPD.`,
      recommendation: 'Implementar gerenciador de consentimento (CMP). Bloquear o carregamento dos scripts de terceiros até que o usuário clique em "Aceitar Cookies" no banner.',
      owasp: 'A04:2021 – Insecure Design / LGPD Art. 7º',
      cwe: 'CWE-359',
      confidence: 'confirmado'
    });
  }

  return findings;
}
