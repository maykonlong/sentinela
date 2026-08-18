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

// Expressões regulares para detecção de PII
const REGEX_CPF = /\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b/;
const REGEX_CNPJ = /\b\d{2}\.?\d{3}\.?\d{3}\/\d{4}-?\d{2}\b/;
const REGEX_EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/;
const REGEX_PHONE = /\b(?:\+?55\s?)?(?:\(?\d{2}\)?\s?)?(?:9\d{4}|\d{4})-?\d{4}\b/;
const PII_PARAM_KEYS = ['cpf', 'cnpj', 'rg', 'credit_card', 'card_number', 'card_num', 'cvv', 'password', 'senha', 'cellphone', 'celular', 'telefone'];

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
      const lowerKey = key.toLowerCase();
      if (PII_PARAM_KEYS.includes(lowerKey)) {
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

      // Testar valores de parâmetros para CPF/CNPJ soltos
      if (REGEX_CPF.test(value) || REGEX_CNPJ.test(value)) {
        findings.push({
          type: 'pii_in_url_value',
          severity: 'HIGH',
          thirdParty: false,
          label: `CPF/CNPJ exposto no valor do parâmetro "${key}" na URL`,
          url: url.split('?')[0],
          paramKey: key,
          risk: `Um número de documento (CPF/CNPJ) foi detectado no parâmetro "${key}" da URL. O tráfego de dados pessoais via URL expõe o titular a vazamentos e viola diretamente a LGPD.`,
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
      const lowerKey = key.toLowerCase();
      const valStr = typeof value === 'string' ? value : JSON.stringify(value);

      if (PII_PARAM_KEYS.some(k => lowerKey.includes(k))) {
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
          confidence: 'confirmado'
        });
      }

      if (REGEX_CPF.test(valStr) || REGEX_CNPJ.test(valStr)) {
        findings.push({
          type: 'pii_in_storage_value',
          severity: 'HIGH',
          thirdParty: false,
          label: `CPF/CNPJ não criptografado gravado no ${storeType} (chave: ${key})`,
          url: pageUrl,
          key,
          storeType,
          risk: `Documentos pessoais (CPF/CNPJ) encontrados sem criptografia na chave "${key}" do ${storeType}. Risco grave de vazamento de PII em caso de XSS.`,
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
        return text.includes('privacidade') || text.includes('lgpd') || text.includes('privacidade') ||
               href.includes('privacidade') || href.includes('privacy') || href.includes('lgpd');
      });

      const hasTermsLink = links.some(a => {
        const text = (a.innerText || '').toLowerCase();
        const href = (a.getAttribute('href') || '').toLowerCase();
        return text.includes('termos') || text.includes('uso') || href.includes('termos') || href.includes('terms');
      });

      // Checar se há formulários sem checkbox de consentimento
      const forms = Array.from(document.querySelectorAll('form'));
      const formWithoutOptin = forms.some(f => {
        const inputs = Array.from(f.querySelectorAll('input'));
        const hasSubmit = inputs.some(i => i.type === 'submit' || i.type === 'button') || f.querySelector('button');
        const hasTextInput = inputs.some(i => ['text', 'email', 'tel'].includes(i.type));
        const hasCheckbox = inputs.some(i => i.type === 'checkbox');
        return hasSubmit && hasTextInput && !hasCheckbox;
      });

      return { hasPrivacyLink, hasTermsLink, formWithoutOptin };
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
        severity: 'MEDIUM',
        thirdParty: false,
        label: 'Formulário sem checkbox explícito de aceite/opt-in (LGPD Art. 7º)',
        url,
        risk: 'Formulário de cadastro/contato coleta dados sem checkbox de consentimento ativo do usuário. A LGPD exige consentimento livre, informado e inequívoco.',
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
