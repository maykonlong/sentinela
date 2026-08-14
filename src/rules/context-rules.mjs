/**
 * Classificação de contexto de recursos: 1ª parte (SEU código) vs 3ª parte (vendor/SaaS).
 *
 * Motivo: rodar as regras de "segredo/eval/innerHTML" em bundles minificados de
 * terceiros (HubSpot, LinkedIn, Cloudflare, React, etc.) gera uma enxurrada de
 * falso-positivo. Este módulo permite:
 *   - separar o que é seu do que é de terceiro (E1)
 *   - detectar código minificado para não aplicar regex frouxa nele (E2)
 */

// Vendors/plataformas conhecidos (host OU caminho). Achados aqui NÃO são seu código.
const VENDOR_HOST_RE = /(?:^|\.)(?:hubspot(?:usercontent)?\.(?:com|net)|hsappstatic\.net|hscollectedforms\.net|hs-analytics\.net|hs-banner\.com|hsadspixel\.net|hubspot\.com|cloudflare\.com|cloudflareinsights\.com|cdnjs\.cloudflare\.com|jsdelivr\.net|unpkg\.com|jquery\.com|bootstrapcdn\.com|googleapis\.com|gstatic\.com|google-analytics\.com|googletagmanager\.com|doubleclick\.net|google\.com|googleadservices\.com|facebook\.(?:com|net)|connect\.facebook\.net|linkedin\.com|licdn\.com|twitter\.com|x\.com|bing\.com|clarity\.ms|hotjar\.com|segment\.(?:com|io)|sentry\.io|newrelic\.com|nr-data\.net|datadoghq\.com|intercom\.(?:io|com)|intercomcdn\.com|zendesk\.com|zdassets\.com|recaptcha\.net|gstatic\.com|stripe\.(?:com|network)|cookiebot\.com|onetrust\.com|cookielaw\.org|youtube\.com|ytimg\.com|vimeo\.com|typekit\.net|fontawesome\.com|cloudfront\.net|akamai(?:hd|zed)?\.net|fastly\.net|amazonaws\.com)/i;

// Caminhos de plataforma servidos no MESMO domínio (ex.: HubSpot CMS/Membership).
const VENDOR_PATH_RE = /(?:\/_hcms\/|\/hs\/|\/hubfs\/|\/-dlb\/|-dlb\/static|\/hs-fs\/|\/__hs|\/wp-content\/plugins\/|\/wp-includes\/)/i;

// Nomes de vendor para rótulo amigável.
const VENDOR_LABELS = [
  [/hubspot|hsappstatic|hscollectedforms|hs-analytics|hsadspixel|_hcms|-dlb\/|hubfs/i, 'HubSpot'],
  [/cloudflare|cf_bm|cfuvid/i, 'Cloudflare'],
  [/linkedin|licdn|li\.lms|bcookie|lidc/i, 'LinkedIn'],
  [/google|gstatic|doubleclick|gtag|analytics/i, 'Google'],
  [/facebook|connect\.facebook/i, 'Meta/Facebook'],
  [/stripe/i, 'Stripe'],
  [/hotjar|clarity|segment|sentry|newrelic|datadog|intercom|zendesk/i, 'Analytics/Monitoring'],
  [/onetrust|cookiebot|cookielaw/i, 'Consent/Cookies'],
];

/**
 * Domínio registrável aproximado (últimos 2 labels). Sem PSL — cobre a maioria
 * dos casos .com/.net/.io. Casos tipo .co.uk não são tratados (aceitável aqui).
 */
export function registrableDomain(host) {
  if (!host) return '';
  const clean = host.replace(/^\.+/, '').toLowerCase();
  const parts = clean.split('.').filter(Boolean);
  if (parts.length <= 2) return clean;
  return parts.slice(-2).join('.');
}

/** Dois hosts pertencem ao mesmo domínio registrável? */
export function sameRegistrableDomain(hostA, hostB) {
  return !!hostA && !!hostB && registrableDomain(hostA) === registrableDomain(hostB);
}

function matchVendorLabel(str) {
  for (const [re, label] of VENDOR_LABELS) {
    if (re.test(str)) return label;
  }
  return 'Terceiro';
}

/**
 * Classifica um recurso (script/URL) como 1ª ou 3ª parte em relação à página.
 * @returns {{ thirdParty: boolean, vendor: string|null, reason: string }}
 */
export function classifyResource(resourceUrl, pageOrigin) {
  let host;
  try {
    host = new URL(resourceUrl).hostname;
  } catch {
    // Sem host (inline, data:, path relativo) → considerar 1ª parte por padrão.
    if (VENDOR_PATH_RE.test(resourceUrl || '')) {
      return { thirdParty: true, vendor: matchVendorLabel(resourceUrl), reason: 'vendor-path' };
    }
    return { thirdParty: false, vendor: null, reason: 'same-origin' };
  }

  let pageHost = '';
  try { pageHost = new URL(pageOrigin).hostname; } catch { /* ignore */ }

  // Host de vendor conhecido → 3ª parte.
  if (VENDOR_HOST_RE.test(host)) {
    return { thirdParty: true, vendor: matchVendorLabel(host), reason: 'vendor-host' };
  }

  // Domínio registrável diferente → 3ª parte.
  if (pageHost && !sameRegistrableDomain(host, pageHost)) {
    return { thirdParty: true, vendor: matchVendorLabel(host + ' ' + resourceUrl), reason: 'cross-domain' };
  }

  // Mesmo domínio, mas caminho de plataforma (ex.: HubSpot no seu domínio).
  if (VENDOR_PATH_RE.test(resourceUrl)) {
    return { thirdParty: true, vendor: matchVendorLabel(resourceUrl), reason: 'vendor-path' };
  }

  return { thirdParty: false, vendor: null, reason: 'first-party' };
}

/** Classifica um cookie pelo domínio dele vs a origem da página. */
export function classifyCookie(cookieDomain, pageOrigin) {
  let pageHost = '';
  try { pageHost = new URL(pageOrigin).hostname; } catch { /* ignore */ }
  const host = (cookieDomain || '').replace(/^\.+/, '');
  if (VENDOR_HOST_RE.test(host)) return { thirdParty: true, vendor: matchVendorLabel(host) };
  if (pageHost && !sameRegistrableDomain(host, pageHost)) {
    return { thirdParty: true, vendor: matchVendorLabel(host) };
  }
  return { thirdParty: false, vendor: null };
}

/**
 * Heurística de código minificado/empacotado. Nesses arquivos as regras
 * baseadas em rótulo (ex.: "password:") disparam falso-positivo, então o
 * chamador deve rodar apenas padrões de alta confiança.
 */
export function isMinified(source, url = '') {
  if (/\.min\.(?:js|css)(?:\?|$)/i.test(url)) return true;
  if (/\/static-\d|\/bundle|\.bundle\.|\.production\./i.test(url)) return true;
  if (!source || source.length < 2000) return false;
  const newlines = (source.match(/\n/g) || []).length;
  const avgLineLen = source.length / (newlines + 1);
  return avgLineLen > 300;
}
