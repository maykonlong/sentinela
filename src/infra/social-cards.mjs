/**
 * Social Cards Checker — Open Graph + Twitter Cards
 * Reimplementação em Node.js do social_checker.py do URL Checker.
 *
 * Extrai meta tags og: e twitter: do HTML para verificar
 * como o site aparece quando compartilhado em redes sociais.
 */

/**
 * Extrai meta tags Open Graph e Twitter Card do HTML.
 * @param {string} html - HTML completo da página
 * @param {string} targetUrl - URL do alvo (fallback para og:url)
 * @returns {object} Meta tags extraídas e status
 */
export function analyzeSocialCards(html, targetUrl) {
  if (!html) {
    return {
      status: 'INFO',
      has_social_cards: false,
      og_meta: {},
      twitter_meta: {},
    };
  }

  function getMeta(attrName, attrVal) {
    // Match <meta property="og:title" content="..."> ou <meta name="twitter:title" content="...">
    const pattern1 = new RegExp(
      `<meta[^>]*${attrName}=["']${attrVal}["'][^>]*content=["'](.*?)["']`,
      'i'
    );
    const match1 = html.match(pattern1);
    if (match1) return match1[1].trim();

    // Ordem inversa: <meta content="..." property="og:title">
    const pattern2 = new RegExp(
      `<meta[^>]*content=["'](.*?)["'][^>]*${attrName}=["']${attrVal}["']`,
      'i'
    );
    const match2 = html.match(pattern2);
    return match2 ? match2[1].trim() : null;
  }

  const ogTitle = getMeta('property', 'og:title') || getMeta('name', 'og:title');
  const ogDesc = getMeta('property', 'og:description') || getMeta('name', 'og:description');
  const ogImage = getMeta('property', 'og:image') || getMeta('name', 'og:image');
  const ogUrl = getMeta('property', 'og:url') || getMeta('name', 'og:url') || targetUrl;
  const ogSiteName = getMeta('property', 'og:site_name') || getMeta('name', 'og:site_name');
  const ogType = getMeta('property', 'og:type') || getMeta('name', 'og:type');

  const twitterCard = getMeta('name', 'twitter:card') || getMeta('property', 'twitter:card');
  const twitterTitle = getMeta('name', 'twitter:title') || getMeta('property', 'twitter:title') || ogTitle;
  const twitterDesc = getMeta('name', 'twitter:description') || getMeta('property', 'twitter:description') || ogDesc;
  const twitterImage = getMeta('name', 'twitter:image') || getMeta('property', 'twitter:image') || ogImage;
  const twitterSite = getMeta('name', 'twitter:site') || getMeta('property', 'twitter:site');

  const hasSocial = !!(ogTitle || ogImage || twitterTitle);

  // Extrair título e meta description da página
  const titleMatch = html.match(/<title[^>]*>(.*?)<\/title>/is);
  const pageTitle = titleMatch ? titleMatch[1].trim() : null;

  const descMatch = html.match(/<meta[^>]*name=["']description["'][^>]*content=["'](.*?)["']/i);
  const metaDesc = descMatch ? descMatch[1].trim() : null;

  return {
    status: hasSocial ? 'PASS' : 'INFO',
    has_social_cards: hasSocial,
    page_title: pageTitle,
    meta_description: metaDesc,
    og_meta: {
      title: ogTitle,
      description: ogDesc,
      image: ogImage,
      url: ogUrl,
      site_name: ogSiteName,
      type: ogType,
    },
    twitter_meta: {
      card: twitterCard,
      title: twitterTitle,
      description: twitterDesc,
      image: twitterImage,
      site: twitterSite,
    },
  };
}
