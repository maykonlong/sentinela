/**
 * GeoIP Lookup — Localização geográfica do servidor
 * Reimplementação em Node.js do geoip_checker.py do URL Checker.
 *
 * Consulta ip-api.com para obter país, cidade, ISP, organização e ASN.
 */

/**
 * Consulta informações geográficas de um IPv4.
 * @param {string} ipv4 - Endereço IP do alvo
 * @returns {Promise<object>} Informações de GeoIP
 */
export async function lookupGeoIP(ipv4) {
  if (!ipv4) {
    return {
      status: 'WARN', country: 'Desconhecido', country_code: '',
      city: 'Desconhecido', isp: 'Desconhecido',
      organization: 'Desconhecido', asn: 'Desconhecido',
    };
  }

  try {
    const url = `http://ip-api.com/json/${ipv4}?fields=status,country,countryCode,city,isp,org,as,query`;
    const res = await fetch(url, {
      headers: { 'User-Agent': 'Sentinela/1.0' },
      signal: AbortSignal.timeout(4000),
    });
    const data = await res.json();

    if (data.status === 'success') {
      return {
        status: 'PASS',
        ip: ipv4,
        country: data.country || 'Desconhecido',
        country_code: data.countryCode || '',
        city: data.city || 'Desconhecido',
        isp: data.isp || 'Desconhecido',
        organization: data.org || 'Desconhecido',
        asn: data.as || 'Desconhecido',
      };
    }
  } catch {
    // API indisponível ou timeout
  }

  return {
    status: 'INFO',
    ip: ipv4,
    country: 'Desconhecido', country_code: '',
    city: 'Desconhecido', isp: 'Desconhecido',
    organization: 'Desconhecido', asn: 'Desconhecido',
  };
}
