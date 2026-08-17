/**
 * DNSBL Reputation Check — Verificação de blacklists de IP
 * Reimplementação em Node.js do reputation_checker.py do URL Checker.
 *
 * Verifica o IP do alvo em listas de bloqueio DNS públicas
 * (Spamhaus, SpamCop, CBL, SORBS) para detectar flags de spam/phishing/malware.
 */

import dns from 'dns';

const BLACKLISTS = [
  'zen.spamhaus.org',
  'bl.spamcop.net',
  'cbl.abuseat.org',
  'dnsbl.sorbs.net',
  'b.barracudacentral.org',
  'spam.dnsbl.sorbs.net',
];

function queryDnsbl(reversedIp, bl) {
  return new Promise((resolve) => {
    const query = `${reversedIp}.${bl}`;
    dns.resolve4(query, (err) => {
      if (err) {
        resolve({ bl, listed: false }); // NXDOMAIN = não listado
      } else {
        resolve({ bl, listed: true }); // Resposta = listado!
      }
    });
  });
}

/**
 * Verifica o IP em múltiplas blacklists DNS públicas.
 * @param {string} targetIp - IPv4 do alvo
 * @param {string} targetHost - Hostname (para referência)
 * @returns {Promise<object>} Resultado com status, blacklists verificadas e achados
 */
export async function checkDnsblReputation(targetIp, targetHost) {
  if (!targetIp || targetIp.includes(':') || !targetIp.includes('.')) {
    return {
      status: 'INFO',
      is_blacklisted: false,
      blacklists_checked: 0,
      blacklists_flagged: [],
      note: 'IP não é IPv4 válido — verificação DNSBL não aplicável.',
    };
  }

  // Reverter os octetos do IP (ex: 1.2.3.4 → 4.3.2.1)
  const reversedIp = targetIp.split('.').reverse().join('.');

  const results = await Promise.all(
    BLACKLISTS.map(bl => queryDnsbl(reversedIp, bl))
  );

  const flagged = results.filter(r => r.listed).map(r => r.bl);

  const findings = [];
  if (flagged.length > 0) {
    findings.push({
      type: 'ip_blacklisted',
      severity: 'HIGH',
      thirdParty: false,
      label: `IP em ${flagged.length} blacklist(s)`,
      ip: targetIp,
      blacklists: flagged,
      risk: `O endereço IP ${targetIp} está listado em ${flagged.length} blacklist(s) públicas (${flagged.join(', ')}). Isso indica que o IP foi associado a spam, phishing ou atividade maliciosa, e pode causar bloqueio de e-mails e reputação negativa.`,
      recommendation: 'Investigar a causa da listagem. Se for um IP compartilhado (cloud), solicitar remoção. Se o servidor foi comprometido, realizar cleanup e solicitar delisting em cada DNSBL.',
    });
  }

  return {
    status: flagged.length > 0 ? 'FAIL' : 'PASS',
    is_blacklisted: flagged.length > 0,
    blacklists_checked: BLACKLISTS.length,
    blacklists_flagged: flagged,
    note: flagged.length === 0
      ? 'IP limpo — sem registros em listas de bloqueio públicas.'
      : `ALERTA: IP consta em ${flagged.length} lista(s) de bloqueio: ${flagged.join(', ')}`,
    findings,
  };
}
