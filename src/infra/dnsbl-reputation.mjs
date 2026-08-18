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

// Faixas RFC1918 / loopback / link-local / CGNAT: IPs que nunca aparecem em
// DNSBL pública. Consultar "20.0.4.10.zen.spamhaus.org" para 10.4.0.20 é ruído.
function isPrivateIpv4(ip) {
  const o = ip.split('.').map(Number);
  if (o.length !== 4 || o.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  if (o[0] === 10) return true;                                  // 10.0.0.0/8
  if (o[0] === 127) return true;                                 // loopback
  if (o[0] === 0) return true;                                   // 0.0.0.0/8
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true;     // 172.16.0.0/12
  if (o[0] === 192 && o[1] === 168) return true;                 // 192.168.0.0/16
  if (o[0] === 169 && o[1] === 254) return true;                 // link-local
  if (o[0] === 100 && o[1] >= 64 && o[1] <= 127) return true;    // CGNAT 100.64/10
  if (o[0] >= 224) return true;                                  // multicast/reservado
  return false;
}

// Erros que provam ausência na lista (o servidor respondeu "não existe").
const ABSENT_ERR_CODES = new Set(['ENOTFOUND', 'ENODATA']);

/**
 * Consulta uma DNSBL e CLASSIFICA a resposta.
 *
 * Antes, qualquer resolução bem-sucedida era tratada como "listado" sem olhar o
 * registro A. Spamhaus/Barracuda respondem 127.255.255.252/254 para dizer
 * "query recusada — resolver público / cota excedida"; isso resolve com SUCESSO
 * e gerava um finding ip_blacklisted HIGH totalmente inventado sempre que a
 * consulta saía via Google DNS/Cloudflare ou de dentro da rede corporativa.
 * Simetricamente, SERVFAIL/timeout era lido como "IP limpo" (falso negativo).
 *
 * @returns {Promise<{bl:string, state:'LISTED'|'CLEAN'|'REFUSED'|'UNKNOWN', addresses?:string[], errCode?:string}>}
 */
function queryDnsbl(reversedIp, bl) {
  return new Promise((resolve) => {
    const query = `${reversedIp}.${bl}`;
    dns.resolve4(query, (err, addresses) => {
      if (err) {
        // Só NXDOMAIN/NODATA significam "não listado". Qualquer outro erro
        // (SERVFAIL, ETIMEOUT, EREFUSED, ECONNREFUSED...) é indeterminado.
        if (ABSENT_ERR_CODES.has(err.code)) {
          resolve({ bl, state: 'CLEAN', errCode: err.code });
        } else {
          resolve({ bl, state: 'UNKNOWN', errCode: err.code });
        }
        return;
      }

      const addrs = addresses || [];
      // 127.255.255.x = código de erro da própria DNSBL (query recusada,
      // resolver público bloqueado, cota excedida) — NÃO é listagem.
      const refused = addrs.some(a => a.startsWith('127.255.255.'));
      // Listagem legítima usa 127.0.0.x (Spamhaus 127.0.0.2-11, SORBS,
      // SpamCop, Barracuda, CBL — todos nessa faixa).
      const listedAddrs = addrs.filter(a => /^127\.0\.0\.\d{1,3}$/.test(a));

      if (listedAddrs.length > 0) {
        resolve({ bl, state: 'LISTED', addresses: listedAddrs });
      } else if (refused) {
        resolve({ bl, state: 'REFUSED', addresses: addrs });
      } else {
        // Resposta fora de qualquer faixa conhecida: não dá para afirmar nada.
        resolve({ bl, state: 'UNKNOWN', addresses: addrs });
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
      blacklists_unknown: [],
      not_applicable: true,
      note: 'IP não é IPv4 válido — verificação DNSBL não aplicável.',
      findings: [],
    };
  }

  // IP privado/reservado: DNSBL não se aplica (nenhuma lista pública indexa
  // RFC1918). Sem esse guard, o alvo de LAN 10.4.0.20 gerava 6 consultas
  // inúteis cujas respostas de erro eram lidas como "IP limpo / PASS".
  if (isPrivateIpv4(targetIp)) {
    return {
      status: 'INFO',
      is_blacklisted: false,
      blacklists_checked: 0,
      blacklists_flagged: [],
      blacklists_unknown: [],
      not_applicable: true,
      note: `IP ${targetIp} é privado/reservado (RFC1918 ou equivalente) — blacklists públicas não indexam esse espaço. Verificação não aplicável.`,
      findings: [],
    };
  }

  // Reverter os octetos do IP (ex: 1.2.3.4 → 4.3.2.1)
  const reversedIp = targetIp.split('.').reverse().join('.');

  const results = await Promise.all(
    BLACKLISTS.map(bl => queryDnsbl(reversedIp, bl))
  );

  const flagged = results.filter(r => r.state === 'LISTED').map(r => r.bl);
  const clean = results.filter(r => r.state === 'CLEAN').map(r => r.bl);
  // REFUSED (127.255.255.x) e UNKNOWN (SERVFAIL/timeout) são o MESMO caso do
  // ponto de vista do relatório: não verificado. Nunca viram listagem nem PASS.
  const unknown = results
    .filter(r => r.state === 'REFUSED' || r.state === 'UNKNOWN')
    .map(r => ({ bl: r.bl, reason: r.state === 'REFUSED' ? 'query recusada pela DNSBL (resolver público/cota)' : (r.errCode || 'resposta inesperada') }));

  const findings = [];
  if (flagged.length > 0) {
    findings.push({
      type: 'ip_blacklisted',
      severity: 'HIGH',
      thirdParty: false,
      label: `IP em ${flagged.length} blacklist(s)`,
      ip: targetIp,
      blacklists: flagged,
      // Evidência explícita: só entra aqui quem devolveu 127.0.0.x.
      evidence: results.filter(r => r.state === 'LISTED').map(r => `${r.bl} → ${(r.addresses || []).join(', ')}`),
      risk: `O endereço IP ${targetIp} está listado em ${flagged.length} blacklist(s) públicas (${flagged.join(', ')}). Isso indica que o IP foi associado a spam, phishing ou atividade maliciosa, e pode causar bloqueio de e-mails e reputação negativa.`,
      recommendation: 'Investigar a causa da listagem. Se for um IP compartilhado (cloud), solicitar remoção. Se o servidor foi comprometido, realizar cleanup e solicitar delisting em cada DNSBL.',
    });
  }

  // PASS só quando TODAS as listas responderam de forma conclusiva. Havendo
  // qualquer consulta indeterminada, o resultado é parcial (INFO), não "limpo".
  let status;
  if (flagged.length > 0) status = 'FAIL';
  else if (unknown.length === 0) status = 'PASS';
  else if (clean.length === 0) status = 'INFO';
  else status = 'INFO';

  let note;
  if (flagged.length > 0) {
    note = `ALERTA: IP consta em ${flagged.length} lista(s) de bloqueio: ${flagged.join(', ')}`;
    if (unknown.length > 0) note += ` · ${unknown.length} lista(s) não verificada(s).`;
  } else if (unknown.length === 0) {
    note = 'IP limpo — sem registros em listas de bloqueio públicas.';
  } else if (clean.length === 0) {
    note = `Reputação NÃO VERIFICADA: nenhuma das ${BLACKLISTS.length} blacklists respondeu de forma conclusiva (${unknown.map(u => u.bl + ': ' + u.reason).join('; ')}).`;
  } else {
    note = `Sem listagem nas ${clean.length} lista(s) que responderam; ${unknown.length} não verificada(s) (${unknown.map(u => u.bl).join(', ')}).`;
  }

  return {
    status,
    is_blacklisted: flagged.length > 0,
    blacklists_checked: BLACKLISTS.length,
    blacklists_conclusive: clean.length + flagged.length,
    blacklists_flagged: flagged,
    blacklists_clean: clean,
    blacklists_unknown: unknown,
    note,
    findings,
  };
}
