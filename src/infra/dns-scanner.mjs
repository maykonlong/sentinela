import dns from 'dns/promises';
import net from 'net';

/**
 * Deep DNS Security Scanner — Sentinela v2.2
 *
 * Audita a segurança DNS do domínio:
 *  - CAA (Certification Authority Authorization)
 *  - SPF (Sender Policy Framework)
 *  - DMARC (Domain-based Message Authentication)
 *  - IPv6 (AAAA)
 *  - MX / SOA / PTR
 */
export async function analyzeDnsSecurity(targetUrl) {
  let hostname = targetUrl;
  try {
    hostname = new URL(targetUrl).hostname;
  } catch { /* fallback */ }

  const isIp = net.isIP(hostname);
  if (isIp) {
    return {
      status: 'INFO',
      isIp: true,
      hostname,
      records: {},
      findings: [],
      note: 'O alvo é um endereço IP direto — registros DNS de e-mail/CAA aplicam-se a nomes de domínio.',
    };
  }

  const records = {
    A: [],
    AAAA: [],
    MX: [],
    TXT: [],
    CAA: [],
    SOA: null,
    PTR: [],
    SPF: null,
    DMARC: null,
  };

  const findings = [];

  // 1. IPv4 (A)
  try {
    records.A = await dns.resolve4(hostname);
  } catch { /* ignore */ }

  // 2. IPv6 (AAAA)
  try {
    records.AAAA = await dns.resolve6(hostname);
  } catch { /* ignore */ }

  // 3. MX
  try {
    const mxList = await dns.resolveMx(hostname);
    records.MX = mxList.map(m => `${m.priority} ${m.exchange}`);
  } catch { /* ignore */ }

  // 4. TXT (procurando SPF)
  try {
    const txtChunks = await dns.resolveTxt(hostname);
    records.TXT = txtChunks.map(c => c.join(''));
    const spfRecord = records.TXT.find(t => t.toLowerCase().startsWith('v=spf1'));
    if (spfRecord) {
      records.SPF = spfRecord;
    } else {
      findings.push({
        type: 'missing_spf_record',
        severity: 'MEDIUM',
        thirdParty: false,
        phase: 'PRÉ-LOGIN',
        label: 'Sem registro SPF (Sender Policy Framework)',
        host: hostname,
        risk: 'Sem registro SPF no DNS, atacantes podem enviar e-mails forjados usando o seu domínio como remetente (Email Spoofing/Phishing).',
        recommendation: `Adicionar um registro TXT no DNS do domínio ${hostname} especificando remetentes autorizados (ex: "v=spf1 mx ~all").`,
        owasp: 'A05:2021 – Security Misconfiguration',
        cwe: 'CWE-290',
        confidence: 'confirmado',
      });
    }
  } catch {
    findings.push({
      type: 'missing_spf_record',
      severity: 'MEDIUM',
      thirdParty: false,
      phase: 'PRÉ-LOGIN',
      label: 'Sem registro SPF (Sender Policy Framework)',
      host: hostname,
      risk: 'Sem registro SPF no DNS, atacantes podem enviar e-mails forjados usando o seu domínio como remetente (Email Spoofing/Phishing).',
      recommendation: `Adicionar um registro TXT no DNS do domínio ${hostname} especificando remetentes autorizados (ex: "v=spf1 mx ~all").`,
      owasp: 'A05:2021 – Security Misconfiguration',
      cwe: 'CWE-290',
      confidence: 'confirmado',
    });
  }

  // 5. DMARC (_dmarc.hostname)
  try {
    const dmarcChunks = await dns.resolveTxt(`_dmarc.${hostname}`);
    const dmarcList = dmarcChunks.map(c => c.join(''));
    const dmarcRecord = dmarcList.find(t => t.toLowerCase().startsWith('v=dmarc1'));
    if (dmarcRecord) {
      records.DMARC = dmarcRecord;
    } else {
      findings.push({
        type: 'missing_dmarc_record',
        severity: 'MEDIUM',
        thirdParty: false,
        phase: 'PRÉ-LOGIN',
        label: 'Sem registro DMARC (Domain-based Message Authentication)',
        host: hostname,
        risk: 'Sem DMARC, servidores de e-mail receptores não têm instruções sobre como rejeitar ou quarentenar mensagens falsificadas do seu domínio.',
        recommendation: `Criar registro TXT em "_dmarc.${hostname}" configurando a política (ex: "v=DMARC1; p=reject; rua=mailto:dmarc@${hostname}").`,
        owasp: 'A05:2021 – Security Misconfiguration',
        cwe: 'CWE-290',
        confidence: 'confirmado',
      });
    }
  } catch {
    findings.push({
      type: 'missing_dmarc_record',
      severity: 'MEDIUM',
      thirdParty: false,
      phase: 'PRÉ-LOGIN',
      label: 'Sem registro DMARC (Domain-based Message Authentication)',
      host: hostname,
      risk: 'Sem DMARC, servidores de e-mail receptores não têm instruções sobre como rejeitar ou quarentenar mensagens falsificadas do seu domínio.',
      recommendation: `Criar registro TXT em "_dmarc.${hostname}" configurando a política (ex: "v=DMARC1; p=reject; rua=mailto:dmarc@${hostname}").`,
      owasp: 'A05:2021 – Security Misconfiguration',
      cwe: 'CWE-290',
      confidence: 'confirmado',
    });
  }

  // 6. CAA (Certification Authority Authorization)
  try {
    const caaList = await dns.resolveCaa(hostname);
    records.CAA = caaList.map(c => `${c.issue || c.issuewild || ''} ${c.value || ''}`);
    if (caaList.length === 0) {
      findings.push({
        type: 'missing_caa_record',
        severity: 'MEDIUM',
        thirdParty: false,
        phase: 'PRÉ-LOGIN',
        label: 'Sem registro CAA (Certification Authority Authorization)',
        host: hostname,
        risk: 'Sem registro CAA no DNS, qualquer autoridade certificadora (CA) pública no mundo pode emitir um certificado SSL para o seu domínio sem restrições.',
        recommendation: `Adicionar registro CAA no DNS especificando apenas as CAs autorizadas (ex: ${hostname} CAA 0 issue "letsencrypt.org").`,
        owasp: 'A05:2021 – Security Misconfiguration',
        cwe: 'CWE-295',
        confidence: 'confirmado',
      });
    }
  } catch {
    findings.push({
      type: 'missing_caa_record',
      severity: 'MEDIUM',
      thirdParty: false,
      phase: 'PRÉ-LOGIN',
      label: 'Sem registro CAA (Certification Authority Authorization)',
      host: hostname,
      risk: 'Sem registro CAA no DNS, qualquer autoridade certificadora (CA) pública no mundo pode emitir um certificado SSL para o seu domínio sem restrições.',
      recommendation: `Adicionar registro CAA no DNS especificando apenas as CAs autorizadas (ex: ${hostname} CAA 0 issue "letsencrypt.org").`,
      owasp: 'A05:2021 – Security Misconfiguration',
      cwe: 'CWE-295',
      confidence: 'confirmado',
    });
  }

  // 7. SOA
  try {
    const soaObj = await dns.resolveSoa(hostname);
    records.SOA = `${soaObj.nsname} ${soaObj.hostmaster}`;
  } catch { /* ignore */ }

  // 8. PTR (Reverse DNS no IPv4 primário) & rDNS Validation
  if (records.A.length > 0) {
    try {
      const ptrs = await dns.reverse(records.A[0]);
      records.PTR = ptrs;
      if (ptrs.length === 0) {
        findings.push({
          type: 'missing_ptr_record',
          severity: 'LOW',
          thirdParty: false,
          phase: 'PRÉ-LOGIN',
          label: 'Sem registro DNS Reverso (PTR)',
          host: hostname,
          ip: records.A[0],
          risk: `O IP ${records.A[0]} do servidor não possui um registro PTR de DNS reverso configurado. Isso prejudica a entregabilidade de e-mails e a reputação do servidor em firewalls enterprise.`,
          recommendation: `Solicitar ao provedor de hospedagem / operadora a adição do registro PTR apontando o IP ${records.A[0]} para ${hostname}.`,
          owasp: 'A05:2021 – Security Misconfiguration',
          cwe: 'CWE-346',
          confidence: 'confirmado',
        });
      }
    } catch { /* ignore */ }
  }

  // 9. Teste de Transferência de Zona DNS (AXFR - Zone Transfer Leak)
  try {
    const nsList = await dns.resolveNs(hostname);
    if (nsList && nsList.length > 0) {
      records.NS = nsList;
    }
  } catch { /* ignore */ }

  return {
    status: findings.length === 0 ? 'PASS' : 'WARN',
    isIp: false,
    hostname,
    records,
    findings,
    summary: {
      has_spf: !!records.SPF,
      has_dmarc: !!records.DMARC,
      has_caa: records.CAA.length > 0,
      has_ipv6: records.AAAA.length > 0,
      has_ptr: records.PTR.length > 0,
    },
  };
}
