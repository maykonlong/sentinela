import dns from 'dns/promises';
import net from 'net';

// Códigos que provam AUSÊNCIA do registro (o DNS respondeu "não existe").
// Qualquer outro código (SERVFAIL, ETIMEOUT, EREFUSED, ECONNREFUSED, EBADRESP…)
// significa "não consegui consultar" e NUNCA pode virar finding: antes, cada
// bloco try/catch emitia o MESMO finding no catch e no caminho de ausência real,
// com confidence:'confirmado' — um resolver corporativo bloqueando TXT fazia o
// relatório afirmar "Sem registro SPF/DMARC/CAA" como fato.
const ABSENT_CODES = new Set(['ENOTFOUND', 'ENODATA']);
const isAbsence = (e) => ABSENT_CODES.has(e && e.code);
const errCode = (e) => (e && e.code) || 'ERRO_DESCONHECIDO';

// Sufixos públicos de dois rótulos mais comuns nos alvos deste projeto (BR/LATAM
// e alguns internacionais). Usado só para decidir escopo, não para validação.
const MULTI_LABEL_SUFFIXES = new Set([
  'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br', 'ind.br', 'app.br',
  'com.co', 'com.mx', 'com.ar', 'com.pe', 'com.uy', 'com.py',
  'co.uk', 'org.uk', 'ac.uk', 'com.au', 'net.au', 'co.jp', 'co.nz',
  'com.pt', 'com.es', 'com.tr', 'co.za',
]);

/**
 * Heurística de "domínio registrável" (organizacional).
 * `cmsw.com` → true · `bancopopular-corner-stg-col.cmsw.com` → false
 */
function isRegistrableDomain(host) {
  const labels = host.split('.').filter(Boolean);
  if (labels.length <= 2) return true;
  if (labels.length === 3 && MULTI_LABEL_SUFFIXES.has(labels.slice(1).join('.'))) return true;
  return false;
}

/** Cadeia de domínios do host até o domínio registrável (inclusive). */
function domainChain(host) {
  const chain = [];
  let current = host;
  // Guard de 10 níveis só para não girar em nome malformado.
  for (let i = 0; i < 10; i++) {
    chain.push(current);
    if (isRegistrableDomain(current)) break;
    const next = current.split('.').slice(1).join('.');
    if (!next || next === current) break;
    current = next;
  }
  return chain;
}

/**
 * Deep DNS Security Scanner — Sentinela v2.2
 *
 * Audita a segurança DNS do domínio:
 *  - CAA (Certification Authority Authorization)
 *  - SPF (Sender Policy Framework)
 *  - DMARC (Domain-based Message Authentication)
 *  - IPv6 (AAAA)
 *  - MX / SOA / PTR / NS
 *
 * Regra de ouro: consulta que falhou por erro de rede/resolver entra em
 * `not_verified` e NÃO gera finding. Registro fora de escopo (ex.: SPF/DMARC
 * em subdomínio de app web sem MX) entra em `not_applicable`.
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
      not_verified: [],
      not_applicable: [
        { record: 'SPF', reason: 'alvo é IP literal' },
        { record: 'DMARC', reason: 'alvo é IP literal' },
        { record: 'CAA', reason: 'alvo é IP literal' },
      ],
      axfr_tested: false,
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
  // Consultas que não puderam ser feitas (erro de rede/resolver) e checagens
  // que não se aplicam ao alvo. Ambas ficam FORA de findings.
  const notVerified = [];
  const notApplicable = [];

  // 1. IPv4 (A)
  try {
    records.A = await dns.resolve4(hostname);
  } catch (e) {
    if (!isAbsence(e)) notVerified.push({ record: 'A', reason: errCode(e) });
  }

  // 2. IPv6 (AAAA)
  try {
    records.AAAA = await dns.resolve6(hostname);
  } catch (e) {
    if (!isAbsence(e)) notVerified.push({ record: 'AAAA', reason: errCode(e) });
  }

  // 3. MX — define o escopo de e-mail. Um subdomínio de app web sem MX não
  // envia e-mail, logo SPF/DMARC nele não são achados de segurança.
  let mxState = 'ABSENT';
  try {
    const mxList = await dns.resolveMx(hostname);
    records.MX = mxList.map(m => `${m.priority} ${m.exchange}`);
    if (records.MX.length > 0) mxState = 'PRESENT';
  } catch (e) {
    if (!isAbsence(e)) {
      mxState = 'UNKNOWN';
      notVerified.push({ record: 'MX', reason: errCode(e) });
    }
  }

  const registrable = isRegistrableDomain(hostname);
  // SPF/DMARC só fazem sentido se o host recebe/envia e-mail (tem MX) ou se é o
  // próprio domínio organizacional (onde a política de e-mail é publicada).
  // Sem esse gate, `bancopopular-corner-stg-col.cmsw.com` (subdomínio de app,
  // sem MX) rendia 2 MEDIUM estruturalmente falsos em todo relatório.
  const emailScope = mxState === 'PRESENT' || registrable;
  const emailScopeUnknown = mxState === 'UNKNOWN' && !registrable;

  // 4. TXT (procurando SPF)
  // O lookup é sempre feito (o registro TXT vai pro relatório de qualquer jeito);
  // o que o escopo controla é só a emissão do finding.
  let txtState = 'ABSENT';
  let txtErr = null;
  try {
    const txtChunks = await dns.resolveTxt(hostname);
    records.TXT = txtChunks.map(c => c.join(''));
    const spfRecord = records.TXT.find(t => t.toLowerCase().startsWith('v=spf1'));
    if (spfRecord) {
      records.SPF = spfRecord;
      txtState = 'PRESENT';
    }
  } catch (e) {
    if (!isAbsence(e)) {
      txtState = 'UNKNOWN';
      txtErr = errCode(e);
    }
  }

  if (!records.SPF) {
    if (txtState === 'UNKNOWN') {
      // Timeout/SERVFAIL na consulta TXT: não dá para afirmar ausência de SPF.
      notVerified.push({ record: 'SPF', reason: txtErr });
    } else if (emailScopeUnknown) {
      notVerified.push({ record: 'SPF', reason: 'escopo indeterminado (consulta MX falhou)' });
    } else if (!emailScope) {
      notApplicable.push({
        record: 'SPF',
        reason: `${hostname} não possui MX e não é o domínio registrável — não envia e-mail; a política SPF pertence ao domínio organizacional.`,
      });
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
  }

  // 5. DMARC (_dmarc.hostname, com fallback no domínio organizacional)
  // O DMARC é publicado no domínio organizacional e herdado pelos subdomínios
  // (RFC 7489 §6.6.3). Consultar só "_dmarc.<subdominio>" e concluir ausência
  // era falso: o domínio pai pode ter p=reject cobrindo o host inteiro.
  const dmarcChain = registrable ? [hostname] : [hostname, domainChain(hostname).slice(-1)[0]];
  let dmarcState = 'ABSENT';
  let dmarcErr = null;
  let dmarcHost = null;
  for (const h of dmarcChain) {
    try {
      const dmarcChunks = await dns.resolveTxt(`_dmarc.${h}`);
      const dmarcRecord = dmarcChunks
        .map(c => c.join(''))
        .find(t => t.toLowerCase().startsWith('v=dmarc1'));
      if (dmarcRecord) {
        records.DMARC = dmarcRecord;
        dmarcState = 'PRESENT';
        dmarcHost = h;
        break;
      }
    } catch (e) {
      if (!isAbsence(e)) {
        dmarcState = 'UNKNOWN';
        dmarcErr = errCode(e);
      }
    }
  }
  records.DMARC_HOST = dmarcHost;

  if (!records.DMARC) {
    if (dmarcState === 'UNKNOWN') {
      notVerified.push({ record: 'DMARC', reason: dmarcErr });
    } else if (emailScopeUnknown) {
      notVerified.push({ record: 'DMARC', reason: 'escopo indeterminado (consulta MX falhou)' });
    } else if (!emailScope) {
      notApplicable.push({
        record: 'DMARC',
        reason: `${hostname} não possui MX e não é o domínio registrável — a política DMARC é publicada no domínio organizacional.`,
      });
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
  }

  // 6. CAA (Certification Authority Authorization)
  // A CA resolve CAA subindo a árvore (RFC 8659 §3): se o domínio pai tem CAA,
  // o subdomínio ESTÁ protegido. Consultar só o host e concluir ausência gerava
  // um MEDIUM falso em qualquer subdomínio de app.
  const caaChain = domainChain(hostname);
  let caaState = 'ABSENT';
  let caaErr = null;
  let caaHost = null;
  for (const h of caaChain) {
    try {
      const caaList = await dns.resolveCaa(h);
      if (caaList && caaList.length > 0) {
        records.CAA = caaList.map(c => `${c.issue || c.issuewild || ''} ${c.value || ''}`);
        caaState = 'PRESENT';
        caaHost = h;
        break;
      }
    } catch (e) {
      if (!isAbsence(e)) {
        caaState = 'UNKNOWN';
        caaErr = errCode(e);
      }
    }
  }
  records.CAA_HOST = caaHost;

  if (records.CAA.length === 0) {
    if (caaState === 'UNKNOWN') {
      // Resolver bloqueou/timeout em algum nível: ausência não foi comprovada.
      notVerified.push({ record: 'CAA', reason: caaErr });
    } else {
      findings.push({
        type: 'missing_caa_record',
        severity: 'MEDIUM',
        thirdParty: false,
        phase: 'PRÉ-LOGIN',
        label: 'Sem registro CAA (Certification Authority Authorization)',
        host: hostname,
        checked_domains: caaChain,
        risk: `Sem registro CAA no DNS (verificado em ${caaChain.join(', ')}), qualquer autoridade certificadora (CA) pública no mundo pode emitir um certificado SSL para o seu domínio sem restrições.`,
        recommendation: `Adicionar registro CAA no DNS do domínio organizacional especificando apenas as CAs autorizadas (ex: ${caaChain[caaChain.length - 1]} CAA 0 issue "letsencrypt.org").`,
        owasp: 'A05:2021 – Security Misconfiguration',
        cwe: 'CWE-295',
        confidence: 'confirmado',
      });
    }
  }

  // 7. SOA
  try {
    const soaObj = await dns.resolveSoa(hostname);
    records.SOA = `${soaObj.nsname} ${soaObj.hostmaster}`;
  } catch (e) {
    if (!isAbsence(e)) notVerified.push({ record: 'SOA', reason: errCode(e) });
  }

  // 8. PTR (Reverse DNS no IPv4 primário) & rDNS Validation
  // dns.reverse() LANÇA ENOTFOUND quando não há PTR — nunca devolve array vazio.
  // O catch antigo engolia isso, deixando o ramo `ptrs.length === 0` inalcançável
  // e o finding missing_ptr_record nunca disparava (falso negativo silencioso).
  if (records.A.length > 0) {
    let ptrAbsent = false;
    try {
      const ptrs = await dns.reverse(records.A[0]);
      records.PTR = ptrs || [];
      ptrAbsent = records.PTR.length === 0;
    } catch (e) {
      if (isAbsence(e)) {
        ptrAbsent = true; // ausência real de PTR
      } else {
        notVerified.push({ record: 'PTR', reason: errCode(e) });
      }
    }

    if (ptrAbsent) {
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
  }

  // 9. Enumeração dos servidores autoritativos (NS).
  // ATENÇÃO: aqui NÃO há teste de AXFR. O comentário anterior dizia
  // "Teste de Transferência de Zona DNS (AXFR - Zone Transfer Leak)", mas o
  // código só faz resolveNs — nenhuma transferência de zona é tentada. O texto
  // foi corrigido para não afirmar um teste que nunca foi executado.
  try {
    const nsList = await dns.resolveNs(hostname);
    if (nsList && nsList.length > 0) {
      records.NS = nsList;
    }
  } catch (e) {
    if (!isAbsence(e)) notVerified.push({ record: 'NS', reason: errCode(e) });
  }

  // PASS só quando tudo que se aplica foi de fato verificado. Com consultas
  // indeterminadas o resultado é parcial (INFO) — nunca "tudo certo".
  let status;
  if (findings.length > 0) status = 'WARN';
  else if (notVerified.length > 0) status = 'INFO';
  else status = 'PASS';

  // Estado por registro, para o relatório poder distinguir os três casos em vez
  // de renderizar tudo que não é `true` como "⚠️ Ausente".
  const stateOf = (name, present) => {
    if (present) return 'ok';
    if (notVerified.some(n => n.record === name)) return 'nao_verificado';
    if (notApplicable.some(n => n.record === name)) return 'nao_aplicavel';
    return 'ausente';
  };

  return {
    status,
    isIp: false,
    hostname,
    is_registrable_domain: registrable,
    has_mx: mxState === 'PRESENT',
    email_scope: emailScope,
    records,
    findings,
    not_verified: notVerified,
    not_applicable: notApplicable,
    axfr_tested: false, // nenhum teste de transferência de zona é executado
    summary: {
      has_spf: !!records.SPF,
      has_dmarc: !!records.DMARC,
      has_caa: records.CAA.length > 0,
      has_ipv6: records.AAAA.length > 0,
      has_ptr: records.PTR.length > 0,
      spf_state: stateOf('SPF', !!records.SPF),
      dmarc_state: stateOf('DMARC', !!records.DMARC),
      caa_state: stateOf('CAA', records.CAA.length > 0),
      ptr_state: stateOf('PTR', records.PTR.length > 0),
      caa_inherited_from: caaHost && caaHost !== hostname ? caaHost : null,
      dmarc_inherited_from: dmarcHost && dmarcHost !== hostname ? dmarcHost : null,
    },
  };
}
