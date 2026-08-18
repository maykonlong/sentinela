/**
 * TCP Port Scanner — Varredura de portas enterprise
 * Reimplementação em Node.js do tcp_checker.py do URL Checker.
 *
 * Escaneia 30 portas comuns (web, DB, cache, SSH, RDP) de forma concorrente
 * usando net.Socket com timeout configurável.
 *
 * Estratégia anti-falso-positivo:
 * - Timeout 1200ms (evita FILTERED virar OPEN em redes lentas)
 * - Dupla confirmação: porta detectada como OPEN é checada uma segunda vez
 * - "Não consegui testar" NUNCA vira CLOSED: erros de rede/recurso viram UNKNOWN
 *   e ficam fora do relatório (contabilizados como não verificados).
 *
 * NOTA sobre latência (regra removida): a versão antiga marcava como UNCERTAIN
 * qualquer conexão com latência < 3ms, supondo "RST imediato = falso OPEN".
 * A premissa é tecnicamente errada: um RST dispara o evento 'error'
 * (ECONNREFUSED), nunca 'connect'. Receber 'connect' significa handshake TCP
 * completo, ou seja, porta genuinamente aberta. Em LAN (ex.: alvo 10.4.0.20,
 * RTT sub-milissegundo) TODA porta aberta caía nessa regra nas duas passadas e
 * era reclassificada como CLOSED — o scanner reportava a própria porta 8443 do
 * app como fechada, com hasWebPort=false e status 'FAIL'.
 */

import net from 'net';

const PORT_SERVICES = {
  80:    'HTTP (Web Server)',
  443:   'HTTPS (Web Server Seguro)',
  8080:  'HTTP-Alt (Proxy / Web)',
  8443:  'HTTPS-Alt (Web Seguro)',
  3000:  'Node.js / React App',
  5000:  'Flask / Python Web',
  8000:  'FastAPI / Django',
  8888:  'Jupyter / Web Console',
  9000:  'PHP-FPM / MinIO',
  21:    'FTP (Transferência de Arquivos)',
  22:    'SSH (Acesso Remoto)',
  23:    'Telnet (Não Seguro)',
  25:    'SMTP (Servidor de E-mail)',
  53:    'DNS (Resolução de Nomes)',
  110:   'POP3 (E-mail)',
  143:   'IMAP (E-mail)',
  465:   'SMTPS (E-mail Seguro)',
  587:   'SMTP Submission',
  993:   'IMAPS (E-mail Seguro)',
  995:   'POP3S (E-mail Seguro)',
  1433:  'MS SQL Server',
  3306:  'MySQL Database',
  3389:  'RDP (Área de Trabalho Remota)',
  5432:  'PostgreSQL Database',
  5672:  'RabbitMQ Broker',
  6379:  'Redis Cache',
  9200:  'Elasticsearch',
  11211: 'Memcached',
  27017: 'MongoDB Database',
};

// Portas que, se abertas, representam risco de segurança
const DANGEROUS_PORTS = new Set([
  3306, 5432, 27017, 6379, 9200, 11211, 1433, 5672,
  21, 22, 23, 3389, 8888,
]);

// Erros que provam que a porta está fechada (a pilha TCP do alvo respondeu).
// Qualquer outro erro significa "não consegui testar", não "porta fechada".
const CLOSED_ERR_CODES = new Set(['ECONNREFUSED', 'ECONNRESET']);

/**
 * Tenta conectar a uma porta. Retorna OPEN, CLOSED, FILTERED ou UNKNOWN.
 * - OPEN     = handshake TCP completo (evento 'connect')
 * - CLOSED   = alvo respondeu recusando (ECONNREFUSED/ECONNRESET)
 * - FILTERED = timeout sem resposta
 * - UNKNOWN  = não foi possível testar (rota/permissão/recurso local)
 */
function checkPort(host, port, timeout = 1200) {
  return new Promise((resolve) => {
    const service = PORT_SERVICES[port] || 'Custom Service';
    const start = Date.now();
    const sock = new net.Socket();
    sock.setTimeout(timeout);

    sock.on('connect', () => {
      const latency = Date.now() - start;
      
      // Tentar capturar o Banner do serviço (SSH, FTP, SMTP, MySQL, etc.)
      let banner = '';
      const onData = (data) => {
        banner = data.toString('utf-8').trim().replace(/[\r\n]+/g, ' ');
      };
      sock.on('data', onData);

      // Esperar brevemente (250ms) por banner espontâneo
      setTimeout(() => {
        sock.destroy();
        // Handshake completo = OPEN, independente da latência. Não há mais
        // downgrade por latência baixa (ver nota no cabeçalho do arquivo).
        resolve({ port, service, state: 'OPEN', latency_ms: latency, banner: banner ? banner.substring(0, 120) : null });
      }, 250);
    });

    sock.on('timeout', () => {
      const latency = Date.now() - start;
      sock.destroy();
      resolve({ port, service, state: 'FILTERED', latency_ms: latency });
    });

    sock.on('error', (err) => {
      const latency = Date.now() - start;
      sock.destroy();
      // Só ECONNREFUSED/ECONNRESET provam porta fechada: o host respondeu RST.
      // EHOSTUNREACH/ENETUNREACH/EACCES/EMFILE/ENFILE/EADDRNOTAVAIL são falhas do
      // nosso lado ou da rota — antes viravam CLOSED, ou seja, "não consegui
      // testar" era relatado como "porta fechada" (e, somado ao bug de latência,
      // fazia o alvo inteiro virar status FAIL sem nenhum teste válido).
      const state = CLOSED_ERR_CODES.has(err.code) ? 'CLOSED' : 'UNKNOWN';
      resolve({ port, service, state, latency_ms: latency, errCode: err.code });
    });

    sock.connect(port, host);
  });
}

/**
 * Dupla confirmação para portas detectadas como OPEN na primeira passada.
 *
 * A primeira passada já provou o handshake TCP; a segunda serve apenas para
 * reforçar (confirmed=true), NUNCA para apagar a evidência. Antes, qualquer
 * segunda tentativa não-OPEN reclassificava a porta como CLOSED — bastava um
 * timeout, um rate-limit do serviço ou um restart momentâneo para o app sumir
 * do relatório (e, com a antiga regra de latência, isso acontecia em 100% das
 * portas em rede local).
 */
async function confirmPort(host, port, firstLatency) {
  const result = await checkPort(host, port, 1200);
  if (result.state === 'OPEN') {
    return {
      state: 'OPEN',
      latency_ms: Math.round((firstLatency + result.latency_ms) / 2),
      confirmed: true,
      inconsistent: false,
    };
  }
  // Divergência entre as passadas: mantemos OPEN (o handshake aconteceu de
  // fato), mas sinalizamos que a confirmação não fechou.
  return {
    state: 'OPEN',
    latency_ms: firstLatency,
    confirmed: false,
    inconsistent: true,
    secondPassState: result.state,
    secondPassErr: result.errCode || null,
  };
}

/**
 * Retorna gravidade, risco detalhado e recomendação de segurança para qualquer porta TCP.
 */
export function getPortSecurityAdvice(port, service) {
  const isDb = [3306, 5432, 27017, 1433, 9200, 11211].includes(port);
  const isCache = [6379, 11211].includes(port);
  const isRemote = [22, 23, 3389].includes(port);
  const isWebApp = [3000, 5000, 8000, 8888, 9000].includes(port);
  const isWebStandard = [80, 443, 8080, 8443].includes(port);
  const isMail = [21, 25, 110, 143, 465, 587, 993, 995].includes(port);

  if (isDb) {
    return {
      severity: 'HIGH',
      risk: `A porta ${port} (${service}) é um banco de dados exposto publicamente. Permite força bruta em senhas de admin e exfiltração/injeção de dados.`,
      recommendation: `Bloquear porta ${port} no firewall externo. Permitir conexões apenas via bind 127.0.0.1 ou rede privada interna / VPN.`,
    };
  }
  if (isCache) {
    return {
      severity: 'HIGH',
      risk: `A porta ${port} (${service}) é um serviço de cache exposto. Caches sem autenticação permitem leitura/escrita de sessões e roubo de dados.`,
      recommendation: `Fechar a porta ${port} no firewall público. Configurar bind 127.0.0.1 e exigir senha de autenticação (requirepass).`,
    };
  }
  if (isRemote) {
    return {
      severity: 'MEDIUM',
      risk: `A porta ${port} (${service}) é um acesso remoto exposto na internet. Alvo constante de robôs de força bruta e exploração de ransomware.`,
      recommendation: `Restringir acesso à porta ${port} por IP no firewall (whitelist). Exigir chave SSH (sem senha) ou acesso via VPN.`,
    };
  }
  if (isWebApp) {
    return {
      severity: 'MEDIUM',
      risk: `A porta ${port} (${service}) é um app/ambiente de desenvolvimento exposto diretamente, sem camada de WAF, rate limit ou TLS nativo.`,
      recommendation: `Colocar um Reverse Proxy (Nginx / Cloudflare) na frente da aplicação e bloquear o acesso externo direto à porta ${port}.`,
    };
  }
  if (isMail) {
    return {
      severity: 'LOW',
      risk: `A porta ${port} (${service}) é um serviço de e-mail/transferência exposto. Pode ser alvo de relay de spam se sem autenticação forte.`,
      recommendation: `Exigir autenticação forte, desabilitar portas legadas não criptografadas e impor TLS obrigatório.`,
    };
  }
  if (isWebStandard) {
    return {
      severity: 'INFO',
      risk: port === 80
        ? `Porta HTTP pública. Tráfego não criptografado transmite credenciais/cookies em texto claro.`
        : `Porta Web padrão exposta para tráfego HTTPS/HTTP.`,
      recommendation: port === 80
        ? `Configurar redirecionamento automático 301 de HTTP para HTTPS (porta 443) e ativar o cabeçalho HSTS.`
        : `Manter certificados TLS atualizados e aplicar cabeçalhos de segurança (CSP, HSTS, X-Content-Type-Options).`,
    };
  }
  return {
    severity: 'LOW',
    risk: `A porta ${port} (${service}) está aberta publicamente e expande a superfície de ataque do servidor.`,
    recommendation: `Avaliar se a porta ${port} precisa estar aberta externamente. Fechar portas desnecessárias no firewall.`,
  };
}

/**
 * Escaneia as portas enterprise de forma concorrente.
 * @param {string} host - IP ou hostname do alvo
 * @param {number[]} [customPorts] - Lista customizada de portas (opcional)
 * @returns {Promise<object>} Resultado com portas abertas, status e findings de segurança
 */
export async function scanTcpPorts(host, customPorts) {
  const portsToCheck = customPorts || Object.keys(PORT_SERVICES).map(Number);

  // Primeira rodada — scan completo
  const firstPass = await Promise.all(
    portsToCheck.map(port => checkPort(host, port))
  );

  // Segunda rodada — reforçar apenas as portas que completaram handshake
  const candidates = firstPass.filter(r => r.state === 'OPEN');
  const confirmations = {};
  if (candidates.length > 0) {
    await Promise.all(candidates.map(async r => {
      const confirmed = await confirmPort(host, r.port, r.latency_ms);
      confirmations[r.port] = confirmed;
    }));
  }

  // Montar resultados finais com dupla confirmação e conselho de segurança aplicado
  const results = firstPass.map(r => {
    const conf = confirmations[r.port];
    const advice = getPortSecurityAdvice(r.port, r.service);
    return {
      ...r,
      state: conf ? conf.state : r.state,
      latency_ms: conf ? conf.latency_ms : r.latency_ms,
      confirmed: conf ? conf.confirmed : false,
      inconsistent: conf ? conf.inconsistent : false,
      second_pass_state: conf ? (conf.secondPassState || null) : null,
      severity: advice.severity,
      risk: advice.risk,
      recommendation: advice.recommendation,
    };
  });

  const openPorts = results.filter(r => r.state === 'OPEN');
  // Portas que não puderam ser testadas: não entram como aberta nem como fechada.
  const unknownPorts = results.filter(r => r.state === 'UNKNOWN');
  const hasWebPort = results.some(r =>
    [80, 443, 8080, 8443].includes(r.port) && r.state === 'OPEN'
  );

  // Gerar findings apenas para portas confirmadas como OPEN E perigosas
  const findings = [];
  for (const r of openPorts) {
    if (!DANGEROUS_PORTS.has(r.port)) continue;

    const advice = getPortSecurityAdvice(r.port, r.service);
    findings.push({
      type: 'exposed_port',
      severity: advice.severity,
      thirdParty: false,
      label: `Porta ${r.port} (${r.service}) aberta`,
      port: r.port,
      service: r.service,
      host,
      latency_ms: r.latency_ms,
      confirmed: r.confirmed || false,
      risk: advice.risk,
      recommendation: advice.recommendation,
    });
  }

  // Se NENHUMA porta deu resposta conclusiva (tudo UNKNOWN ou FILTERED), o
  // resultado é indeterminado — 'FAIL' aqui afirmaria "nenhuma porta aberta"
  // com base apenas em timeouts e erros locais.
  const verifiedCount = results.filter(r => r.state === 'OPEN' || r.state === 'CLOSED').length;
  let status;
  if (hasWebPort) status = 'PASS';
  else if (openPorts.length > 0) status = 'WARN';
  else if (verifiedCount === 0) status = 'INFO';
  else status = 'FAIL';

  return {
    status,
    total_scanned: results.length,
    verified_count: verifiedCount,
    open_count: openPorts.length,
    unverified_count: unknownPorts.length,
    unverified_ports: unknownPorts.map(r => ({ port: r.port, errCode: r.errCode || null })),
    note: unknownPorts.length > 0
      ? `${unknownPorts.length} porta(s) não puderam ser testadas (erro de rota/recurso local) — estado indeterminado, não contabilizadas como abertas nem fechadas.`
      : null,
    ports: results,
    findings,
  };
}

