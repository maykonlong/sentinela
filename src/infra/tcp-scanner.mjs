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
 * - Latência < 2ms em conexão bem-sucedida pode indicar RST imediato (falso OPEN) → marcada UNCERTAIN
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

/**
 * Tenta conectar a uma porta. Retorna OPEN, CLOSED ou FILTERED.
 * Latência < 3ms pode indicar RST imediato (falso positivo) — marcado UNCERTAIN.
 */
function checkPort(host, port, timeout = 1200) {
  return new Promise((resolve) => {
    const service = PORT_SERVICES[port] || 'Custom Service';
    const start = Date.now();
    const sock = new net.Socket();
    sock.setTimeout(timeout);

    sock.on('connect', () => {
      const latency = Date.now() - start;
      sock.destroy();
      // Latência < 3ms em IPs não-localhost é suspeita (RST imediato do firewall)
      const state = (latency < 3 && !['127.0.0.1', '::1', 'localhost'].includes(host))
        ? 'UNCERTAIN'
        : 'OPEN';
      resolve({ port, service, state, latency_ms: latency });
    });

    sock.on('timeout', () => {
      const latency = Date.now() - start;
      sock.destroy();
      resolve({ port, service, state: 'FILTERED', latency_ms: latency });
    });

    sock.on('error', (err) => {
      const latency = Date.now() - start;
      sock.destroy();
      // ECONNREFUSED = porta fechada com resposta RST (definitivamente CLOSED)
      // Outros erros (EHOSTUNREACH, ENETUNREACH) = também CLOSED/inacessível
      resolve({ port, service, state: 'CLOSED', latency_ms: latency, errCode: err.code });
    });

    sock.connect(port, host);
  });
}

/**
 * Dupla confirmação para portas marcadas como OPEN ou UNCERTAIN.
 * Se a segunda tentativa falhar, reclassifica como CLOSED.
 */
async function confirmPort(host, port, firstLatency) {
  const result = await checkPort(host, port, 1200);
  if (result.state === 'OPEN') {
    return { state: 'OPEN', latency_ms: Math.round((firstLatency + result.latency_ms) / 2) };
  }
  // Segunda tentativa falhou → falso positivo
  return { state: 'CLOSED', latency_ms: result.latency_ms };
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

  // Segunda rodada — confirmar apenas as candidatas a OPEN/UNCERTAIN
  const candidates = firstPass.filter(r => r.state === 'OPEN' || r.state === 'UNCERTAIN');
  const confirmations = {};
  if (candidates.length > 0) {
    await Promise.all(candidates.map(async r => {
      const confirmed = await confirmPort(host, r.port, r.latency_ms);
      confirmations[r.port] = confirmed;
    }));
  }

  // Montar resultados finais com dupla confirmação aplicada
  const results = firstPass.map(r => {
    if (confirmations[r.port]) {
      return { ...r, state: confirmations[r.port].state, latency_ms: confirmations[r.port].latency_ms, confirmed: true };
    }
    return r;
  });

  const openPorts = results.filter(r => r.state === 'OPEN');
  const hasWebPort = results.some(r =>
    [80, 443, 8080, 8443].includes(r.port) && r.state === 'OPEN'
  );

  // Gerar findings apenas para portas confirmadas como OPEN E perigosas
  const findings = [];
  for (const r of openPorts) {
    if (!DANGEROUS_PORTS.has(r.port)) continue;

    const isDb = [3306, 5432, 27017, 1433, 9200, 11211].includes(r.port);
    const isCache = [6379, 11211].includes(r.port);
    const isRemote = [22, 23, 3389].includes(r.port);

    findings.push({
      type: 'exposed_port',
      severity: isDb || isCache ? 'HIGH' : 'MEDIUM',
      thirdParty: false,
      label: `Porta ${r.port} (${r.service}) aberta`,
      port: r.port,
      service: r.service,
      host,                            // ← incluir host para verificação manual correta
      latency_ms: r.latency_ms,
      confirmed: r.confirmed || false,
      risk: isDb
        ? `A porta ${r.port} (${r.service}) está aberta publicamente. Bancos de dados não devem ser acessíveis pela internet — expõe dados a ataques de força bruta, injeção e exfiltração.`
        : isCache
        ? `A porta ${r.port} (${r.service}) está aberta publicamente. Caches sem autenticação (Redis, Memcached) podem ser lidos/escritos por qualquer pessoa, expondo dados sensíveis e permitindo envenenamento de cache.`
        : isRemote
        ? `A porta ${r.port} (${r.service}) está aberta publicamente. Serviços de acesso remoto expostos são alvo constante de força bruta automatizada.`
        : `A porta ${r.port} (${r.service}) está aberta e pode representar superfície de ataque desnecessária.`,
      recommendation: isDb
        ? `Fechar a porta ${r.port} no firewall para acesso externo. Usar conexão via VPN, SSH tunnel ou rede privada. Se necessário acesso externo, exigir autenticação forte e TLS.`
        : isCache
        ? `Fechar a porta ${r.port} no firewall. Redis/Memcached devem escutar apenas em localhost (bind 127.0.0.1). Habilitar autenticação (requirepass no Redis).`
        : isRemote
        ? `Restringir acesso à porta ${r.port} por IP no firewall (whitelist). Usar chave SSH ao invés de senha. Considerar fail2ban para proteção contra brute force.`
        : `Avaliar se a porta ${r.port} precisa estar aberta. Fechar portas desnecessárias reduz a superfície de ataque.`,
    });
  }

  return {
    status: hasWebPort ? 'PASS' : (openPorts.length > 0 ? 'WARN' : 'FAIL'),
    total_scanned: results.length,
    open_count: openPorts.length,
    ports: results,
    findings,
  };
}
