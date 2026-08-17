/**
 * TCP Port Scanner — Varredura de portas enterprise
 * Reimplementação em Node.js do tcp_checker.py do URL Checker.
 *
 * Escaneia 30 portas comuns (web, DB, cache, SSH, RDP) de forma concorrente
 * usando net.Socket com timeout de 600ms.
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

// Portas que, se abertas, representam risco de segurança (DB/cache sem autenticação típica)
const DANGEROUS_PORTS = new Set([
  3306, 5432, 27017, 6379, 9200, 11211, 1433, 5672,
  21, 22, 23, 3389, 8888,
]);

function checkPort(host, port, timeout = 600) {
  return new Promise((resolve) => {
    const service = PORT_SERVICES[port] || 'Custom Service';
    const start = Date.now();
    const sock = new net.Socket();
    sock.setTimeout(timeout);

    sock.on('connect', () => {
      const latency = Date.now() - start;
      sock.destroy();
      resolve({ port, service, state: 'OPEN', latency_ms: latency });
    });

    sock.on('timeout', () => {
      const latency = Date.now() - start;
      sock.destroy();
      resolve({ port, service, state: 'FILTERED', latency_ms: latency });
    });

    sock.on('error', (err) => {
      const latency = Date.now() - start;
      sock.destroy();
      const state = err.code === 'ECONNREFUSED' ? 'CLOSED' : 'CLOSED';
      resolve({ port, service, state, latency_ms: latency });
    });

    sock.connect(port, host);
  });
}

/**
 * Escaneia as portas enterprise de forma concorrente.
 * @param {string} hostname - IP ou hostname do alvo
 * @param {number[]} [customPorts] - Lista customizada de portas (opcional)
 * @returns {Promise<object>} Resultado com portas abertas, status e findings de segurança
 */
export async function scanTcpPorts(hostname, customPorts) {
  const portsToCheck = customPorts || Object.keys(PORT_SERVICES).map(Number);

  const results = await Promise.all(
    portsToCheck.map(port => checkPort(hostname, port))
  );

  const openPorts = results.filter(r => r.state === 'OPEN');
  const hasWebPort = results.some(r =>
    [80, 443, 8080, 8443].includes(r.port) && r.state === 'OPEN'
  );

  // Gerar findings de segurança para portas perigosas abertas
  const findings = [];
  for (const r of openPorts) {
    if (DANGEROUS_PORTS.has(r.port)) {
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
        latency_ms: r.latency_ms,
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
  }

  return {
    status: hasWebPort ? 'PASS' : (openPorts.length > 0 ? 'WARN' : 'FAIL'),
    total_scanned: results.length,
    open_count: openPorts.length,
    ports: results,
    findings,
  };
}
