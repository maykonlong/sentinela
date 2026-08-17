/**
 * Socket Timing Breakdown — Latência física por fase de conexão
 * Reimplementação em Node.js do socket_timing_checker.py do URL Checker.
 *
 * Mede em milissegundos: DNS → TCP Connect → TLS Handshake → TTFB → Download
 */

import dns from 'dns';
import net from 'net';
import tls from 'tls';
import { URL } from 'url';

function resolveHostname(hostname) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    dns.lookup(hostname, 4, (err, address) => {
      const elapsed = Date.now() - start;
      if (err) reject({ elapsed, error: err });
      else resolve({ elapsed, ip: address });
    });
  });
}

/**
 * Mede a latência física de cada fase da conexão com o servidor.
 * @param {string} targetUrl - URL completa do alvo
 * @returns {Promise<object>} Breakdown DNS/TCP/TLS/TTFB/Download em ms
 */
export async function measureSocketTiming(targetUrl) {
  const parsed = new URL(targetUrl);
  const scheme = parsed.protocol.replace(':', '');
  const hostname = parsed.hostname;
  const port = parsed.port ? parseInt(parsed.port) : (scheme === 'https' ? 443 : 80);
  let path = parsed.pathname || '/';
  if (parsed.search) path += parsed.search;

  // 1. DNS Lookup
  let ip, dnsTime;
  try {
    const dnsResult = await resolveHostname(hostname);
    ip = dnsResult.ip;
    dnsTime = dnsResult.elapsed;
  } catch (e) {
    return {
      status: 'FAIL', dns_ms: e.elapsed || 0,
      tcp_ms: 0, tls_ms: 0, ttfb_ms: 0, download_ms: 0,
      total_ms: e.elapsed || 0, error: 'DNS resolution failed',
    };
  }

  // 2. TCP Connect
  const tcpStart = Date.now();
  const rawSock = await new Promise((resolve, reject) => {
    const sock = net.createConnection({ host: ip, port, timeout: 5000 }, () => {
      resolve(sock);
    });
    sock.on('error', (err) => reject(err));
    sock.on('timeout', () => { sock.destroy(); reject(new Error('TCP timeout')); });
  }).catch(err => {
    const tcpTime = Date.now() - tcpStart;
    return { error: true, tcpTime, msg: err.message };
  });

  if (rawSock.error) {
    return {
      status: 'FAIL', dns_ms: dnsTime, tcp_ms: rawSock.tcpTime,
      tls_ms: 0, ttfb_ms: 0, download_ms: 0,
      total_ms: dnsTime + rawSock.tcpTime, error: 'TCP connect failed: ' + rawSock.msg,
    };
  }
  const tcpTime = Date.now() - tcpStart;

  // 3. TLS Handshake (se HTTPS)
  let sock = rawSock;
  let tlsTime = 0;
  if (scheme === 'https') {
    const tlsStart = Date.now();
    try {
      sock = await new Promise((resolve, reject) => {
        const tlsSock = tls.connect({
          socket: rawSock,
          servername: hostname,
          rejectUnauthorized: false,
        }, () => {
          resolve(tlsSock);
        });
        tlsSock.on('error', reject);
      });
      tlsTime = Date.now() - tlsStart;
    } catch (err) {
      rawSock.destroy();
      tlsTime = Date.now() - tlsStart;
      return {
        status: 'FAIL', dns_ms: dnsTime, tcp_ms: tcpTime, tls_ms: tlsTime,
        ttfb_ms: 0, download_ms: 0,
        total_ms: dnsTime + tcpTime + tlsTime, error: 'TLS handshake failed',
      };
    }
  }

  // 4. TTFB (Time to First Byte)
  const ttfbStart = Date.now();
  const reqStr = `GET ${path} HTTP/1.1\r\nHost: ${hostname}\r\nUser-Agent: Sentinela/1.0\r\nConnection: close\r\n\r\n`;
  
  const firstByte = await new Promise((resolve, reject) => {
    sock.write(reqStr);
    sock.once('data', (chunk) => {
      resolve({ elapsed: Date.now() - ttfbStart, chunk });
    });
    sock.once('error', (err) => reject(err));
    setTimeout(() => reject(new Error('TTFB timeout')), 10000);
  }).catch(err => {
    sock.destroy();
    return { error: true, elapsed: Date.now() - ttfbStart };
  });

  if (firstByte.error) {
    const ttfbTime = firstByte.elapsed;
    return {
      status: 'FAIL', dns_ms: dnsTime, tcp_ms: tcpTime, tls_ms: tlsTime,
      ttfb_ms: ttfbTime, download_ms: 0,
      total_ms: dnsTime + tcpTime + tlsTime + ttfbTime, error: 'TTFB timeout',
    };
  }
  const ttfbTime = firstByte.elapsed;

  // 5. Download (rest of response)
  const dlStart = Date.now();
  let totalBytes = firstByte.chunk.length;
  await new Promise((resolve) => {
    sock.on('data', (chunk) => { totalBytes += chunk.length; });
    sock.on('end', resolve);
    sock.on('error', resolve);
    sock.on('close', resolve);
    setTimeout(resolve, 10000); // safety cap
  });
  const downloadTime = Date.now() - dlStart;
  sock.destroy();

  const totalTime = dnsTime + tcpTime + tlsTime + ttfbTime + downloadTime;

  return {
    status: 'PASS',
    dns_ms: dnsTime,
    tcp_ms: tcpTime,
    tls_ms: tlsTime,
    ttfb_ms: ttfbTime,
    download_ms: downloadTime,
    total_ms: totalTime,
    total_bytes: totalBytes,
    ip,
  };
}
