/**
 * Load Percentiles — Teste de carga e estabilidade
 * Reimplementação em Node.js do performance_load_checker.py do URL Checker.
 *
 * Dispara N requisições concorrentes e calcula percentis de latência
 * (P50, P75, P90, P95, P99) + taxa de sucesso.
 */

function percentile(sortedArr, pct) {
  if (!sortedArr.length) return 0;
  const k = (sortedArr.length - 1) * (pct / 100);
  const f = Math.floor(k);
  const c = f + 1;
  if (c >= sortedArr.length) return sortedArr[f];
  return Math.round((sortedArr[f] * (c - k) + sortedArr[c] * (k - f)) * 100) / 100;
}

async function singleProbe(targetUrl) {
  const start = Date.now();
  try {
    const res = await fetch(targetUrl, {
      method: 'GET',
      headers: { 'User-Agent': 'Sentinela/1.0' },
      signal: AbortSignal.timeout(8000),
      redirect: 'follow',
    });
    // Consumir o body para medir tempo total
    await res.text();
    const elapsed = Date.now() - start;
    return { success: res.status < 500, status_code: res.status, time_ms: elapsed };
  } catch {
    const elapsed = Date.now() - start;
    return { success: false, status_code: 0, time_ms: elapsed };
  }
}

/**
 * Executa lote controlado de requisições e calcula percentis de latência.
 * @param {string} targetUrl - URL a testar
 * @param {number} [requestCount=20] - Número de requisições
 * @param {number} [concurrency=10] - Requisições simultâneas
 * @returns {Promise<object>} Resultado com percentis, taxa de sucesso e probes
 */
export async function measureLoadPercentiles(targetUrl, requestCount = 20, concurrency = 10) {
  // Executar em lotes de concurrency
  const results = [];
  for (let i = 0; i < requestCount; i += concurrency) {
    const batch = Math.min(concurrency, requestCount - i);
    const promises = Array.from({ length: batch }, () => singleProbe(targetUrl));
    const batchResults = await Promise.all(promises);
    results.push(...batchResults);
  }

  const successful = results.filter(r => r.success);
  const times = successful.map(r => r.time_ms).sort((a, b) => a - b);

  const totalRequests = results.length;
  const successCount = successful.length;
  const errorCount = totalRequests - successCount;
  const successRate = totalRequests > 0 ? Math.round((successCount / totalRequests) * 1000) / 10 : 0;

  if (!times.length) {
    return {
      status: 'FAIL',
      total_requests: totalRequests,
      success_count: 0,
      error_count: errorCount,
      success_rate_pct: 0,
      min_ms: null, max_ms: null, average_ms: null,
      percentiles: { p50: null, p75: null, p90: null, p95: null, p99: null },
      note: 'Todas as requisições de carga falharam.',
    };
  }

  const min_ms = times[0];
  const max_ms = times[times.length - 1];
  const average_ms = Math.round(times.reduce((a, b) => a + b, 0) / times.length);

  return {
    status: successRate >= 95 ? 'PASS' : (successRate >= 80 ? 'WARN' : 'FAIL'),
    total_requests: totalRequests,
    success_count: successCount,
    error_count: errorCount,
    success_rate_pct: successRate,
    min_ms,
    max_ms,
    average_ms,
    percentiles: {
      p50: percentile(times, 50),
      p75: percentile(times, 75),
      p90: percentile(times, 90),
      p95: percentile(times, 95),
      p99: percentile(times, 99),
    },
  };
}
