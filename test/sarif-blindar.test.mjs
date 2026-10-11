import test from 'node:test';
import assert from 'node:assert/strict';
import { generateSarif } from '../src/report/sarif-export.mjs';
test('SARIF preserva alvo, SHA, idade real, sessão e severidade para o Blindar', () => {
  const meta = { target: 'https://fastlist.example/', timestamp: '2026-10-11T12:00:00Z', auditTimestamp: '2026-09-01T12:00:00Z', git_sha: 'a'.repeat(40), sessionId: 'session-test', executionSuccessful: true };
  const run = generateSarif({ meta, findings: [{ type: 'IDOR', severity: 'CRITICAL', label: 'Pedido de outra loja', cwe: 'CWE-639' }] }).runs[0];
  assert.equal(run.properties.timestamp, meta.auditTimestamp); assert.equal(run.properties.git_sha, meta.git_sha);
  assert.equal(run.properties.sessionId, meta.sessionId); assert.equal(run.properties.authenticated, false);
  assert.equal(run.invocations[0].executionSuccessful, true); assert.equal(run.results[0].properties.severity, 'CRITICAL');
  assert.ok(run.tool.driver.rules[0].properties.tags.includes('CWE-639'));
});
test('fases configuradas e relatório sem achados não provam conclusão nem login', () => {
  const run = generateSarif({ meta: { phases: ['PRÉ-LOGIN', 'LOGIN', 'PÓS-LOGIN'] }, findings: [] }).runs[0];
  assert.deepEqual(run.results, []); assert.equal(run.invocations[0].executionSuccessful, false); assert.equal(run.properties.authenticated, false);
});
