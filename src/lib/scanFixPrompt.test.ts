import { test } from 'node:test';
import assert from 'node:assert/strict';
import { actionableFindings, buildScanFixPrompt } from './scanFixPrompt.js';
import type { Finding, Scan } from '../types.js';

function f(over: Partial<Finding> & { title: string; severity: Finding['severity'] }): Finding {
  return { id: over.title, description: 'd', confidence: 'high', fix: 'do the fix', category: 'DAST', ...over } as Finding;
}
function scan(findings: Finding[], url = 'https://shop.example.com/checkout'): Scan {
  return { id: 's', userId: 'u', url, status: 'complete', findings, createdAt: 't' } as Scan;
}

test('actionableFindings drops suppressed and info findings, sorts most-severe first', () => {
  const findings = [
    f({ title: 'low thing', severity: 'low' }),
    f({ title: 'crit thing', severity: 'critical' }),
    f({ title: 'info note', severity: 'info' }),
    f({ title: 'suppressed crit', severity: 'critical', isFalsePositive: true }),
    f({ title: 'high thing', severity: 'high' }),
  ];
  const out = actionableFindings(findings);
  assert.deepEqual(out.map((x) => x.title), ['crit thing', 'high thing', 'low thing']);
});

test('buildScanFixPrompt returns a no-work plan when nothing is actionable', () => {
  const prompt = buildScanFixPrompt(scan([f({ title: 'info note', severity: 'info' })]));
  assert.match(prompt, /no actionable issues to fix/i);
  assert.match(prompt, /shop\.example\.com/);
});

test('buildScanFixPrompt lists findings in priority order with role framing and guardrails', () => {
  const prompt = buildScanFixPrompt(scan([
    f({ title: 'Reflected XSS', severity: 'high', owasp: 'A03:2021 – Injection', endpoint: '/search' }),
    f({ title: 'SQL Injection', severity: 'critical' }),
  ]));
  // Role framing + host.
  assert.match(prompt, /senior application security engineer/i);
  assert.match(prompt, /shop\.example\.com/);
  // Most-severe first: SQLi (critical) must appear before XSS (high).
  assert.ok(prompt.indexOf('SQL Injection') < prompt.indexOf('Reflected XSS'), 'critical listed before high');
  // Per-finding detail is folded in.
  assert.match(prompt, /A03:2021 – Injection/);
  assert.match(prompt, /Affected endpoint: \/search/);
  // Global guardrails + acceptance checklist are present exactly once.
  assert.match(prompt, /## Global guardrails/);
  assert.match(prompt, /## Done when/);
});

test('buildScanFixPrompt folds in a reproduction line when a proven receipt exists', () => {
  const proven = f({
    title: 'SQL Injection', severity: 'critical',
    evidence: {
      method: 'error-signature',
      attack: { request: 'GET /?id=%27', response: 'SQL syntax' },
      signal: { quote: 'SQL syntax', offsetInResponse: 0, why: 'w' },
      demonstration: 'd', reproduction: 'curl -s "https://x/?id=%27"', capturedAt: 't',
    },
  } as Partial<Finding> & { title: string; severity: Finding['severity'] });
  const prompt = buildScanFixPrompt(scan([proven]));
  assert.match(prompt, /Proof \(reproduce\):/);
  assert.match(prompt, /curl -s/);
});
