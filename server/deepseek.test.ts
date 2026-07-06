import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateAiReport, refineCategory } from './deepseek.js';
import type { Finding } from '../src/types.js';

test('refineCategory corrects the model\'s lazy DAST bucketing by title', () => {
  // Headers / cookies / session policy → IAST
  assert.equal(refineCategory('DAST', 'Missing Content-Security-Policy (CSP)'), 'IAST');
  assert.equal(refineCategory('DAST', 'Missing Strict-Transport-Security (HSTS) Policy'), 'IAST');
  assert.equal(refineCategory('DAST', 'Cookie Set Without HttpOnly Attribute'), 'IAST');
  // Perimeter / server disclosure → EASM
  assert.equal(refineCategory('DAST', 'Verbose Server Framework Signature Leak'), 'EASM');
  assert.equal(refineCategory('DAST', 'Insecure Connection Protocol (HTTP)'), 'EASM');
  // Dependencies → SCA
  assert.equal(refineCategory('DAST', 'Outdated Library Vulnerability Detected (jQuery)'), 'SCA');
  // Genuinely dynamic findings keep the model's category
  assert.equal(refineCategory('DAST', 'Application Surface Mapped'), 'DAST');
  assert.equal(refineCategory('RED_TEAM', 'Active SQL Injection Probe'), 'RED_TEAM');
});

// The test runner never loads .env.local, so DEEPSEEK_API_KEY is unset here
// and generateAiReport exercises its local, deterministic fallback path — the
// same one used in production when no key is configured.

test('generateAiReport always returns a populated executiveBreakdown, even without DeepSeek', async () => {
  const findings: Finding[] = [
    { id: 'a', title: 'Missing CSP', description: 'desc', severity: 'high', fix: 'Add a CSP header.', category: 'IAST' },
    { id: 'b', title: 'Outdated jQuery', description: 'desc', severity: 'medium', fix: 'Upgrade jQuery.', category: 'SCA' },
  ];
  const staticCompiled = { score: 55, severity: 'high' as const, findings };

  const report = await generateAiReport('https://x.test', { techLeaked: [], missingHeaders: [], sslSecure: true, responseStatus: 200, probedPaths: [], cookieIssues: [] }, staticCompiled);

  assert.ok(report.executiveBreakdown);
  assert.match(report.executiveBreakdown.overview, /x\.test/);
  assert.ok(report.executiveBreakdown.riskAreas.length > 0);
  assert.ok(report.executiveBreakdown.businessImpact.length > 0);
  assert.ok(report.executiveBreakdown.priorityActions.length > 0);
  // Highest-severity finding's fix should be prioritized first.
  assert.equal(report.executiveBreakdown.priorityActions[0], 'Add a CSP header.');
});

test('generateAiReport reports clean hygiene and no risk areas placeholder for zero findings', async () => {
  const staticCompiled = { score: 100, severity: 'info' as const, findings: [] as Finding[] };
  const report = await generateAiReport('https://clean.test', { techLeaked: [], missingHeaders: [], sslSecure: true, responseStatus: 200, probedPaths: [], cookieIssues: [] }, staticCompiled);

  assert.equal(report.executiveBreakdown.riskAreas[0].area, 'General Hygiene');
  assert.equal(report.executiveBreakdown.priorityActions[0], 'No action required — no active findings this scan.');
});
