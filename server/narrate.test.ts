import { test } from 'node:test';
import assert from 'node:assert/strict';
import { narrateScanning, narrateAnalysis } from './narrate.js';
import type { DiagnosticResult } from './scanner.js';

// The test runner never loads .env.local (only server/env.ts does, at app
// boot), so DEEPSEEK_API_KEY is unset here and both functions exercise their
// local, deterministic fallback path — the same one used in production when
// no key is configured.

function baseDiag(overrides: Partial<DiagnosticResult> = {}): DiagnosticResult {
  return {
    url: 'https://x.test', scannedAt: '', responseStatus: 200, sslSecure: true,
    headers: {}, missingHeaders: [], techLeaked: [], probedPaths: [], cookieIssues: [],
    sastFindings: [], scaLibraries: [], easmPerimeter: { subdomains: [], ip: '', nameserver: '', protocol: '' },
    redTeamFindings: [], apiSecFindings: [], ...overrides,
  } as DiagnosticResult;
}

test('narrateScanning falls back to real, deterministic lines built from diagnostics', async () => {
  const diag = baseDiag({ missingHeaders: ['content-security-policy', 'strict-transport-security'] });
  const lines = await narrateScanning(diag, 'https://x.test');
  assert.ok(lines.length > 0);
  assert.ok(lines.some((l) => l.includes('content-security-policy')));
});

test('narrateAnalysis falls back to real, deterministic lines built from compiled findings', async () => {
  const compiled = {
    score: 62,
    severity: 'high' as const,
    findings: [
      { id: 'a', title: 'Missing CSP', description: '', severity: 'high' as const, fix: '', category: 'IAST' },
    ],
  };
  const lines = await narrateAnalysis(compiled, 'https://x.test');
  assert.ok(lines.some((l) => l.includes('62/100')));
  assert.ok(lines.some((l) => l.includes('Missing CSP')));
});
