import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildAgentPrompt, buildImpactFallback } from './agentPrompt.js';
import type { ExploitEvidence } from '../src/types.js';

test('buildAgentPrompt includes the title, target, fix, and endpoint when present', () => {
  const prompt = buildAgentPrompt(
    { title: 'Missing CSP', description: 'No Content-Security-Policy header.', fix: 'Add a strict CSP header.', category: 'IAST', owasp: 'A05:2021 – Security Misconfiguration', endpoint: '/api/login' },
    'https://example.test',
  );
  assert.match(prompt, /Missing CSP/);
  assert.match(prompt, /https:\/\/example\.test/);
  assert.match(prompt, /Add a strict CSP header\./);
  assert.match(prompt, /\/api\/login/);
  assert.match(prompt, /A05:2021/);
});

test('buildAgentPrompt omits the endpoint line when none is given', () => {
  const prompt = buildAgentPrompt(
    { title: 'Outdated jQuery', description: 'Vulnerable jQuery version detected.', fix: 'Upgrade jQuery.', category: 'SCA' },
    'https://example.test',
  );
  assert.ok(!prompt.includes('Affected endpoint'));
});

test('buildAgentPrompt emits the full master-prompt structure', () => {
  const prompt = buildAgentPrompt(
    { title: 'SQL Injection', description: 'A parameter is concatenated into a query.', fix: 'Use parameterized queries.', category: 'RED_TEAM', owasp: 'A03:2021 – Injection' },
    'https://example.test',
  );
  // Every section a portable agent prompt needs, so it drives an end-to-end fix.
  for (const heading of ['# Security Fix Task', '## The issue', '## Recommended fix', '## Work it in this order', '## Guardrails', '## Done when']) {
    assert.ok(prompt.includes(heading), `expected section: ${heading}`);
  }
  // Provider-neutral: portable across any AI coding agent, with no vendor names
  // baked into the prompt handed to the agent.
  assert.match(prompt, /any AI coding agent on any platform/);
  for (const vendor of ['Claude Code', 'Codex', 'Replit', 'Cursor', 'Windsurf']) {
    assert.ok(!prompt.includes(vendor), `prompt must not name a specific agent (${vendor})`);
  }
  // The workflow forces confirm-before-change (false-positive guard) and a test.
  assert.match(prompt, /false positive/i);
  assert.match(prompt, /regression test/i);
  // A checkable definition of done.
  assert.match(prompt, /- \[ \] /);
});

test('buildAgentPrompt surfaces severity and impact when provided', () => {
  const prompt = buildAgentPrompt(
    { title: 'Exposed .env', description: 'Environment file is publicly served.', fix: 'Block access to dotfiles.', category: 'DAST', severity: 'critical', confidence: 'high', impact: 'An attacker can read database credentials.' },
    'https://example.test',
  );
  assert.match(prompt, /Severity: CRITICAL/);
  assert.match(prompt, /confidence: high/);
  assert.match(prompt, /Impact if left unfixed: An attacker can read database credentials\./);
});

test('buildAgentPrompt folds in a replayable exploit receipt as proof, and omits it otherwise', () => {
  const evidence: ExploitEvidence = {
    method: 'error-signature',
    attack: { request: 'GET /api/item?id=1%27 HTTP/1.1', response: "HTTP/1.1 500\n...SQL syntax error near \"'\"..." },
    signal: { quote: 'SQL syntax error', offsetInResponse: 42, why: 'A raw SQL parser error means the input reached the query unescaped.' },
    demonstration: 'Sending a single quote in the id parameter triggered a database error.',
    reproduction: "curl 'https://example.test/api/item?id=1%27'",
    capturedAt: '2026-07-23T00:00:00.000Z',
  };
  const withProof = buildAgentPrompt(
    { title: 'SQL Injection', description: 'Injectable id parameter.', fix: 'Parameterize the query.', category: 'RED_TEAM', evidence },
    'https://example.test',
  );
  assert.match(withProof, /## Proof this is real/);
  assert.match(withProof, /curl 'https:\/\/example\.test\/api\/item\?id=1%27'/);
  assert.match(withProof, /SQL syntax error/);

  const withoutProof = buildAgentPrompt(
    { title: 'SQL Injection', description: 'Injectable id parameter.', fix: 'Parameterize the query.', category: 'RED_TEAM' },
    'https://example.test',
  );
  assert.ok(!withoutProof.includes('## Proof this is real'));
});

test('buildImpactFallback scales language with severity', () => {
  assert.match(buildImpactFallback('critical'), /full compromise/i);
  assert.match(buildImpactFallback('info'), /informational/i);
});
