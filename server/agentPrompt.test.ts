import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildAgentPrompt, buildImpactFallback } from './agentPrompt.js';

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

test('buildImpactFallback scales language with severity', () => {
  assert.match(buildImpactFallback('critical'), /full compromise/i);
  assert.match(buildImpactFallback('info'), /informational/i);
});
