import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyNmapScriptOutput } from './classify.js';

test('classifyNmapScriptOutput: a real VULNERABLE hit is a finding', () => {
  assert.equal(
    classifyNmapScriptOutput('VULNERABLE:\nApache path traversal and remote code execution\n  State: VULNERABLE (Exploitable)\n  IDs:  CVE:CVE-2021-41773'),
    'finding',
  );
  assert.equal(classifyNmapScriptOutput('VULNERABLE:\nMySQL and MariaDB weak password authentication scramble\n  State: VULNERABLE\n  IDs:  CVE:CVE-2012-2122'), 'finding');
});

test('classifyNmapScriptOutput: explicit negative results are never a finding', () => {
  assert.equal(classifyNmapScriptOutput("Couldn't find any CSRF vulnerabilities."), 'negative');
  assert.equal(classifyNmapScriptOutput("Couldn't find any DOM based XSS."), 'negative');
  assert.equal(classifyNmapScriptOutput("Couldn't find any stored XSS vulnerabilities."), 'negative');
  assert.equal(classifyNmapScriptOutput('State: NOT VULNERABLE'), 'negative');
  assert.equal(classifyNmapScriptOutput('No vulnerabilities found.'), 'negative');
  assert.equal(classifyNmapScriptOutput('Target appears to be not vulnerable'), 'negative');
});

test('classifyNmapScriptOutput: "NOT VULNERABLE" is never mistaken for a VULNERABLE hit', () => {
  // Regression guard: a naive /VULNERABLE/ substring test would misclassify this.
  assert.equal(classifyNmapScriptOutput('State: NOT VULNERABLE'), 'negative');
});

test('classifyNmapScriptOutput: script execution errors and timeouts are not findings', () => {
  assert.equal(classifyNmapScriptOutput('ERROR: Script execution failed (use -d to debug)'), 'error');
  assert.equal(classifyNmapScriptOutput('No reply from server (TIMEOUT)'), 'error');
});

test('classifyNmapScriptOutput: an UNKNOWN vulns.lua state is inconclusive, not a finding', () => {
  assert.equal(classifyNmapScriptOutput('State: UNKNOWN (going to safe state)'), 'inconclusive');
});

test('classifyNmapScriptOutput: empty output is treated as negative, not a finding', () => {
  assert.equal(classifyNmapScriptOutput(''), 'negative');
  assert.equal(classifyNmapScriptOutput('   '), 'negative');
});

test('classifyNmapScriptOutput: freeform substantive output with no negative/error markers defaults to finding', () => {
  // Not every vuln script uses vulns.lua's State: convention — a script that
  // says nothing negative and produced real content should still surface,
  // never silently dropped (never under-report a real signal).
  assert.equal(classifyNmapScriptOutput('slowloris-vulnerable: server does not fully close connections after the request timeout'), 'finding');
});
