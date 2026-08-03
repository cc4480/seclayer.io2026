import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildNmapArgs, DEFAULT_HOST_TIMEOUT_MINUTES } from './args.js';

test('buildNmapArgs produces the exact full-depth scan invocation', () => {
  const args = buildNmapArgs('203.0.113.10');
  assert.deepEqual(args, [
    '-p-', '-sV', '-O', '--script', 'vuln', '-T4',
    '--host-timeout', `${DEFAULT_HOST_TIMEOUT_MINUTES}m`,
    '--stats-every', '10s', '-oX', '-', '203.0.113.10',
  ]);
});

test('buildNmapArgs honors a custom host-timeout', () => {
  const args = buildNmapArgs('203.0.113.10', 5);
  assert.ok(args.includes('--host-timeout'));
  assert.equal(args[args.indexOf('--host-timeout') + 1], '5m');
});

test('buildNmapArgs supports IPv6 literals', () => {
  const args = buildNmapArgs('2001:db8::1');
  assert.equal(args.at(-1), '2001:db8::1');
});

test('buildNmapArgs refuses a hostname — the caller must resolve first', () => {
  assert.throws(() => buildNmapArgs('scan-me.test'), /must be a literal IP address/);
});
