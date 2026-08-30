import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildNmapArgs, DEFAULT_HOST_TIMEOUT_MINUTES, DEEP_HOST_TIMEOUT_MINUTES, FAST_HOST_TIMEOUT_MINUTES } from './args.js';

test('buildNmapArgs defaults to the fast top-1000-port, script-capped scan', () => {
  const args = buildNmapArgs('203.0.113.10');
  assert.deepEqual(args, [
    '--top-ports', '1000', '-sV', '-O', '--script', 'vuln',
    '--script-timeout', '60s', '-T4',
    '--host-timeout', `${FAST_HOST_TIMEOUT_MINUTES}m`,
    '--stats-every', '10s', '-oX', '-', '203.0.113.10',
  ]);
});

test('buildNmapArgs deep=true runs the exhaustive all-ports, uncapped-script sweep', () => {
  const args = buildNmapArgs('203.0.113.10', undefined, true, true);
  assert.deepEqual(args, [
    '-p-', '-sV', '-O', '--script', 'vuln', '-T4',
    '--host-timeout', `${DEEP_HOST_TIMEOUT_MINUTES}m`,
    '--stats-every', '10s', '-oX', '-', '203.0.113.10',
  ]);
  // The fast default must NOT scan all ports; deep must NOT cap scripts.
  assert.ok(!buildNmapArgs('203.0.113.10').includes('-p-'));
  assert.ok(!args.includes('--script-timeout'));
});

test('buildNmapArgs defaults to the privileged (SYN + OS) technique', () => {
  // Omitting the flag must match passing privileged:true — the historical
  // behavior — so callers that never opt in are unaffected.
  assert.deepEqual(buildNmapArgs('203.0.113.10'), buildNmapArgs('203.0.113.10', undefined, true));
});

test('buildNmapArgs runs an unprivileged connect scan when raw sockets are unavailable', () => {
  const args = buildNmapArgs('203.0.113.10', DEFAULT_HOST_TIMEOUT_MINUTES, false);
  assert.deepEqual(args, [
    '--top-ports', '1000', '-sT', '-sV', '--unprivileged', '-Pn', '--script', 'vuln',
    '--script-timeout', '60s', '-T4',
    '--host-timeout', `${DEFAULT_HOST_TIMEOUT_MINUTES}m`,
    '--stats-every', '10s', '-oX', '-', '203.0.113.10',
  ]);
  // OS detection needs raw sockets — it must NOT be requested unprivileged, or
  // nmap quits instead of degrading.
  assert.ok(!args.includes('-O'));
  assert.ok(!args.includes('-sS'));
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
