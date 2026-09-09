import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isBlockedIp, assertScanTargetSafe, firstBlockedAddress } from './ssrf.js';

// This module is the control that stops the scanner being used as an attack
// proxy into our own network, and it is imported by 24 others. It had no direct
// test file until 2026-09-09, and an SSRF bypass had been sitting in it.

test('isBlockedIp blocks every internal IPv4 range', () => {
  for (const ip of [
    '127.0.0.1', '127.1.2.3',      // loopback
    '0.0.0.0',                      // "this" network — reaches localhost on Linux
    '10.0.0.1', '172.16.0.1', '172.31.255.254', '192.168.1.1', // RFC1918
    '169.254.169.254',              // link-local + cloud metadata
    '100.64.0.1', '100.127.255.255',// CGNAT
    '192.0.0.1',                    // IETF protocol assignments
    '198.18.0.1', '198.19.255.255', // benchmarking
    '224.0.0.1', '255.255.255.255', // multicast / reserved
  ]) assert.equal(isBlockedIp(ip), true, `${ip} must be blocked`);
});

test('isBlockedIp blocks every internal IPv6 range', () => {
  for (const ip of [
    '::1', '::',                    // loopback / unspecified
    'fe80::1',                      // link-local
    'feaa::1', 'febf::1',           // link-local is fe80::/10, not just the fe80 prefix
    'fc00::1', 'fd00::1',           // unique local
  ]) assert.equal(isBlockedIp(ip), true, `${ip} must be blocked`);
});

test('isBlockedIp judges an embedded IPv4 in EVERY notation', () => {
  // The bypass: Node's URL parser rewrites [::ffff:127.0.0.1] to
  // [::ffff:7f00:1], so a check matching only the dotted form never fired on
  // any URL-derived target. Every internal range was reachable in hex.
  for (const ip of [
    '::ffff:127.0.0.1',             // dotted
    '::ffff:7f00:1',                // hex — what URL parsing actually produces
    '0:0:0:0:0:ffff:7f00:1',        // expanded
    '::FFFF:7F00:1',                // uppercase
    '::ffff:a9fe:a9fe',             // 169.254.169.254 — cloud metadata
    '::ffff:a00:1',                 // 10.0.0.1
    '::ffff:c0a8:1',                // 192.168.0.1
    '::ffff:ac10:1',                // 172.16.0.1
    '64:ff9b::7f00:1',              // NAT64 well-known prefix
    '::127.0.0.1',                  // deprecated IPv4-compatible
  ]) assert.equal(isBlockedIp(ip), true, `${ip} must be blocked`);
});

test('isBlockedIp allows genuinely public addresses', () => {
  // Over-blocking would break scanning entirely, so pin this too.
  for (const ip of [
    '8.8.8.8', '1.1.1.1', '142.251.218.206', '93.184.216.34',
    '2001:4860:4860::8888',
    '::ffff:8.8.8.8', '::ffff:808:808',   // public IPv4, mapped — must pass
  ]) assert.equal(isBlockedIp(ip), false, `${ip} must be allowed`);
});

test('isBlockedIp blocks anything it cannot parse', () => {
  for (const junk of ['', 'not-an-ip', '999.999.999.999', 'http://x']) {
    assert.equal(isBlockedIp(junk), true, `${JSON.stringify(junk)} must fail closed`);
  }
});

test('assertScanTargetSafe refuses internal targets in hex IPv6 notation', async () => {
  for (const url of [
    'http://127.0.0.1/', 'http://[::1]/', 'http://169.254.169.254/',
    'http://[::ffff:127.0.0.1]/', 'http://[::ffff:7f00:1]/',
    'http://[::ffff:a9fe:a9fe]/', 'http://[::ffff:a00:1]/',
    'http://localhost/', 'http://foo.internal/', 'http://bar.local/',
  ]) {
    await assert.rejects(() => assertScanTargetSafe(url), `${url} must be refused`);
  }
});

test('assertScanTargetSafe refuses non-http schemes', async () => {
  for (const url of ['file:///etc/passwd', 'gopher://x/', 'ftp://x/']) {
    await assert.rejects(() => assertScanTargetSafe(url), `${url} must be refused`);
  }
});

test('firstBlockedAddress reports the first internal address in a set', () => {
  // A round-robin record mixing one public and one private answer is the
  // classic bypass, so any single private answer must block the host.
  assert.equal(firstBlockedAddress('x.test', ['8.8.8.8', '10.0.0.1']), '10.0.0.1');
  assert.equal(firstBlockedAddress('x.test', ['8.8.8.8', '1.1.1.1']), null);
  assert.equal(firstBlockedAddress('x.test', ['::ffff:7f00:1']), '::ffff:7f00:1');
});
