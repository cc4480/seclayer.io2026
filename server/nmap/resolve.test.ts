import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveNmapTarget } from './resolve.js';

test('resolveNmapTarget blocks a loopback IP literal', async () => {
  await assert.rejects(() => resolveNmapTarget('http://127.0.0.1'), /internal or reserved/);
});

test('resolveNmapTarget blocks a private RFC1918 IP literal', async () => {
  await assert.rejects(() => resolveNmapTarget('http://10.0.0.5'), /internal or reserved/);
});

test('resolveNmapTarget accepts a public IP literal without a DNS lookup', async () => {
  const { hostname, ip } = await resolveNmapTarget('http://203.0.113.10');
  assert.equal(hostname, '203.0.113.10');
  assert.equal(ip, '203.0.113.10');
});

test('resolveNmapTarget blocks internal-only hostnames outright (localhost/.local/.internal)', async () => {
  await assert.rejects(() => resolveNmapTarget('http://localhost'), /internal hostname/);
  await assert.rejects(() => resolveNmapTarget('http://foo.local'), /internal hostname/);
  await assert.rejects(() => resolveNmapTarget('http://svc.internal'), /internal hostname/);
});

test('SCAN_DEV_ALLOW_HOSTS unlocks a loopback target only in dev, only for the exact listed host', async () => {
  const prevEnv = process.env.NODE_ENV;
  const prevAllow = process.env.SCAN_DEV_ALLOW_HOSTS;
  process.env.NODE_ENV = 'development';
  process.env.SCAN_DEV_ALLOW_HOSTS = '127.0.0.1:4100';
  try {
    const { ip } = await resolveNmapTarget('http://127.0.0.1:4100');
    assert.equal(ip, '127.0.0.1');

    // A different loopback host/port not on the allowlist is still refused.
    await assert.rejects(() => resolveNmapTarget('http://127.0.0.2'), /internal or reserved/);
  } finally {
    process.env.NODE_ENV = prevEnv;
    if (prevAllow === undefined) delete process.env.SCAN_DEV_ALLOW_HOSTS;
    else process.env.SCAN_DEV_ALLOW_HOSTS = prevAllow;
  }
});

test('SCAN_DEV_ALLOW_HOSTS is hard-disabled in production', async () => {
  const prevEnv = process.env.NODE_ENV;
  const prevAllow = process.env.SCAN_DEV_ALLOW_HOSTS;
  process.env.NODE_ENV = 'production';
  process.env.SCAN_DEV_ALLOW_HOSTS = '127.0.0.1:4100';
  try {
    await assert.rejects(() => resolveNmapTarget('http://127.0.0.1:4100'), /internal or reserved/);
  } finally {
    process.env.NODE_ENV = prevEnv;
    if (prevAllow === undefined) delete process.env.SCAN_DEV_ALLOW_HOSTS;
    else process.env.SCAN_DEV_ALLOW_HOSTS = prevAllow;
  }
});

test('resolveNmapTarget rejects a hostname that fails to resolve', async () => {
  await assert.rejects(
    () => resolveNmapTarget('http://this-domain-should-not-exist-seclayer-test.invalid'),
    /DNS resolution failed/,
  );
});
