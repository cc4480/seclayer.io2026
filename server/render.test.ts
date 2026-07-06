import { test } from 'node:test';
import assert from 'node:assert/strict';
import { captureScreenshot, isScreenshotEnabled } from './render.js';

// These tests lock in the safety-critical behaviour of the target-screenshot
// capture WITHOUT launching a real browser: every case here returns before the
// dynamic playwright import, so the suite stays fast and CI-safe (no browser
// binary required). The full "screenshot is taken and rendered" path is
// exercised manually against a running server.

const FLAG = 'ENABLE_TARGET_SCREENSHOT';

function setFlag(value: string | undefined): string | undefined {
  const prev = process.env[FLAG];
  if (value === undefined) delete process.env[FLAG];
  else process.env[FLAG] = value;
  return prev;
}

test('isScreenshotEnabled reflects the env flag', () => {
  const prev = setFlag('true');
  try {
    assert.equal(isScreenshotEnabled(), true);
    setFlag('false');
    assert.equal(isScreenshotEnabled(), false);
    setFlag(undefined);
    assert.equal(isScreenshotEnabled(), false);
  } finally {
    setFlag(prev);
  }
});

test('captureScreenshot is a no-op (returns null) when the feature is disabled', async () => {
  const prev = setFlag(undefined); // disabled
  try {
    assert.equal(await captureScreenshot('https://example.com', {}), null);
  } finally {
    setFlag(prev);
  }
});

test('captureScreenshot refuses internal/reserved and non-http targets even when enabled (SSRF guard)', async () => {
  const prev = setFlag('true');
  try {
    const blocked = [
      'http://127.0.0.1/',                          // loopback
      'http://localhost/',                          // internal hostname
      'http://169.254.169.254/latest/meta-data/',   // cloud metadata
      'http://10.0.0.5/',                           // RFC1918
      'http://192.168.1.1/',                        // RFC1918
      'http://[::1]/',                              // IPv6 loopback
      'ftp://example.com/',                         // non-http scheme
      'file:///etc/passwd',                         // file scheme
      'not-a-url',                                  // unparseable
    ];
    for (const url of blocked) {
      assert.equal(await captureScreenshot(url, {}, 1000), null, `expected null for ${url}`);
    }
  } finally {
    setFlag(prev);
  }
});
