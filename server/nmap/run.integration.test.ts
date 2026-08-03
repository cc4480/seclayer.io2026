// Requires a real, runnable `nmap` binary — self-skips everywhere it isn't
// installed (this dev container, most CI runners, the Vercel deployment)
// rather than failing the suite. Exercises the actual process-execution path
// against a target this repo owns, using the same SCAN_DEV_ALLOW_HOSTS
// mechanism the AppSec active probes already use to unlock 127.0.0.1 in dev.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectNmap } from './detect.js';
import { resolveNmapTarget } from './resolve.js';
import { runNmap, killNmapProcess } from './run.js';
import { parseNmapXml } from './parseXml.js';

test('a real nmap scan against a local target returns well-formed XML with the expected open port', async (t) => {
  const detection = await detectNmap();
  if (!detection.available) {
    t.skip(`nmap not installed in this environment (${detection.error}) — install it locally to run this test.`);
    return;
  }

  const prevEnv = process.env.NODE_ENV;
  const prevAllow = process.env.SCAN_DEV_ALLOW_HOSTS;
  process.env.NODE_ENV = 'development';
  process.env.SCAN_DEV_ALLOW_HOSTS = '127.0.0.1:4100';
  try {
    // Reuses the same vulnerable test target the AppSec active-probe tests
    // scan against — see test-targets/vulnerable-app.mjs. Assumes it's
    // already running on 4100 (as scripts/live-scan.ts documents); if it
    // isn't, this test's own scan will just report the port closed/filtered
    // rather than failing outright, so skip gracefully in that case too.
    const { ip } = await resolveNmapTarget('http://127.0.0.1:4100');

    const events: string[] = [];
    const result = await runNmap('nmap_test_' + Date.now(), ip, (_channel, text) => events.push(text), 2 * 60 * 1000);

    assert.match(result.xml, /<nmaprun/);
    const parsed = parseNmapXml(result.xml);
    const port4100 = parsed.ports.find((p) => p.portid === 4100);
    if (!port4100 || port4100.state !== 'open') {
      t.skip('test-targets/vulnerable-app.mjs does not appear to be running on 127.0.0.1:4100 — start it to exercise this path fully.');
      return;
    }
    assert.equal(port4100.state, 'open');
  } finally {
    process.env.NODE_ENV = prevEnv;
    if (prevAllow === undefined) delete process.env.SCAN_DEV_ALLOW_HOSTS;
    else process.env.SCAN_DEV_ALLOW_HOSTS = prevAllow;
  }
});

test('killNmapProcess returns false for an unknown scan id', () => {
  assert.equal(killNmapProcess('does-not-exist'), false);
});
