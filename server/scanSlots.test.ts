import { test } from 'node:test';
import assert from 'node:assert/strict';

process.env.DB_PATH = ':memory:';
process.env.MAX_CONCURRENT_SCANS = '2';
const { scanSlots } = await import('./scanWorker.js');

// /api/mcp/scan ran runDiagnostics directly in its request handler, so it was
// governed by nothing: N concurrent MCP requests started N concurrent scans on
// that instance regardless of maxConcurrentScans. Both entry points must draw
// from ONE pool, or the cap means nothing on whichever path skips it.
test('the scan slot pool is shared and actually caps concurrency', async () => {
  let running = 0;
  let peak = 0;
  const job = () => scanSlots.run(async () => {
    running += 1;
    peak = Math.max(peak, running);
    await new Promise((r) => setTimeout(r, 40));
    running -= 1;
  });

  // Six callers at once, from either entry point, against a cap of 2.
  await Promise.all([job(), job(), job(), job(), job(), job()]);

  assert.equal(peak, 2, `at most maxConcurrentScans may run at once, saw ${peak}`);
  assert.equal(running, 0, 'every slot must be released');
});

test('a slot is released even when the scan throws', async () => {
  // A failing scan that kept its slot would starve the instance one leak at a
  // time until nothing could run.
  await assert.rejects(scanSlots.run(async () => { throw new Error('scan blew up'); }), /scan blew up/);
  assert.equal(scanSlots.activeCount, 0, 'a thrown scan must not leak its slot');
});
