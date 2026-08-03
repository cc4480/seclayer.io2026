import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectNmap, isNmapAvailable, nmapVersionString } from './detect.js';

// No mocking: this genuinely probes whatever nmap binary (if any) is on PATH
// in the environment running the tests, and asserts on whichever branch is
// real — so it passes identically on a machine with nmap installed (most
// self-hosted/dev setups once this feature is adopted) and one without (CI,
// a bare `npm run dev` checkout, the Vercel-hosted deployment's build step).
test('detectNmap reports availability consistently with isNmapAvailable/nmapVersionString', async () => {
  const detection = await detectNmap();

  assert.equal(isNmapAvailable(), detection.available);

  if (detection.available) {
    assert.equal(typeof detection.version, 'string');
    assert.ok(detection.version!.length > 0);
    assert.equal(nmapVersionString(), detection.version);
  } else {
    assert.equal(typeof detection.error, 'string');
    assert.equal(nmapVersionString(), undefined);
  }
});

test('detectNmap is memoized — a second call returns the same cached result', async () => {
  const first = await detectNmap();
  const second = await detectNmap();
  assert.deepEqual(second, first);
});
