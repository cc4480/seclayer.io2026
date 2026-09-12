import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { signaturePreexists } from "./baseline.js";

// The guard that stops a signature-matching probe from reporting page content it
// did not cause. Seven CRITICAL false positives at high confidence came from its
// absence — six Path Traversal and one SSRF, all against a target whose
// documentation quotes the very strings the probes match on.

const PASSWD = /root:[^:\n]*:0:0:/;

// Loopback is blocked by the SSRF guard unless this dev-only escape hatch names
// the exact host:port — same pattern the other probe tests use.
async function withServer(
  body: string,
  fn: (url: string) => Promise<void>,
  status = 200,
): Promise<void> {
  const server = http.createServer((_req, res) => {
    res.writeHead(status, { "Content-Type": "text/html" });
    res.end(body);
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as { port: number }).port;
  const prev = process.env.SCAN_DEV_ALLOW_HOSTS;
  process.env.SCAN_DEV_ALLOW_HOSTS = `127.0.0.1:${port}`;
  try {
    await fn(`http://127.0.0.1:${port}/`);
  } finally {
    if (prev === undefined) delete process.env.SCAN_DEV_ALLOW_HOSTS;
    else process.env.SCAN_DEV_ALLOW_HOSTS = prev;
    await new Promise<void>((r) => server.close(() => r()));
  }
}

test("reports a signature that is already in the page as pre-existing", async () => {
  // The hardened reference target's shape: the passwd line as documentation.
  const page = "<h1>Runbook</h1><pre>root:x:0:0:root:/root:/bin/bash</pre>";
  await withServer(page, async (url) => {
    assert.equal(await signaturePreexists(url, {}, PASSWD), true);
  });
});

test("reports a clean page as not pre-existing, so a real finding still fires", async () => {
  await withServer("<h1>Shop</h1><p>Nothing to see.</p>", async (url) => {
    assert.equal(await signaturePreexists(url, {}, PASSWD), false);
  });
});

// A probe would otherwise be blinded by an unrelated near-miss: the word "root"
// alone, or a passwd-shaped line for a non-zero uid, must not count.
test("does not treat a near-miss as the signature", async () => {
  const page = "<p>Run as root. daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin</p>";
  await withServer(page, async (url) => {
    assert.equal(await signaturePreexists(url, {}, PASSWD), false);
  });
});

// Fails CLOSED. A probe that reported a critical vulnerability because its
// control request happened to fail would be worse than one that stays quiet;
// the next scan re-tests it anyway.
test("treats an unreachable baseline as pre-existing rather than assuming clean", async () => {
  const prev = process.env.SCAN_DEV_ALLOW_HOSTS;
  process.env.SCAN_DEV_ALLOW_HOSTS = "127.0.0.1:1";
  try {
    // Port 1 on loopback: nothing listens, so the fetch fails.
    assert.equal(await signaturePreexists("http://127.0.0.1:1/", {}, PASSWD), true);
  } finally {
    if (prev === undefined) delete process.env.SCAN_DEV_ALLOW_HOSTS;
    else process.env.SCAN_DEV_ALLOW_HOSTS = prev;
  }
});

// A /g regex carries lastIndex between calls, so the same pattern used for the
// attack test and then this one would resume mid-string and silently miss.
test("a global regex does not carry match state between calls", async () => {
  const page = "<pre>root:x:0:0:root:/root:/bin/bash</pre>";
  const globalSig = /root:[^:\n]*:0:0:/g;
  await withServer(page, async (url) => {
    assert.equal(await signaturePreexists(url, {}, globalSig), true);
    // Second call must agree — it would not if lastIndex leaked.
    assert.equal(await signaturePreexists(url, {}, globalSig), true);
  });
});

test("finds the signature regardless of the baseline's status code", async () => {
  // The hardened target answers 400 for a rejected parameter and STILL serves
  // its documentation, so the guard has to read the body of an error page too.
  const page = "<p>Bad request</p><pre>root:x:0:0:root:/root:/bin/bash</pre>";
  await withServer(page, async (url) => {
    assert.equal(await signaturePreexists(url, {}, PASSWD), true);
  }, 400);
});
