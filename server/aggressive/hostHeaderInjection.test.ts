import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { probeHostHeaderInjection } from "./hostHeaderInjection.js";
import type { ProbeContext } from "../redTeam/types.js";

async function withServer(handler: http.RequestListener, fn: (port: number) => Promise<void>) {
  const server = http.createServer(handler);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as AddressInfo).port;
  const prevEnv = process.env.NODE_ENV;
  const prevAllow = process.env.SCAN_DEV_ALLOW_HOSTS;
  try {
    process.env.NODE_ENV = "development";
    process.env.SCAN_DEV_ALLOW_HOSTS = `127.0.0.1:${port}`;
    await fn(port);
  } finally {
    if (prevEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = prevEnv;
    if (prevAllow === undefined) delete process.env.SCAN_DEV_ALLOW_HOSTS; else process.env.SCAN_DEV_ALLOW_HOSTS = prevAllow;
    await new Promise((r) => server.close(r));
  }
}

const ctxFor = (port: number): ProbeContext => ({
  url: `http://127.0.0.1:${port}`,
  fuzzHeaders: { "User-Agent": "test", "Cache-Control": "no-cache" },
});

test("flags host-header injection reflected into a redirect Location (high, proven)", async () => {
  await withServer((req, res) => {
    const xfh = req.headers["x-forwarded-host"];
    // Vulnerable: builds an absolute redirect from the forwarded host.
    res.writeHead(302, { Location: `https://${xfh}/dashboard` });
    res.end();
  }, async (port) => {
    const finding = await probeHostHeaderInjection(ctxFor(port));
    assert.ok(finding, "expected a host-header-injection finding");
    assert.equal(finding!.severity, "high");
    assert.ok(finding!.evidence!.attack.response.includes(finding!.evidence!.signal.quote));
  });
});

test("flags host-header injection reflected into an absolute URL in the body (medium, proven)", async () => {
  await withServer((req, res) => {
    const xfh = req.headers["x-forwarded-host"];
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(`<!doctype html><html><head><link rel="canonical" href="https://${xfh}/"></head><body>hi</body></html>`);
  }, async (port) => {
    const finding = await probeHostHeaderInjection(ctxFor(port));
    assert.ok(finding, "expected a reflected host-header finding");
    assert.equal(finding!.severity, "medium");
    assert.ok(finding!.evidence!.attack.response.includes(finding!.evidence!.signal.quote));
  });
});

test("returns null when the app ignores X-Forwarded-Host (no false positive)", async () => {
  await withServer((_req, res) => {
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end('<!doctype html><html><head><link rel="canonical" href="https://real-site.example/"></head><body>hi</body></html>');
  }, async (port) => {
    assert.equal(await probeHostHeaderInjection(ctxFor(port)), null);
  });
});
