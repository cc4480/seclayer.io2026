import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { probeI18nAuthBypass } from "./i18nProbe.js";

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

const HEADERS = { "User-Agent": "test" };

test("flags a protected route gated on /en/ but not its /es/ sibling (PROVEN, differential)", async () => {
  await withServer((req, res) => {
    if (req.url === "/en/admin/dashboard") {
      res.writeHead(401, { "Content-Type": "application/json" });
      return res.end('{"error":"unauthorized"}');
    }
    if (req.url === "/es/admin/dashboard") {
      res.writeHead(200, { "Content-Type": "text/html" });
      return res.end("<html><body>Panel de Administrador — Ingresos totales: $5,000 USD</body></html>");
    }
    res.writeHead(404); res.end("not found");
  }, async (port) => {
    const base = `http://127.0.0.1:${port}`;
    const finding = await probeI18nAuthBypass(base, [`${base}/en/admin/dashboard`], HEADERS);
    assert.ok(finding, "expected a locale auth-bypass finding");
    assert.equal(finding!.severity, "critical");
    assert.match(finding!.testName, /Language Route Auth Bypass/);
    assert.equal(finding!.evidence.method, "differential");
    assert.ok(finding!.evidence.attack.response.includes(finding!.evidence.signal.quote));
    assert.match(finding!.evidence.control.response, /401/);
  });
});

test("also fires when discovered from the ES side (symmetric — not hardcoded to EN being correct)", async () => {
  await withServer((req, res) => {
    if (req.url === "/es/admin/dashboard") {
      res.writeHead(403, { "Content-Type": "application/json" });
      return res.end('{"error":"forbidden"}');
    }
    if (req.url === "/en/admin/dashboard") {
      res.writeHead(200, { "Content-Type": "text/html" });
      return res.end("<html><body>Admin Dashboard — Total revenue: $5,000 USD</body></html>");
    }
    res.writeHead(404); res.end("not found");
  }, async (port) => {
    const base = `http://127.0.0.1:${port}`;
    const finding = await probeI18nAuthBypass(base, [`${base}/es/admin/dashboard`], HEADERS);
    assert.ok(finding, "expected the reverse-direction bypass to be caught too");
    assert.match(finding!.testName, /es gated, en is not/);
  });
});

test("no finding when both locales are consistently gated (negative control)", async () => {
  await withServer((req, res) => {
    if (req.url === "/en/account" || req.url === "/es/account") {
      res.writeHead(401, { "Content-Type": "application/json" });
      return res.end('{"error":"unauthorized"}');
    }
    res.writeHead(404); res.end("not found");
  }, async (port) => {
    const base = `http://127.0.0.1:${port}`;
    const finding = await probeI18nAuthBypass(base, [`${base}/en/account`, `${base}/es/account`], HEADERS);
    assert.equal(finding, null, "consistent auth across both locales must not be flagged");
  });
});

test("no finding when neither locale enforces auth (nothing to prove a bypass of)", async () => {
  await withServer((req, res) => {
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end("<html><body>public page</body></html>");
  }, async (port) => {
    const base = `http://127.0.0.1:${port}`;
    const finding = await probeI18nAuthBypass(base, [`${base}/en/public`], HEADERS);
    assert.equal(finding, null);
  });
});

test("ignores paths that carry no /en/ or /es/ locale segment", async () => {
  await withServer((req, res) => {
    res.writeHead(401); res.end("nope");
  }, async (port) => {
    const base = `http://127.0.0.1:${port}`;
    const finding = await probeI18nAuthBypass(base, [`${base}/api/admin/dashboard`], HEADERS);
    assert.equal(finding, null);
  });
});
