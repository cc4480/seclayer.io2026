import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { probeEdgeFunctionAuth, extractEdgeFunctionUrls } from "./edgeFunctionProbe.js";

test("extractEdgeFunctionUrls: absolute URL, relative path + base, and functions.invoke()", () => {
  const abs = extractEdgeFunctionUrls([`fetch("http://api.example.com/functions/v1/do-thing")`]);
  assert.deepEqual(abs, ["http://api.example.com/functions/v1/do-thing"]);

  const rel = extractEdgeFunctionUrls([
    `window.SUPABASE_URL = "http://127.0.0.1:54321"; fetch(SUPABASE_URL + "/functions/v1/sensitive-task")`,
  ]);
  assert.ok(rel.includes("http://127.0.0.1:54321/functions/v1/sensitive-task"));

  const invoke = extractEdgeFunctionUrls([
    `const API_URL = "https://x.co"; supabase.functions.invoke('exporter')`,
  ]);
  assert.ok(invoke.includes("https://x.co/functions/v1/exporter"));

  assert.deepEqual(extractEdgeFunctionUrls(["nothing here"]), []);
});

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

const H = { "User-Agent": "test" };
const content = (port: number) => [`fetch("http://127.0.0.1:${port}/functions/v1/sensitive-task")`];

test("proves an Edge Function that accepts any token where no token is denied", async () => {
  // VULNERABLE: 401 with no Authorization header, but accepts ANY header value.
  await withServer((req, res) => {
    if (req.url !== "/functions/v1/sensitive-task") { res.writeHead(404); return res.end("{}"); }
    if (!req.headers.authorization) { res.writeHead(401, { "Content-Type": "application/json" }); return res.end('{"error":"Unauthorized"}'); }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end('{"success":true,"dataExported":"sk_admin_secret"}');
  }, async (port) => {
    const finding = await probeEdgeFunctionAuth(content(port), H);
    assert.ok(finding, "expected an Edge Function auth-bypass finding");
    assert.match(finding!.testName, /Edge Function Authorization Bypass/);
    assert.equal(finding!.severity, "critical");
    assert.match(finding!.evidence.control.response, /401/);
    assert.ok(finding!.evidence.attack.response.includes(finding!.evidence.signal.quote));
  });
});

test("does NOT fire when the function actually verifies the token (forged token rejected)", async () => {
  await withServer((req, res) => {
    if (req.url !== "/functions/v1/sensitive-task") { res.writeHead(404); return res.end("{}"); }
    const ok = req.headers.authorization === "Bearer the-only-valid-token";
    res.writeHead(ok ? 200 : 401, { "Content-Type": "application/json" });
    res.end(ok ? '{"success":true}' : '{"error":"Unauthorized"}');
  }, async (port) => {
    assert.equal(await probeEdgeFunctionAuth(content(port), H), null);
  });
});

test("does NOT fire when the function is simply public (no token also returns 200)", async () => {
  await withServer((_req, res) => { res.writeHead(200, { "Content-Type": "application/json" }); res.end('{"ok":true}'); },
    async (port) => { assert.equal(await probeEdgeFunctionAuth(content(port), H), null); });
});

test("no-op when the scanned content references no Edge Function", async () => {
  assert.equal(await probeEdgeFunctionAuth(["<html>nothing</html>"], H), null);
});
