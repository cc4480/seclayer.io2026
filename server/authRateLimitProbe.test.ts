import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { probeAuthRateLimit } from "./authRateLimitProbe.js";

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

test("flags an OTP-verify endpoint that never throttles — at MEDIUM confidence, no PROVEN receipt", async () => {
  const noLimit: http.RequestListener = (req, res) => {
    if (req.url !== "/api/auth/verify-sms") { res.writeHead(404); return res.end("{}"); }
    res.writeHead(400, { "Content-Type": "application/json" }); res.end('{"error":"Invalid code"}');
  };
  await withServer(noLimit, async (port) => {
    const finding = await probeAuthRateLimit(`http://127.0.0.1:${port}/`, [], H);
    assert.ok(finding, "expected a missing-rate-limit finding");
    assert.match(finding!.testName, /No Rate Limiting/i);
    assert.equal(finding!.confidence, "medium", "must be medium confidence, not high");
    assert.equal(finding!.evidence, undefined, "must NOT carry a PROVEN receipt");
  });
});

test("does NOT fire when the endpoint returns 429 within the burst", async () => {
  let hits = 0;
  const limited429: http.RequestListener = (req, res) => {
    if (req.url !== "/api/auth/verify-sms") { res.writeHead(404); return res.end("{}"); }
    hits++;
    if (hits > 3) { res.writeHead(429, { "Content-Type": "application/json" }); return res.end('{"error":"Too many attempts"}'); }
    res.writeHead(400, { "Content-Type": "application/json" }); res.end('{"error":"Invalid code"}');
  };
  await withServer(limited429, async (port) => {
    assert.equal(await probeAuthRateLimit(`http://127.0.0.1:${port}/`, [], H), null);
  });
});

test("does NOT fire when RateLimit-* headers are present (limiter observable from the first response)", async () => {
  const headerLimiter: http.RequestListener = (req, res) => {
    if (req.url !== "/api/auth/verify-sms") { res.writeHead(404); return res.end("{}"); }
    res.writeHead(400, { "Content-Type": "application/json", "RateLimit-Limit": "3", "RateLimit-Remaining": "2" });
    res.end('{"error":"Invalid code"}');
  };
  await withServer(headerLimiter, async (port) => {
    assert.equal(await probeAuthRateLimit(`http://127.0.0.1:${port}/`, [], H), null);
  });
});

test("does NOT fire on a 404 (no such endpoint) or a 200 (accepts anything)", async () => {
  await withServer((_req, res) => { res.writeHead(404); res.end("{}"); }, async (port) => {
    assert.equal(await probeAuthRateLimit(`http://127.0.0.1:${port}/`, [], H), null);
  });
  await withServer((req, res) => {
    if (req.url !== "/api/auth/verify-sms") { res.writeHead(404); return res.end("{}"); }
    res.writeHead(200, { "Content-Type": "application/json" }); res.end('{"ok":true}');
  }, async (port) => {
    assert.equal(await probeAuthRateLimit(`http://127.0.0.1:${port}/`, [], H), null);
  });
});

test("finds a verify endpoint supplied via a discovered POST target matching the hint", async () => {
  const handler: http.RequestListener = (req, res) => {
    if (req.url !== "/custom/2fa/check") { res.writeHead(404); return res.end("{}"); }
    res.writeHead(401, { "Content-Type": "application/json" }); res.end('{"error":"bad code"}');
  };
  await withServer(handler, async (port) => {
    const finding = await probeAuthRateLimit(`http://127.0.0.1:${port}/`, [`http://127.0.0.1:${port}/custom/2fa/check`], H);
    assert.ok(finding, "expected the discovered 2fa endpoint to be tested");
  });
});
