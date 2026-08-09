import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { probeWebhookSignatureBypass } from "./webhookSignatureProbe.js";

function readBody(req: http.IncomingMessage): Promise<any> {
  return new Promise((resolve) => {
    let raw = ""; req.on("data", (d) => (raw += d));
    req.on("end", () => { try { resolve(JSON.parse(raw || "{}")); } catch { resolve({}); } });
  });
}

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
const VALID_SIG = "the-only-valid-signature";

// Vulnerable: verifies the signature only for USD; skips it for other currencies.
const conditional: http.RequestListener = async (req, res) => {
  if (req.url !== "/api/webhooks/stripe" || req.method !== "POST") { res.writeHead(404); return res.end("{}"); }
  const body = await readBody(req);
  const currency = body?.data?.object?.currency;
  if (currency === "usd" && req.headers["stripe-signature"] !== VALID_SIG) {
    res.writeHead(400, { "Content-Type": "application/json" }); return res.end('{"error":"invalid signature"}');
  }
  res.writeHead(200, { "Content-Type": "application/json" }); res.end('{"received":true}');
};

test("proves conditional signature verification (rejected for USD, accepted for another currency)", async () => {
  await withServer(conditional, async (port) => {
    const finding = await probeWebhookSignatureBypass(`http://127.0.0.1:${port}/`, [], H);
    assert.ok(finding, "expected a webhook signature-bypass finding");
    assert.match(finding!.testName, /Webhook Signature Verification Bypass/);
    assert.equal(finding!.evidence.method, "differential");
    assert.match(finding!.evidence.control.response, /400/);
    assert.ok(finding!.evidence.attack.response.includes(finding!.evidence.signal.quote));
  });
});

test("does NOT fire on an endpoint that verifies the signature unconditionally (no false positive)", async () => {
  const safe: http.RequestListener = (req, res) => {
    if (req.url !== "/api/webhooks/stripe") { res.writeHead(404); return res.end("{}"); }
    // Always rejects a bad signature, regardless of currency.
    if (req.headers["stripe-signature"] !== VALID_SIG) { res.writeHead(400, { "Content-Type": "application/json" }); return res.end('{"error":"invalid signature"}'); }
    res.writeHead(200, { "Content-Type": "application/json" }); res.end('{"received":true}');
  };
  await withServer(safe, async (port) => {
    assert.equal(await probeWebhookSignatureBypass(`http://127.0.0.1:${port}/`, [], H), null);
  });
});

test("does NOT fire when the endpoint accepts everything (ambiguous / not a provable conditional bypass)", async () => {
  const openAll: http.RequestListener = (_req, res) => { res.writeHead(200, { "Content-Type": "application/json" }); res.end('{"received":true}'); };
  await withServer(openAll, async (port) => {
    // control (USD) is accepted, so the required "rejected-for-USD" precondition fails → no finding.
    assert.equal(await probeWebhookSignatureBypass(`http://127.0.0.1:${port}/`, [], H), null);
  });
});

test("finds a webhook endpoint supplied via discovered POST targets (off the guess list)", async () => {
  const handler: http.RequestListener = async (req, res) => {
    if (req.url !== "/events/inbound") { res.writeHead(404); return res.end("{}"); }
    const body = await readBody(req);
    if (body?.data?.object?.currency === "usd") { res.writeHead(400); return res.end('{"error":"invalid signature"}'); }
    res.writeHead(200, { "Content-Type": "application/json" }); res.end('{"received":true}');
  };
  await withServer(handler, async (port) => {
    const finding = await probeWebhookSignatureBypass(`http://127.0.0.1:${port}/`, [`http://127.0.0.1:${port}/events/inbound`], H);
    assert.ok(finding, "expected the discovered webhook endpoint to be caught");
    assert.match(finding!.evidence.attack.request, /\/events\/inbound/);
  });
});
