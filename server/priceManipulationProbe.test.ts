import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { probePriceManipulation } from "./priceManipulationProbe.js";

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

function readBody(req: http.IncomingMessage): Promise<any> {
  return new Promise((resolve) => {
    let raw = ""; req.on("data", (d) => (raw += d));
    req.on("end", () => { try { resolve(JSON.parse(raw || "{}")); } catch { resolve({}); } });
  });
}

const H = { "User-Agent": "test" };

test("proves price tampering when the charge total tracks the client-supplied price", async () => {
  const handler: http.RequestListener = async (req, res) => {
    if (req.url !== "/api/checkout" || req.method !== "POST") { res.writeHead(404); return res.end("{}"); }
    const body = await readBody(req);
    let total = 0;
    for (const it of body.items || []) total += Number(it.price) * Number(it.quantity); // VULNERABLE
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ success: true, chargeAmount: Math.round(total * 100) / 100, orderId: "ord_x" }));
  };
  await withServer(handler, async (port) => {
    const finding = await probePriceManipulation(`http://127.0.0.1:${port}/`, [], H);
    assert.ok(finding, "expected a price-tampering finding");
    assert.match(finding!.testName, /Price Tampering/i);
    assert.equal(finding!.severity, "high");
    assert.equal(finding!.evidence.method, "differential");
    assert.ok(finding!.evidence.attack.response.includes(finding!.evidence.signal.quote));
  });
});

test("does NOT fire on a server-sourced price (safe endpoint ignores the client price)", async () => {
  const handler: http.RequestListener = async (req, res) => {
    if (req.url !== "/api/checkout" || req.method !== "POST") { res.writeHead(404); return res.end("{}"); }
    const body = await readBody(req);
    // SAFE: price is looked up server-side (fixed), client price ignored.
    let total = 0;
    for (const it of body.items || []) total += 50 * Number(it.quantity); // server price = 50, not client's
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ success: true, chargeAmount: total, orderId: "ord_x" }));
  };
  await withServer(handler, async (port) => {
    assert.equal(await probePriceManipulation(`http://127.0.0.1:${port}/`, [], H), null);
  });
});

test("does NOT false-fire on a plain echo endpoint (reflects price but never price*quantity)", async () => {
  // Echoes the whole body back — the client price appears, but no COMPUTED
  // price*quantity total does, so the probe must not flag it.
  const handler: http.RequestListener = async (req, res) => {
    const body = await readBody(req);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ success: true, echoed: body }));
  };
  await withServer(handler, async (port) => {
    const finding = await probePriceManipulation(`http://127.0.0.1:${port}/`, [`http://127.0.0.1:${port}/api/echo`], H);
    assert.equal(finding, null, "an echo of the request must not be mistaken for a computed charge");
  });
});

test("finds a checkout endpoint supplied only via discovered POST targets (not the guess list)", async () => {
  const handler: http.RequestListener = async (req, res) => {
    if (req.url !== "/store/pay-now") { res.writeHead(404); return res.end("{}"); }
    const body = await readBody(req);
    let total = 0;
    for (const it of body.items || []) total += Number(it.price) * Number(it.quantity);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, grandTotal: total }));
  };
  await withServer(handler, async (port) => {
    const finding = await probePriceManipulation(`http://127.0.0.1:${port}/`, [`http://127.0.0.1:${port}/store/pay-now`], H);
    assert.ok(finding, "expected the discovered-target checkout to be caught");
    assert.match(finding!.evidence.attack.request, /\/store\/pay-now/);
  });
});
