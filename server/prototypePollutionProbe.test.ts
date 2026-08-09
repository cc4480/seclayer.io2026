import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { probePrototypePollution } from "./prototypePollutionProbe.js";

// A minimal app modeling the real vulnerability shape: an endpoint that
// deep-merges the request body into an object with NO __proto__ guard, and
// formats its JSON response using a value read from a plain (pollutable) config
// object via unguarded bracket access. Once Object.prototype["json spaces"] is
// polluted, the config read inherits it and output flips compact -> indented.
function vulnerableHandler(): http.RequestListener {
  const appConfig: Record<string, unknown> = {}; // plain object → inherits Object.prototype
  const unsafeMerge = (target: any, src: any): any => {
    for (const key in src) {
      if (src[key] && typeof src[key] === "object" && !Array.isArray(src[key])) {
        if (typeof target[key] !== "object" || target[key] === null) target[key] = {};
        unsafeMerge(target[key], src[key]);
      } else {
        target[key] = src[key];
      }
    }
    return target;
  };
  return (req, res) => {
    if (req.method !== "POST") { res.writeHead(404); return res.end("nope"); }
    let raw = "";
    req.on("data", (d) => (raw += d));
    req.on("end", () => {
      let body: any;
      try { body = JSON.parse(raw || "{}"); } catch { res.writeHead(400); return res.end('{"error":"bad json"}'); }
      const session = unsafeMerge({}, body);
      const spaces = (appConfig as any)["json spaces"] || 0; // unguarded, pollutable read
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ success: true, session }, null, spaces));
    });
  };
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

test("proves prototype pollution via the json-spaces formatting gadget (differential)", async () => {
  await withServer(vulnerableHandler(), async (port) => {
    const base = `http://127.0.0.1:${port}`;
    const finding = await probePrototypePollution(base + "/", [base + "/api/merge"], H);
    assert.ok(finding, "expected a prototype-pollution finding");
    assert.match(finding!.testName, /Prototype Pollution/i);
    assert.equal(finding!.severity, "high");
    assert.equal(finding!.evidence.method, "differential");
    // PROVEN: the quoted indentation signal is a literal substring of the attack response.
    assert.ok(finding!.evidence.attack.response.includes(finding!.evidence.signal.quote));
  });
});

test("does NOT fire on an endpoint that does not merge into a pollutable object (no false positive)", async () => {
  // Echoes the body back but never merges into an object whose prototype leaks,
  // and formats with a FIXED indentation — so the gadget can't change anything.
  const safe: http.RequestListener = (req, res) => {
    if (req.method !== "POST") { res.writeHead(404); return res.end("nope"); }
    let raw = ""; req.on("data", (d) => (raw += d));
    req.on("end", () => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true })); // always compact, no config read
    });
  };
  await withServer(safe, async (port) => {
    const base = `http://127.0.0.1:${port}`;
    const finding = await probePrototypePollution(base + "/", [base + "/api/echo"], H);
    assert.equal(finding, null, "a non-pollutable endpoint must not be flagged");
  });
});

test("does NOT fire when the endpoint returns non-JSON (nothing to observe)", async () => {
  const htmlOnly: http.RequestListener = (_req, res) => { res.writeHead(200, { "Content-Type": "text/html" }); res.end("<html>ok</html>"); };
  await withServer(htmlOnly, async (port) => {
    const base = `http://127.0.0.1:${port}`;
    assert.equal(await probePrototypePollution(base + "/", [base + "/x"], H), null);
  });
});

test("reverts the gadget after proving it (best-effort restore to compact formatting)", async () => {
  await withServer(vulnerableHandler(), async (port) => {
    const base = `http://127.0.0.1:${port}`;
    const finding = await probePrototypePollution(base + "/", [base + "/api/merge"], H);
    assert.ok(finding);
    // After the probe, a fresh benign request must come back compact again.
    const res = await fetch(base + "/api/merge", { method: "POST", headers: { "Content-Type": "application/json" }, body: '{"z":1}' });
    const text = await res.text();
    assert.ok(!text.includes("\n       "), "formatting should be reverted to compact after the probe");
  });
});
