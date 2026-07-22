import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import type { AddressInfo } from "node:net";
import { scan } from "./client.js";

async function withServer(handler: http.RequestListener, fn: (baseUrl: string) => Promise<void>) {
  const server = http.createServer(handler);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as AddressInfo).port;
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((r) => server.close(r));
  }
}

// A bound-then-closed ephemeral port: nothing is listening there, so a
// connection attempt fails instantly (ECONNREFUSED), no network-timeout wait.
async function reserveClosedPort(): Promise<number> {
  const srv = net.createServer();
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", () => r()));
  const port = (srv.address() as AddressInfo).port;
  await new Promise((r) => srv.close(r));
  return port;
}

test("scan sends the API key in the request body, not a header, and parses a 200", async () => {
  let receivedBody: any;
  await withServer(
    (req, res) => {
      let raw = "";
      req.on("data", (c) => (raw += c));
      req.on("end", () => {
        receivedBody = JSON.parse(raw);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          success: true, targetUrl: "https://x.test", postureScore: 90, vulnerabilityLevel: "low",
          analysisSummary: "clean", executiveBreakdown: { overview: "o", riskAreas: [], businessImpact: "b", priorityActions: [] },
          securityFindings: [], creditsRemaining: 10,
        }));
      });
    },
    async (baseUrl) => {
      const outcome = await scan(baseUrl, "sl_live_test", { url: "https://x.test", authHeader: "Bearer abc" });
      assert.equal(outcome.ok, true);
      assert.equal((outcome as any).data.postureScore, 90);
      assert.deepEqual(receivedBody, { url: "https://x.test", apiKey: "sl_live_test", authHeader: "Bearer abc" });
    },
  );
});

test("scan maps a 400 to bad_request with the backend's detail message", async () => {
  await withServer(
    (_req, res) => {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Target URL cannot be scanned." }));
    },
    async (baseUrl) => {
      const outcome = await scan(baseUrl, "key", { url: "https://x.test" });
      assert.equal(outcome.ok, false);
      assert.equal((outcome as any).kind, "bad_request");
      assert.match((outcome as any).message, /Target URL cannot be scanned\./);
    },
  );
});

test("scan maps a 401 to unauthorized", async () => {
  await withServer(
    (_req, res) => {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Invalid API Key, active key required, or insufficient credits." }));
    },
    async (baseUrl) => {
      const outcome = await scan(baseUrl, "bad-key", { url: "https://x.test" });
      assert.equal(outcome.ok, false);
      assert.equal((outcome as any).kind, "unauthorized");
    },
  );
});

test("scan maps a 429 to rate_limited and captures Retry-After", async () => {
  await withServer(
    (_req, res) => {
      res.writeHead(429, { "Content-Type": "application/json", "Retry-After": "37" });
      res.end(JSON.stringify({ status: "error", message: "Too many requests." }));
    },
    async (baseUrl) => {
      const outcome = await scan(baseUrl, "key", { url: "https://x.test" });
      assert.equal(outcome.ok, false);
      assert.equal((outcome as any).kind, "rate_limited");
      assert.equal((outcome as any).retryAfterSeconds, 37);
    },
  );
});

test("scan maps a 500 to server_error and surfaces the refunded credit count", async () => {
  await withServer(
    (_req, res) => {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Internal audit scanning failed", details: "boom", creditsRemaining: 12 }));
    },
    async (baseUrl) => {
      const outcome = await scan(baseUrl, "key", { url: "https://x.test" });
      assert.equal(outcome.ok, false);
      assert.equal((outcome as any).kind, "server_error");
      assert.match((outcome as any).message, /refunded/);
      assert.match((outcome as any).message, /credits remaining: 12/);
    },
  );
});

test("scan maps a connection refusal to a network error", async () => {
  const closedPort = await reserveClosedPort();
  const outcome = await scan(`http://127.0.0.1:${closedPort}`, "key", { url: "https://x.test" });
  assert.equal(outcome.ok, false);
  assert.equal((outcome as any).kind, "network");
});

test("scan maps a stalled backend to a timeout using the injected timeoutMs", async () => {
  await withServer(
    (_req, _res) => {
      // Never responds — simulates a stalled/hung backend.
    },
    async (baseUrl) => {
      const start = Date.now();
      const outcome = await scan(baseUrl, "key", { url: "https://x.test" }, 200);
      const elapsed = Date.now() - start;
      assert.equal(outcome.ok, false);
      assert.equal((outcome as any).kind, "timeout");
      assert.ok(elapsed < 2000, `expected the abort near 200ms, took ${elapsed}ms`);
    },
  );
});

test("scan maps a non-JSON 200 response to malformed", async () => {
  await withServer(
    (_req, res) => {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end("<html>not json</html>");
    },
    async (baseUrl) => {
      const outcome = await scan(baseUrl, "key", { url: "https://x.test" });
      assert.equal(outcome.ok, false);
      assert.equal((outcome as any).kind, "malformed");
    },
  );
});

test("scan maps a 200 missing success:true to malformed", async () => {
  await withServer(
    (_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    },
    async (baseUrl) => {
      const outcome = await scan(baseUrl, "key", { url: "https://x.test" });
      assert.equal(outcome.ok, false);
      assert.equal((outcome as any).kind, "malformed");
    },
  );
});
