import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { parseJwt, probeJwtAuth } from "./jwtProbe.js";

const b64url = (s: string) => Buffer.from(s, "utf8").toString("base64url");
// A realistic HS256 JWT (the signature is fake — the probe never needs a valid one).
const REAL_JWT =
  `${b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }))}.${b64url(JSON.stringify({ sub: "alice", role: "user" }))}.s1gn4tur3`;

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

const headersWith = (jwt: string) => ({ "User-Agent": "test", Authorization: `Bearer ${jwt}` });

test("parseJwt accepts a well-formed Bearer JWT and reads its alg; rejects non-JWTs", () => {
  const p = parseJwt(`Bearer ${REAL_JWT}`);
  assert.ok(p);
  assert.equal(p!.alg, "HS256");
  assert.equal(parseJwt("Bearer not-a-jwt"), null);
  assert.equal(parseJwt("Basic abc123"), null);
  assert.equal(parseJwt(undefined), null);
});

test("flags a server that accepts a forged token where no token is rejected (PROVEN, differential)", async () => {
  // Vulnerable: enforces auth (401 without a token) but accepts ANY Bearer token
  // without verifying the signature.
  await withServer((req, res) => {
    if (!req.headers.authorization) {
      res.writeHead(401, { "Content-Type": "text/html" });
      return res.end("<html>401 Unauthorized</html>");
    }
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end("<html><body>Welcome alice — your private account dashboard balance $9,999</body></html>");
  }, async (port) => {
    const finding = await probeJwtAuth(`http://127.0.0.1:${port}/account`, headersWith(REAL_JWT));
    assert.ok(finding, "expected a JWT-signature-not-verified finding");
    assert.equal(finding!.severity, "critical");
    assert.match(finding!.testName, /JWT Signature Not Verified/);
    assert.equal(finding!.evidence.method, "differential");
    // PROVEN: signal.quote is a literal substring of the captured forged response.
    assert.ok(finding!.evidence.attack.response.includes(finding!.evidence.signal.quote));
    // The control shows the no-token 401.
    assert.match(finding!.evidence.control.response, /401/);
  });
});

test("no finding when the server verifies the signature (rejects forged tokens)", async () => {
  // Secure: only the exact real token is accepted; forged variants get 401.
  await withServer((req, res) => {
    const ok = req.headers.authorization === `Bearer ${REAL_JWT}`;
    res.writeHead(ok ? 200 : 401, { "Content-Type": "text/html" });
    res.end(ok ? "<html>welcome</html>" : "<html>401</html>");
  }, async (port) => {
    const finding = await probeJwtAuth(`http://127.0.0.1:${port}/account`, headersWith(REAL_JWT));
    assert.equal(finding, null, "a server that verifies signatures must not be flagged");
  });
});

test("no finding when the endpoint does not enforce auth (no clean differential)", async () => {
  await withServer((_req, res) => {
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end("<html>public page</html>");
  }, async (port) => {
    const finding = await probeJwtAuth(`http://127.0.0.1:${port}/`, headersWith(REAL_JWT));
    assert.equal(finding, null, "cannot prove a bypass where auth is not enforced at all");
  });
});

test("no-op when the scan carries no Bearer JWT", async () => {
  const finding = await probeJwtAuth("http://127.0.0.1:1/", { "User-Agent": "test" });
  assert.equal(finding, null);
});
