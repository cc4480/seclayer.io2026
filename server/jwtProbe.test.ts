import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import crypto from "node:crypto";
import { parseJwt, probeJwtAuth, extractJwtSecretCandidates } from "./jwtProbe.js";

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

test("flags privilege escalation when the endpoint gates on a role claim in addition to the signature (Tier2-style)", async () => {
  // A route that (a) accepts an unsigned token — the underlying vuln — but
  // (b) ALSO checks the token's own role claim before granting access. A
  // same-claims forgery (alice's real, non-admin payload with the signature
  // stripped) gets a correct 403 here, which looks identical to "correctly
  // rejected" — only an ESCALATED-claims forgery can prove the bypass.
  await withServer((req, res) => {
    const authz = req.headers.authorization;
    if (!authz) {
      res.writeHead(401, { "Content-Type": "text/html" });
      return res.end("<html>401 Unauthorized</html>");
    }
    const parts = authz.replace(/^Bearer\s+/i, "").split(".");
    let role = "user";
    try {
      role = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")).role;
    } catch {
      // malformed payload — treat as no role
    }
    if (role !== "admin") {
      res.writeHead(403, { "Content-Type": "text/html" });
      return res.end("<html>403 Forbidden</html>");
    }
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end("<html><body>Admin settings — apiKey: sk_test_totally_fake_1234567890</body></html>");
  }, async (port) => {
    const finding = await probeJwtAuth(`http://127.0.0.1:${port}/`, headersWith(REAL_JWT));
    assert.ok(finding, "expected the escalated-role forgery to expose the signature bypass");
    assert.match(finding!.testName, /alg:none\+escalated-role/);
  });
});

test("extractJwtSecretCandidates finds a leaked secret in .env-shaped text", () => {
  const env = "SUPABASE_URL=http://127.0.0.1:54321\nSUPABASE_JWT_SECRET=super-secret-jwt-token-with-at-least-32-characters-long\nPORT=4103\n";
  assert.deepEqual(extractJwtSecretCandidates(env), ["super-secret-jwt-token-with-at-least-32-characters-long"]);
});

test("extractJwtSecretCandidates finds a leaked secret in JSON-shaped text", () => {
  const json = '{"STRIPE_WEBHOOK_SECRET":"whsec_x","JWT_SIGNING_SECRET":"a-real-signing-secret-value-here"}';
  assert.deepEqual(extractJwtSecretCandidates(json), ["a-real-signing-secret-value-here"]);
});

test("extractJwtSecretCandidates ignores short/placeholder values and unrelated keys", () => {
  assert.deepEqual(extractJwtSecretCandidates("JWT_SECRET=short"), []);
  assert.deepEqual(extractJwtSecretCandidates("API_KEY=some-long-value-that-is-not-a-jwt-secret"), []);
  assert.deepEqual(extractJwtSecretCandidates(""), []);
});

test("a leaked signing secret proves a bypass even against a properly-verified signature (NC-002-style target)", async () => {
  // The server ONLY accepts a token whose signature genuinely verifies
  // against SECRET — alg:none and tampered-signature forgeries are both
  // correctly rejected. This is exactly the shape a "safe" negative control
  // presents. The leaked-secret-resign forgery is the only one that can
  // still get through, because it produces a VALIDLY signed token.
  const SECRET = "leaked-signing-secret-for-this-fixture-1234567890";
  function verify(token: string): boolean {
    const parts = token.split(".");
    if (parts.length !== 3) return false;
    const [h, p, s] = parts;
    const expected = crypto.createHmac("sha256", SECRET).update(`${h}.${p}`).digest("base64url");
    return s === expected;
  }
  await withServer((req, res) => {
    const authz = req.headers.authorization;
    const token = authz ? authz.replace(/^Bearer\s+/i, "") : "";
    if (!token || !verify(token)) {
      res.writeHead(401, { "Content-Type": "text/html" });
      return res.end("<html>401 Unauthorized</html>");
    }
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end("<html><body>Welcome — properly verified, apiKey: sk_test_totally_fake_1234567890</body></html>");
  }, async (port) => {
    // Without the secret: correctly NOT flagged (both classic forgeries fail).
    const clean = await probeJwtAuth(`http://127.0.0.1:${port}/account`, headersWith(REAL_JWT));
    assert.equal(clean, null, "must not be flagged when the secret is unknown");

    // With the secret (as if discovered elsewhere in the same scan, e.g. a
    // leaked .env): the resigned forgery gets through.
    const finding = await probeJwtAuth(`http://127.0.0.1:${port}/account`, headersWith(REAL_JWT), [SECRET]);
    assert.ok(finding, "expected the leaked-secret resign to prove a bypass");
    assert.match(finding!.testName, /leaked-secret-resign/);
    assert.equal(finding!.evidence.method, "differential");
  });
});

test("also catches the bypass on a protected sub-path when the root itself is public", async () => {
  // Regression coverage: root used to be the ONLY url ever tested. A very
  // common real shape — a public marketing/nav root, with a specific
  // sub-path (e.g. /api/admin/settings) actually gated — used to make the
  // differential's own precondition (no-token -> 401) unmeetable at root,
  // so the whole probe silently declined on every such target.
  await withServer((req, res) => {
    if (req.url === "/api/admin/settings") {
      if (!req.headers.authorization) {
        res.writeHead(401, { "Content-Type": "text/html" });
        return res.end("<html>401 Unauthorized</html>");
      }
      res.writeHead(200, { "Content-Type": "text/html" });
      return res.end("<html><body>Admin settings — apiKey: sk_test_totally_fake_1234567890</body></html>");
    }
    // Root is a public page — no auth required at all.
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end("<html><body>public homepage</body></html>");
  }, async (port) => {
    const finding = await probeJwtAuth(`http://127.0.0.1:${port}/`, headersWith(REAL_JWT));
    assert.ok(finding, "expected the candidate-path broadening to find the gated sub-path");
    assert.match(finding!.testName, /JWT Signature Not Verified/);
    assert.match(finding!.evidence.attack.request, /\/api\/admin\/settings/);
  });
});

test("also catches the bypass on a crawl-discovered path that isn't in the fixed guess list (Tier3-style /api/profiles-safe)", async () => {
  // Regression coverage: a real live-scan miss against the Tier3 fixture,
  // whose only protected endpoint is /api/profiles-safe — not on
  // COMMON_PROTECTED_PATHS and not shaped like any of those guesses. The
  // crawler discovers it (it's a plain <a href> on the homepage) and feeds it
  // in via discoveredUrls; without that, this probe silently declined on
  // every candidate (all 404, never 401) and no finding was ever produced.
  await withServer((req, res) => {
    if (req.url === "/api/profiles-safe") {
      if (!req.headers.authorization) {
        res.writeHead(401, { "Content-Type": "application/json" });
        return res.end('{"error":"Unauthorized"}');
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end('[{"id":"alice","email":"alice@tier3.test"}]');
    }
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end('<html><body><a href="/api/profiles-safe">Profiles (safe)</a></body></html>');
  }, async (port) => {
    const base = `http://127.0.0.1:${port}`;
    const noDiscovery = await probeJwtAuth(`${base}/`, headersWith(REAL_JWT));
    assert.equal(noDiscovery, null, "the fixed guess list alone must not find this path");

    const finding = await probeJwtAuth(`${base}/`, headersWith(REAL_JWT), [], [`${base}/api/profiles-safe`]);
    assert.ok(finding, "expected the discovered-URL candidate to find the gated endpoint");
    assert.match(finding!.evidence.attack.request, /\/api\/profiles-safe/);
  });
});
