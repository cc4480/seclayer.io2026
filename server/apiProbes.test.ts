import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { exposedCredentialListInCapture, runApiSecProbes } from "./apiProbes.js";

// Same loopback escape hatch the fuzzer/scanner tests use: safeFetch blocks
// loopback unless SCAN_DEV_ALLOW_HOSTS names this exact host:port in dev.
async function withServer(handler: http.RequestListener, fn: (port: number) => Promise<void>) {
  const server = http.createServer(handler);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as any).port;
  const prevEnv = process.env.NODE_ENV;
  const prevAllow = process.env.SCAN_DEV_ALLOW_HOSTS;
  try {
    process.env.NODE_ENV = "development";
    process.env.SCAN_DEV_ALLOW_HOSTS = `127.0.0.1:${port}`;
    await fn(port);
  } finally {
    if (prevEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = prevEnv;
    if (prevAllow === undefined) delete process.env.SCAN_DEV_ALLOW_HOSTS; else process.env.SCAN_DEV_ALLOW_HOSTS = prevAllow;
    await new Promise<void>((r) => server.close(() => r()));
  }
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve) => { let d = ""; req.on("data", (c) => (d += c)); req.on("end", () => resolve(d)); });
}

const HEADERS = { "User-Agent": "test", "Cache-Control": "no-cache" };

const SRC = "http://127.0.0.1:4103/api/tokens";

test("flags a per-user credential dump (session_tokens shape) with real evidence", () => {
  const body = JSON.stringify([
    { id: "1", user_id: "aaa", token: "fake-plaintext-session-token-alice", created_at: "t" },
    { id: "2", user_id: "bbb", token: "fake-plaintext-session-token-bob", created_at: "t" },
  ]);
  const f = exposedCredentialListInCapture(body, SRC);
  assert.ok(f, "expected a credential-list finding");
  assert.equal(f!.testName, "Exposed Credential List Endpoint");
  assert.equal(f!.severity, "critical");
  // PROVEN-style: the quoted signal is a literal substring of the captured response.
  assert.ok(f!.evidence.attack.response.includes(f!.evidence.signal.quote));
  assert.match(f!.evidence.signal.quote, /fake-plaintext-session-token/);
});

test("also catches api_key / access_token field names, not just 'token'", () => {
  const body = JSON.stringify([
    { userId: 1, api_key: "sk_live_abcdefghijklmnop" },
    { userId: 2, api_key: "sk_live_qrstuvwxyz012345" },
  ]);
  const f = exposedCredentialListInCapture(body, SRC);
  assert.ok(f);
  assert.match(f!.description, /api_key/);
});

test("does NOT fire on a profile list with no credential field (left to the user-list check)", () => {
  const body = JSON.stringify([
    { user_id: "a", email: "alice@corp.test", sensitive_data: "alice-ssn" },
    { user_id: "b", email: "bob@corp.test", sensitive_data: "bob-ssn" },
  ]);
  assert.equal(exposedCredentialListInCapture(body, SRC), null);
});

test("does NOT fire on a credential value with no co-located user identifier", () => {
  // A bare list of tokens with nothing tying each to a user — far weaker
  // signal, could be one caller's rotating tokens; deliberately not flagged.
  const body = JSON.stringify([
    { token: "some-standalone-token-value-1" },
    { token: "some-standalone-token-value-2" },
  ]);
  assert.equal(exposedCredentialListInCapture(body, SRC), null);
});

test("does NOT fire when the same constant credential is repeated (not a per-user dump)", () => {
  const body = JSON.stringify([
    { user_id: "a", token: "same-token-value-constant" },
    { user_id: "b", token: "same-token-value-constant" },
  ]);
  assert.equal(exposedCredentialListInCapture(body, SRC), null);
});

test("does NOT fire on a single record, a non-array, or a short/absent value", () => {
  assert.equal(exposedCredentialListInCapture(JSON.stringify([{ user_id: "a", token: "long-enough-token-1" }]), SRC), null); // 1 element
  assert.equal(exposedCredentialListInCapture(JSON.stringify({ user_id: "a", token: "long-enough-token-1" }), SRC), null); // object, not array
  assert.equal(exposedCredentialListInCapture(JSON.stringify([{ user_id: "a", token: "short" }, { user_id: "b", token: "tiny" }]), SRC), null); // values < 8 chars
  assert.equal(exposedCredentialListInCapture("not json", SRC), null);
  assert.equal(exposedCredentialListInCapture("", SRC), null);
});

test("does NOT fire when only SOME rows carry the credential (must be every row)", () => {
  const body = JSON.stringify([
    { user_id: "a", token: "a-real-token-value-here" },
    { user_id: "b", note: "no token on this one" },
  ]);
  assert.equal(exposedCredentialListInCapture(body, SRC), null);
});

test("GraphQL cost probe: flags alias amplification when the server resolves every aliased __typename", async () => {
  await withServer(async (req, res) => {
    if (req.method === "POST" && req.url === "/graphql") {
      const body = await readBody(req);
      let query = "";
      try { query = JSON.parse(body).query || ""; } catch { /* not json */ }
      // Resolve every aX:__typename the client asked for — an uncapped server.
      const data: Record<string, string> = {};
      for (const m of query.matchAll(/a(\d+):__typename/g)) data[`a${m[1]}`] = "Query";
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(Object.keys(data).length ? { data } : { data: { __typename: "Query" } }));
      return;
    }
    res.writeHead(404); res.end("nope");
  }, async (port) => {
    const findings = await runApiSecProbes(`http://127.0.0.1:${port}`, `127.0.0.1:${port}`, HEADERS);
    const cost = findings.find((f) => /Query-Cost Controls/i.test(f.testName));
    assert.ok(cost, "expected a GraphQL cost-control finding on an uncapped endpoint");
    assert.equal(cost.severity, "medium");
    assert.match(cost.evidence.signal.quote, /^"a\d+"$/, "receipt quotes a late resolved alias");
  });
});

test("GraphQL cost probe: does NOT flag a server that caps query cost (rejects the batch)", async () => {
  await withServer(async (req, res) => {
    if (req.method === "POST" && req.url === "/graphql") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ errors: [{ message: "Query exceeds maximum operation cost of 100" }] }));
      return;
    }
    res.writeHead(404); res.end("nope");
  }, async (port) => {
    const findings = await runApiSecProbes(`http://127.0.0.1:${port}`, `127.0.0.1:${port}`, HEADERS);
    assert.ok(!findings.some((f) => /Query-Cost Controls/i.test(f.testName)), "a cost-capped server must not be flagged");
  });
});

test("GraphQL cost probe: does NOT flag a non-GraphQL endpoint (no data object)", async () => {
  await withServer((req, res) => { res.writeHead(404); res.end("not here"); }, async (port) => {
    const findings = await runApiSecProbes(`http://127.0.0.1:${port}`, `127.0.0.1:${port}`, HEADERS);
    assert.ok(!findings.some((f) => /Query-Cost Controls/i.test(f.testName)), "no /graphql endpoint => no finding");
  });
});
