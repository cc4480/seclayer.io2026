import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import crypto from "node:crypto";
import type { AddressInfo } from "node:net";
import { extractToken, findLoginTarget, probeWeakSessionToken } from "./weakSessionToken.js";
import type { InjectableTarget } from "../crawler.js";

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
const loginTarget = (port: number, contentType?: "form" | "json"): InjectableTarget => ({
  url: `http://127.0.0.1:${port}/login`,
  method: "POST",
  params: ["username", "password"],
  source: "form",
  contentType,
});

test("findLoginTarget picks the POST target with both username- and password-shaped fields", () => {
  const targets: InjectableTarget[] = [
    { url: "https://x/search", method: "GET", params: ["q"], source: "query" },
    { url: "https://x/comment", method: "POST", params: ["text"], source: "form" },
    { url: "https://x/login", method: "POST", params: ["email", "pwd"], source: "form" },
  ];
  const found = findLoginTarget(targets);
  assert.ok(found);
  assert.equal(found!.url, "https://x/login");
});

test("findLoginTarget returns null when nothing looks like a login form", () => {
  const targets: InjectableTarget[] = [{ url: "https://x/comment", method: "POST", params: ["text"], source: "form" }];
  assert.equal(findLoginTarget(targets), null);
});

test("extractToken reads a JSON token field, or falls back to Set-Cookie", () => {
  assert.equal(extractToken('{"token":"abc12345"}', "application/json", []), "abc12345");
  assert.equal(extractToken('{"sessionId":"xyz98765"}', "application/json", []), "xyz98765");
  assert.equal(extractToken("not json", "text/html", ["sid=cookieval123; Path=/"]), "cookieval123");
  assert.equal(extractToken("{}", "application/json", []), null);
});

test("proves a predictable MD5(username+timestamp) session token — the exact weak pattern this targets", async () => {
  await withServer((req, res) => {
    if (req.method === "POST" && req.url === "/login") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const params = new URLSearchParams(body);
        const token = crypto.createHash("md5").update(params.get("username") + String(Math.floor(Date.now() / 1000))).digest("hex");
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: true, token }));
      });
      return;
    }
    res.writeHead(404); res.end();
  }, async (port) => {
    const finding = await probeWeakSessionToken(loginTarget(port), { username: "carlos", password: "whatever" }, HEADERS);
    assert.ok(finding, "expected the weak-token pattern to be reproduced and proven");
    assert.equal(finding!.severity, "critical");
    assert.match(finding!.testName, /Predictable Session Token/);
    assert.match(finding!.payload, /^md5\(/);
    // PROVEN invariant: the quoted signal is a literal substring of the captured response text.
    assert.ok(finding!.evidence.attack.response.includes(finding!.evidence.signal.quote));
    // The reproduction command must be a single, syntactically valid, copy-pasteable
    // shell argument — no unescaped nested double quotes — AND must actually
    // recompute the exact same token when run for real (not just look plausible).
    assert.equal((finding!.evidence.reproduction.match(/"/g) || []).length, 2, 'exactly the two outer -e quotes, nothing nested unescaped');
    const { execSync } = await import('node:child_process');
    const output = execSync(finding!.evidence.reproduction, { encoding: 'utf8' }).trim();
    assert.equal(output, finding!.evidence.signal.quote, 'the reproduction command, actually run, must reproduce the exact captured token');
  });
});

test("does NOT flag a real cryptographically random session token (no false positive)", async () => {
  await withServer((req, res) => {
    if (req.method === "POST" && req.url === "/login") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ success: true, token: crypto.randomBytes(16).toString("hex") }));
      return;
    }
    res.writeHead(404); res.end();
  }, async (port) => {
    const finding = await probeWeakSessionToken(loginTarget(port), { username: "carlos", password: "whatever" }, HEADERS);
    assert.equal(finding, null, "a genuinely random token must never be flagged");
  });
});

test("no finding when login fails and no token is ever issued", async () => {
  await withServer((_req, res) => {
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "invalid credentials" }));
  }, async (port) => {
    const finding = await probeWeakSessionToken(loginTarget(port), { username: "carlos", password: "wrong" }, HEADERS);
    assert.equal(finding, null);
  });
});

test("also works when the token is only carried in a Set-Cookie header, not the JSON body", async () => {
  await withServer((req, res) => {
    if (req.method === "POST" && req.url === "/login") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const params = new URLSearchParams(body);
        const token = crypto.createHash("sha256").update(params.get("username") + String(Math.floor(Date.now() / 1000))).digest("hex");
        res.writeHead(200, { "Content-Type": "application/json", "Set-Cookie": `sessionId=${token}; Path=/` });
        res.end(JSON.stringify({ success: true }));
      });
      return;
    }
    res.writeHead(404); res.end();
  }, async (port) => {
    const finding = await probeWeakSessionToken(loginTarget(port), { username: "carlos", password: "whatever" }, HEADERS);
    assert.ok(finding, "expected the sha256 cookie-carried token to be reproduced too");
    assert.match(finding!.payload, /^sha256\(/);
  });
});

test("submits as JSON when the discovered form's contentType is json", async () => {
  await withServer((req, res) => {
    if (req.method === "POST" && req.url === "/login") {
      assert.match(req.headers["content-type"] || "", /application\/json/);
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const parsed = JSON.parse(body);
        assert.equal(parsed.username, "carlos");
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ token: crypto.randomBytes(16).toString("hex") }));
      });
      return;
    }
    res.writeHead(404); res.end();
  }, async (port) => {
    await probeWeakSessionToken(loginTarget(port, "json"), { username: "carlos", password: "whatever" }, HEADERS);
  });
});
