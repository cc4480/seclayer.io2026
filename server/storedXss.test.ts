import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { probeStoredXss } from "./storedXss.js";
import type { InjectableTarget } from "./crawler.js";

// A stateful guestbook: POST /guestbook stores the `comment` field; GET renders
// stored comments — escaped or raw depending on the `escape` flag.
async function withGuestbook(
  escape: boolean,
  fn: (port: number) => Promise<void>,
) {
  const stored: string[] = [];
  const readBody = (req: http.IncomingMessage) =>
    new Promise<string>((r) => { let d = ""; req.on("data", (c) => (d += c)); req.on("end", () => r(d)); });
  const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

  const server = http.createServer(async (req, res) => {
    if (req.method === "POST") {
      const comment = new URLSearchParams(await readBody(req)).get("comment") || "";
      stored.push(comment);
      res.writeHead(200, { "Content-Type": "text/html" });
      return res.end("<!doctype html><html><body>Thanks!</body></html>");
    }
    // GET renders the stored comments.
    const items = stored.map((c) => `<li>${escape ? esc(c) : c}</li>`).join("");
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(`<!doctype html><html><body><ul>${items}</ul></body></html>`);
  });

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

const HEADERS = { "User-Agent": "test", "Cache-Control": "no-cache" };
const formTarget = (port: number): InjectableTarget => ({
  url: `http://127.0.0.1:${port}/guestbook`, method: "POST", params: ["comment"], source: "form",
});

test("confirms stored XSS when a submitted marker returns unescaped on a later GET (PROVEN)", async () => {
  await withGuestbook(false, async (port) => {
    const findings = await probeStoredXss([formTarget(port)], HEADERS);
    assert.equal(findings.length, 1, "expected one stored-XSS finding");
    const f = findings[0];
    assert.equal(f.severity, "critical");
    assert.match(f.testName, /Stored XSS/);
    // Core PROVEN invariant: the quoted proof is literally present in the captured GET.
    assert.ok(f.evidence.attack.response.includes(f.evidence.signal.quote));
    assert.match(f.evidence.attack.request, /^GET /m, "the proof request is a separate GET, not the POST");
  });
});

test("no finding when the app escapes stored output (no false positive)", async () => {
  await withGuestbook(true, async (port) => {
    const findings = await probeStoredXss([formTarget(port)], HEADERS);
    assert.equal(findings.length, 0, "escaped output must not be reported as stored XSS");
  });
});

// A REST-style split: POST goes to /api/comments (which never renders HTML
// back), and the ONLY page that displays stored comments is /post/1 — a
// different URL entirely. Regression coverage for discoveredOnPage: without
// it, displayCandidates only tries the action URL and site root, neither of
// which is /post/1, so the real stored XSS would go undetected.
async function withSplitCommentApp(fn: (port: number) => Promise<void>) {
  const stored: string[] = [];
  const readBody = (req: http.IncomingMessage) =>
    new Promise<string>((r) => { let d = ""; req.on("data", (c) => (d += c)); req.on("end", () => r(d)); });

  const server = http.createServer(async (req, res) => {
    if (req.method === "POST" && req.url === "/api/comments") {
      const text = new URLSearchParams(await readBody(req)).get("text") || "";
      stored.push(text);
      res.writeHead(201, { "Content-Type": "application/json" });
      return res.end('{"success":true}');
    }
    if (req.url === "/post/1") {
      const items = stored.map((c) => `<p>${c}</p>`).join(""); // unescaped
      res.writeHead(200, { "Content-Type": "text/html" });
      return res.end(`<!doctype html><html><body>${items}</body></html>`);
    }
    res.writeHead(404, { "Content-Type": "text/html" });
    res.end("<!doctype html><html><body>not found</body></html>");
  });

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

test("confirms stored XSS when the display page differs from the form's action URL (discoveredOnPage)", async () => {
  await withSplitCommentApp(async (port) => {
    const target: InjectableTarget = {
      url: `http://127.0.0.1:${port}/api/comments`,
      method: "POST",
      params: ["text"],
      source: "form",
      discoveredOnPage: `http://127.0.0.1:${port}/post/1`,
    };
    const findings = await probeStoredXss([target], HEADERS);
    assert.equal(findings.length, 1, "expected one stored-XSS finding via the discovered display page");
    assert.match(findings[0].evidence.attack.request, /^GET \/post\/1 HTTP\/1\.1/m);
  });
});

test("misses the same stored XSS when discoveredOnPage is absent (documents the limitation this fixes)", async () => {
  await withSplitCommentApp(async (port) => {
    const target: InjectableTarget = {
      url: `http://127.0.0.1:${port}/api/comments`,
      method: "POST",
      params: ["text"],
      source: "form",
      // no discoveredOnPage — only the action URL (/api/comments, never
      // renders HTML) and the site root (never registered, 404s) are tried.
    };
    const findings = await probeStoredXss([target], HEADERS);
    assert.equal(findings.length, 0);
  });
});

test("no finding for a GET-only target (nothing to submit)", async () => {
  await withGuestbook(false, async (port) => {
    const getTarget: InjectableTarget = { url: `http://127.0.0.1:${port}/`, method: "GET", params: ["q"], source: "query" };
    const findings = await probeStoredXss([getTarget], HEADERS);
    assert.equal(findings.length, 0);
  });
});
