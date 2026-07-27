import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { parseAttack, retestFinding } from "./retest.js";
import type { Finding, Scan } from "../src/types.js";

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

function provenFinding(port: number, quote: string, over: Partial<Finding> = {}): Finding {
  return {
    id: "f1", title: "Reflected XSS", description: "d", severity: "high", confidence: "high",
    fix: "encode", category: "RED_TEAM",
    evidence: {
      method: "reflection",
      attack: { request: `GET /?q=probe HTTP/1.1\nHost: 127.0.0.1:${port}\n`, response: "..." },
      signal: { quote, offsetInResponse: 0, why: "w" },
      demonstration: "d", reproduction: "curl", capturedAt: new Date().toISOString(),
    },
    ...over,
  } as Finding;
}

function scanFor(port: number): Scan {
  return { id: "s1", userId: "u1", url: `http://127.0.0.1:${port}`, status: "complete", createdAt: "t" } as Scan;
}

test("parseAttack reconstructs method, url, content-type and body from a rendered request", () => {
  const req = "POST /submit HTTP/1.1\nHost: example.test\nContent-Type: application/x-www-form-urlencoded\n\nq=payload";
  const a = parseAttack(req, "https://example.test");
  assert.equal(a?.method, "POST");
  assert.equal(a?.url, "https://example.test/submit");
  assert.equal(a?.contentType, "application/x-www-form-urlencoded");
  assert.equal(a?.body, "q=payload");
});

test("retest reports still_present when the proof signal reproduces", async () => {
  const QUOTE = "PROOF_TOKEN_STILL_HERE";
  await withServer((_req, res) => {
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(`<html>${QUOTE}</html>`);
  }, async (port) => {
    const result = await retestFinding(provenFinding(port, QUOTE), scanFor(port));
    assert.equal(result.status, "still_present");
  });
});

test("retest reports not_reproduced when the proof signal is gone (fixed)", async () => {
  await withServer((_req, res) => {
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end("<html>all good now, encoded &lt;script&gt;</html>");
  }, async (port) => {
    const result = await retestFinding(provenFinding(port, "PROOF_TOKEN_STILL_HERE"), scanFor(port));
    assert.equal(result.status, "not_reproduced");
  });
});

test("retest finds a proof signal that lives in a response header (open-redirect / CRLF style)", async () => {
  await withServer((_req, res) => {
    res.writeHead(302, { Location: "https://seclayer-openredirect-probe.example/" });
    res.end();
  }, async (port) => {
    const finding = provenFinding(port, "seclayer-openredirect-probe.example", { category: "RED_TEAM" });
    const result = await retestFinding(finding, scanFor(port));
    assert.equal(result.status, "still_present", "header-based proofs are checked too");
  });
});

test("retest is unsupported for a heuristic finding with no receipt", async () => {
  const finding = { id: "f2", title: "Missing CSP", description: "d", severity: "medium", confidence: "medium", fix: "add", category: "IAST" } as Finding;
  const result = await retestFinding(finding, scanFor(4100));
  assert.equal(result.status, "unsupported");
});

test("retest is unsupported for a blind out-of-band finding", async () => {
  const finding = provenFinding(4100, "tok", { evidence: {
    method: "out-of-band",
    attack: { request: "GET /?url=x HTTP/1.1\nHost: 127.0.0.1:4100\n", response: "callback" },
    signal: { quote: "tok", offsetInResponse: 0, why: "w" },
    demonstration: "d", reproduction: "curl", capturedAt: "t",
  } } as Partial<Finding>);
  const result = await retestFinding(finding, scanFor(4100));
  assert.equal(result.status, "unsupported");
});
