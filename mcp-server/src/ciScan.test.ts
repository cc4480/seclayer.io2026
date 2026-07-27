import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { blockingFindings, parseCiArgs, runCiScan } from "./ciScan.js";
import type { Finding } from "./types.js";

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

function scanBody(findings: Array<Partial<Finding> & { severity: Finding["severity"]; title: string }>) {
  return JSON.stringify({
    success: true, targetUrl: "https://x.test", postureScore: 55, vulnerabilityLevel: "medium",
    analysisSummary: "s", executiveBreakdown: { overview: "o", riskAreas: [], businessImpact: "b", priorityActions: [] },
    securityFindings: findings.map((f, i) => ({ id: `f${i}`, description: "d", confidence: "high", fix: "x", category: "DAST", ...f })),
    creditsRemaining: 1,
  });
}

const capture = () => {
  const lines: string[] = [];
  return { fn: (s: string) => lines.push(s), lines };
};

test("blockingFindings filters by threshold and ignores suppressed findings", () => {
  const findings = [
    { id: "1", title: "crit", severity: "critical", description: "", fix: "", category: "DAST" },
    { id: "2", title: "med", severity: "medium", description: "", fix: "", category: "DAST" },
    { id: "3", title: "sup-crit", severity: "critical", isFalsePositive: true, description: "", fix: "", category: "DAST" },
  ] as Finding[];
  assert.deepEqual(blockingFindings(findings, "high").map((f) => f.title), ["crit"]);
  assert.deepEqual(blockingFindings(findings, "medium").map((f) => f.title), ["crit", "med"]);
  assert.equal(blockingFindings(findings, "critical").length, 1, "suppressed critical never gates");
});

test("parseCiArgs reads flags and falls back to env", () => {
  const a = parseCiArgs(["--url", "https://t.test", "--fail-on", "MEDIUM"], { SECLAYER_API_KEY: "k", SECLAYER_API_URL: "https://api.test" } as any);
  assert.equal(a.url, "https://t.test");
  assert.equal(a.failOn, "medium");
  assert.equal(a.apiKey, "k");
  assert.equal(a.apiUrl, "https://api.test");
});

test("runCiScan returns 2 on missing url / key / bad severity", async () => {
  const e = capture();
  assert.equal(await runCiScan([], {} as any, () => {}, e.fn), 2); // no url
  assert.equal(await runCiScan(["--url", "https://t"], {} as any, () => {}, e.fn), 2); // no key
  assert.equal(await runCiScan(["--url", "https://t", "--key", "k", "--fail-on", "bogus"], {} as any, () => {}, e.fn), 2);
});

test("runCiScan exits 0 when nothing meets the threshold", async () => {
  await withServer((_req, res) => { res.writeHead(200, { "Content-Type": "application/json" }); res.end(scanBody([{ title: "low thing", severity: "low" }])); },
    async (baseUrl) => {
      const o = capture();
      const code = await runCiScan(["--url", "https://t.test", "--key", "k", "--api-url", baseUrl, "--fail-on", "high"], {} as any, o.fn, () => {});
      assert.equal(code, 0);
      assert.ok(o.lines.some((l) => /PASSED/.test(l)));
    });
});

test("runCiScan exits 1 and lists the blocking findings when the threshold is hit", async () => {
  await withServer((_req, res) => { res.writeHead(200, { "Content-Type": "application/json" }); res.end(scanBody([{ title: "SQL Injection", severity: "critical" }, { title: "Missing CSP", severity: "medium" }])); },
    async (baseUrl) => {
      const o = capture(); const e = capture();
      const code = await runCiScan(["--url", "https://t.test", "--key", "k", "--api-url", baseUrl, "--fail-on", "high"], {} as any, o.fn, e.fn);
      assert.equal(code, 1);
      assert.ok(e.lines.some((l) => /FAILED/.test(l)));
      assert.ok(e.lines.some((l) => /SQL Injection/.test(l)));
      assert.ok(!e.lines.some((l) => /Missing CSP/.test(l)), "a medium finding must not block a high gate");
    });
});

test("runCiScan exits 2 when the scan itself fails", async () => {
  await withServer((_req, res) => { res.writeHead(401, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "Invalid API Key" })); },
    async (baseUrl) => {
      const code = await runCiScan(["--url", "https://t.test", "--key", "bad", "--api-url", baseUrl], {} as any, () => {}, () => {});
      assert.equal(code, 2);
    });
});
