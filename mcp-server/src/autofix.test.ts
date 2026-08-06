import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { autofixEligible, buildPrBody, parseAutofixArgs, resolveBaseBranchName, runAutofix, slugify } from "./autofix.js";
import type { Finding } from "./types.js";

async function withServer(handler: http.RequestListener, fn: (baseUrl: string, hits: Record<string, number>) => Promise<void>) {
  const hits: Record<string, number> = {};
  const server = http.createServer((req, res) => {
    hits[req.url || ""] = (hits[req.url || ""] || 0) + 1;
    handler(req, res);
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as AddressInfo).port;
  try {
    await fn(`http://127.0.0.1:${port}`, hits);
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

test("autofixEligible: excludes false positives, low-confidence/no-evidence findings, and anything below the threshold", () => {
  const findings = [
    { id: "1", title: "proven-critical", severity: "critical", confidence: "medium", evidence: { demonstration: "x" }, description: "", fix: "", category: "RED_TEAM" },
    { id: "2", title: "high-confidence-high", severity: "high", confidence: "high", description: "", fix: "", category: "IAST" },
    { id: "3", title: "medium-confidence-high-sev", severity: "high", confidence: "medium", description: "", fix: "", category: "SCA" },
    { id: "4", title: "suppressed-critical", severity: "critical", confidence: "high", isFalsePositive: true, description: "", fix: "", category: "SAST" },
    { id: "5", title: "below-threshold", severity: "medium", confidence: "high", description: "", fix: "", category: "IAST" },
  ] as unknown as Finding[];

  const eligible = autofixEligible(findings, "high");
  assert.deepEqual(eligible.map((f) => f.title), ["proven-critical", "high-confidence-high"]);
});

test("autofixEligible: sorts eligible findings most-severe first", () => {
  const findings = [
    { id: "1", title: "high", severity: "high", confidence: "high", description: "", fix: "", category: "IAST" },
    { id: "2", title: "critical", severity: "critical", confidence: "high", description: "", fix: "", category: "IAST" },
  ] as unknown as Finding[];
  assert.deepEqual(autofixEligible(findings, "high").map((f) => f.title), ["critical", "high"]);
});

test("parseAutofixArgs reads flags, falls back to env, and defaults maxFixes/dryRun", () => {
  const a = parseAutofixArgs(
    ["--url", "https://t.test", "--fail-on", "MEDIUM", "--max-fixes", "5", "--test-cmd", "npm test", "--dry-run"],
    { SECLAYER_API_KEY: "k", SECLAYER_API_URL: "https://api.test" } as any,
  );
  assert.equal(a.url, "https://t.test");
  assert.equal(a.failOn, "medium");
  assert.equal(a.maxFixes, 5);
  assert.equal(a.testCmd, "npm test");
  assert.equal(a.dryRun, true);
  assert.equal(a.apiKey, "k");
  assert.equal(a.apiUrl, "https://api.test");

  const defaults = parseAutofixArgs([], {} as any);
  assert.equal(defaults.maxFixes, 3);
  assert.equal(defaults.dryRun, false);
  assert.equal(defaults.failOn, "high");
});

test("slugify produces a short, filesystem/branch-safe token", () => {
  assert.equal(slugify("Missing Content-Security-Policy Header!!"), "missing-content-security-policy-header");
  assert.equal(slugify(""), "finding");
  assert.equal(slugify("---"), "finding");
});

test("resolveBaseBranchName prefers explicit, then GITHUB_HEAD_REF, then GITHUB_REF_NAME, then main", () => {
  assert.equal(resolveBaseBranchName("release", { GITHUB_HEAD_REF: "pr-branch", GITHUB_REF_NAME: "main" } as any), "release");
  assert.equal(resolveBaseBranchName(undefined, { GITHUB_HEAD_REF: "pr-branch", GITHUB_REF_NAME: "main" } as any), "pr-branch");
  assert.equal(resolveBaseBranchName(undefined, { GITHUB_REF_NAME: "main" } as any), "main");
  assert.equal(resolveBaseBranchName(undefined, {} as any), "main");
});

test("buildPrBody surfaces the finding, the agent's summary, and the no-source-left-CI trust note", () => {
  const finding = { title: "Missing CSP", severity: "high", confidence: "high", description: "d", fix: "f", category: "IAST", owasp: "A05:2021" } as unknown as Finding;
  const body = buildPrBody(finding, "Added a Content-Security-Policy header.", "https://x.test");
  assert.match(body, /Missing CSP/);
  assert.match(body, /HIGH/);
  assert.match(body, /Added a Content-Security-Policy header\./);
  assert.match(body, /never received this repository's source/);
});

test("runAutofix returns 2 on missing url / key / bad severity", async () => {
  const e = capture();
  assert.equal(await runAutofix([], {} as any, () => {}, e.fn), 2); // no url
  assert.equal(await runAutofix(["--url", "https://t"], {} as any, () => {}, e.fn), 2); // no key
  assert.equal(await runAutofix(["--url", "https://t", "--key", "k", "--fail-on", "bogus"], {} as any, () => {}, e.fn), 2);
});

test("runAutofix returns 2 when the scan itself fails", async () => {
  await withServer(
    (_req, res) => { res.writeHead(401, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "Invalid API Key" })); },
    async (baseUrl) => {
      const code = await runAutofix(["--url", "https://t.test", "--key", "bad", "--api-url", baseUrl], {} as any, () => {}, () => {});
      assert.equal(code, 2);
    },
  );
});

test("runAutofix exits 0 and opens nothing when no finding is eligible", async () => {
  await withServer(
    (req, res) => {
      if (req.url === "/api/mcp/scan") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(scanBody([{ title: "low severity", severity: "low", confidence: "high" }]));
      } else {
        res.writeHead(500); res.end();
      }
    },
    async (baseUrl, hits) => {
      const o = capture();
      const code = await runAutofix(["--url", "https://t.test", "--key", "k", "--api-url", baseUrl, "--fail-on", "high"], {} as any, o.fn, () => {});
      assert.equal(code, 0);
      assert.ok(o.lines.some((l) => /Nothing eligible/.test(l)));
      assert.equal(hits["/api/mcp/autofix/start"], undefined, "must never start a (billable) session when nothing is eligible");
    },
  );
});

test("runAutofix --dry-run previews the plan without spending a credit or starting a session", async () => {
  await withServer(
    (req, res) => {
      if (req.url === "/api/mcp/scan") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(scanBody([{ title: "Missing CSP header", severity: "high", confidence: "high", agentPrompt: "Add a CSP header." }]));
      } else {
        // /autofix/start or /autofix/turn must never be hit in dry-run mode.
        res.writeHead(500); res.end();
      }
    },
    async (baseUrl, hits) => {
      const o = capture();
      const code = await runAutofix(
        ["--url", "https://t.test", "--key", "k", "--api-url", baseUrl, "--fail-on", "high", "--dry-run"],
        {} as any, o.fn, () => {},
      );
      assert.equal(code, 0);
      assert.ok(o.lines.some((l) => /Dry run/.test(l)));
      assert.ok(o.lines.some((l) => /Missing CSP header/.test(l)));
      assert.equal(hits["/api/mcp/autofix/start"], undefined, "dry-run must never spend a credit");
    },
  );
});
