import { test } from "node:test";
import assert from "node:assert/strict";
import { formatScanReport, formatScanList } from "./format.js";
import type { Finding, ScanListSuccess, ScanReport, ScanSuccess } from "./types.js";

function baseSuccess(overrides: Partial<ScanSuccess> = {}): ScanSuccess {
  return {
    success: true,
    targetUrl: "https://target.example.com",
    postureScore: 62,
    vulnerabilityLevel: "high",
    analysisSummary: "Some summary.",
    executiveBreakdown: {
      overview: "overview text",
      riskAreas: [{ area: "Headers", detail: "missing CSP" }],
      businessImpact: "could compound with future issues",
      priorityActions: ["Deploy CSP", "Enable HSTS"],
    },
    securityFindings: [],
    creditsRemaining: 41,
    ...overrides,
  };
}

test("formatScanReport includes the score, severity, credits, and summary", () => {
  const text = formatScanReport(baseSuccess());
  assert.match(text, /Posture score: 62\/100/);
  assert.match(text, /Severity: HIGH/);
  assert.match(text, /Credits remaining: 41/);
  assert.match(text, /Some summary\./);
  assert.match(text, /https:\/\/target\.example\.com/);
});

test("formatScanReport renders every finding field when present, sorted by severity", () => {
  const findings: Finding[] = [
    { id: "a", title: "Low issue", description: "d1", severity: "low", fix: "f1", category: "IAST" },
    {
      id: "b",
      title: "Critical issue",
      description: "d2",
      severity: "critical",
      confidence: "high",
      fix: "f2",
      category: "RED_TEAM",
      owasp: "A03:2021 – Injection",
      endpoint: "/api/orders",
      impact: "full compromise",
      agentPrompt: "Fix the SQL injection in orders.ts",
      evidence: { some: "receipt" },
    },
  ];
  const text = formatScanReport(baseSuccess({ securityFindings: findings }));

  // Critical must be rendered before Low (severity-sorted).
  assert.ok(text.indexOf("Critical issue") < text.indexOf("Low issue"));
  assert.match(text, /\[CRITICAL · confidence: high\]/);
  assert.match(text, /Category: RED_TEAM/);
  assert.match(text, /OWASP: A03:2021 – Injection/);
  assert.match(text, /Endpoint: \/api\/orders/);
  assert.match(text, /Proven — replayable exploit evidence captured/);
  assert.match(text, /\*\*Impact:\*\* full compromise/);
  assert.match(text, /\*\*Fix:\*\* f2/);
  assert.match(text, /Fix the SQL injection in orders\.ts/);
});

test("formatScanReport omits absent optional finding fields instead of printing them blank", () => {
  const findings: Finding[] = [
    { id: "a", title: "Minimal finding", description: "d", severity: "medium", fix: "do the fix", category: "DAST" },
  ];
  const text = formatScanReport(baseSuccess({ securityFindings: findings }));

  assert.doesNotMatch(text, /OWASP:/);
  assert.doesNotMatch(text, /Endpoint:/);
  assert.doesNotMatch(text, /confidence:/);
  assert.doesNotMatch(text, /\*\*Impact:\*\*/);
  assert.doesNotMatch(text, /Suggested agent prompt/);
  assert.doesNotMatch(text, /Proven —/);
});

test("formatScanReport prepends a directive to surface & apply fixes when a finding carries a prompt", () => {
  const findings: Finding[] = [
    { id: "a", title: "X", description: "d", severity: "high", fix: "f", category: "IAST", agentPrompt: "do the fix task" },
  ];
  const text = formatScanReport(baseSuccess({ securityFindings: findings }));
  assert.match(text, /Acting on this report/);
  assert.match(text, /offer to apply the fix/i);
});

test("formatScanReport omits the fix-prompt directive when no finding has one", () => {
  const findings: Finding[] = [
    { id: "a", title: "X", description: "d", severity: "medium", fix: "f", category: "DAST" },
  ];
  const text = formatScanReport(baseSuccess({ securityFindings: findings }));
  assert.doesNotMatch(text, /Acting on this report/);
});

test("formatScanReport states plainly when there are no findings", () => {
  const text = formatScanReport(baseSuccess({ securityFindings: [] }));
  assert.match(text, /## Findings \(0\)/);
  assert.match(text, /No findings were reported for this target\./);
});

// --- retrieval formatting (read tools) ---

test("formatScanReport shows the scan date for a retrieved report and omits the credit line", () => {
  const report: ScanReport = {
    success: true,
    targetUrl: "https://target.example.com",
    postureScore: 55,
    vulnerabilityLevel: "medium",
    analysisSummary: "Retrieved summary.",
    executiveBreakdown: { overview: "o", riskAreas: [], businessImpact: "b", priorityActions: [] },
    securityFindings: [],
    completedAt: "2026-01-02T03:04:05Z",
  };
  const out = formatScanReport(report);
  assert.match(out, /Scanned: 2026-01-02T03:04:05Z/);
  assert.doesNotMatch(out, /Credits remaining/, "a retrieved report has no credit balance to show");
});

test("formatScanList renders a table of scans, newest first, with fetch guidance", () => {
  const list: ScanListSuccess = {
    success: true,
    scans: [
      { id: "scan_a", url: "https://a.test", status: "complete", score: 42, severity: "high", createdAt: "t0", completedAt: "t1" },
      { id: "scan_b", url: "https://b.test", status: "scanning", score: null, severity: null, createdAt: "t2", completedAt: null },
    ],
  };
  const out = formatScanList(list);
  assert.match(out, /scan_a/);
  assert.match(out, /42\/100/);
  assert.match(out, /HIGH/);
  assert.match(out, /scan_b/);
  assert.match(out, /seclayer_get_report/);
});

test("formatScanList handles an empty history", () => {
  const out = formatScanList({ success: true, scans: [] });
  assert.match(out, /No scans found/);
});
