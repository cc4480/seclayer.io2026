import { test } from "node:test";
import assert from "node:assert/strict";
import { formatScanReport } from "./format.js";
import type { Finding, ScanSuccess } from "./types.js";

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

test("formatScanReport states plainly when there are no findings", () => {
  const text = formatScanReport(baseSuccess({ securityFindings: [] }));
  assert.match(text, /## Findings \(0\)/);
  assert.match(text, /No findings were reported for this target\./);
});
