import { test } from "node:test";
import assert from "node:assert/strict";
import { compileLocalSummary, compileLocalBreakdown, sanitizeBreakdown } from "./localReport.js";
import type { Finding, Severity } from "../src/types.js";

const URL = "https://target.test";

function finding(over: Partial<Finding> = {}): Finding {
  return {
    id: "f_" + Math.random().toString(16).slice(2, 8),
    title: "A finding",
    description: "d",
    severity: "medium",
    fix: "Do the fix.",
    category: "IAST",
    ...over,
  };
}
const scored = (severity: Severity, findings: Finding[], score = 50) => ({ score, severity, findings });

// --- compileLocalSummary ----------------------------------------------------

test("compileLocalSummary names the target and escalates tone with severity", () => {
  for (const sev of ["critical", "high"] as Severity[]) {
    const s = compileLocalSummary(URL, scored(sev, []));
    assert.ok(s.includes(URL));
    assert.match(s, /urgent/i);
  }
  const med = compileLocalSummary(URL, scored("medium", []));
  assert.ok(med.includes(URL));
  assert.match(med, /moderate/i);

  const low = compileLocalSummary(URL, scored("low", []));
  assert.ok(low.includes(URL));
  assert.match(low, /strong basic defensive hygiene/i);
});

test("compileLocalSummary never states a numeric score in its prose", () => {
  // The displayed score is recalculated deterministically on read; prose that
  // quoted its own number could contradict the box the user is looking at.
  for (const sev of ["critical", "high", "medium", "low", "info"] as Severity[]) {
    const s = compileLocalSummary(URL, scored(sev, [], 37));
    assert.ok(!/\b\d{1,3}\s*\/\s*100\b/.test(s), `"${sev}" summary must not quote a score`);
    assert.ok(!s.includes("37"), `"${sev}" summary must not quote the score value`);
  }
});

// --- compileLocalBreakdown --------------------------------------------------

test("compileLocalBreakdown summarises counts, areas and score in the overview", () => {
  const b = compileLocalBreakdown(URL, scored("high", [
    finding({ category: "SAST", severity: "critical", title: "Leaked AWS key" }),
    finding({ category: "IAST", severity: "medium" }),
  ], 20));
  assert.ok(b.overview.includes(URL));
  assert.ok(b.overview.includes("2 active finding(s)"));
  assert.ok(b.overview.includes("20/100"));
});

test("compileLocalBreakdown excludes suppressed false positives from every section", () => {
  const b = compileLocalBreakdown(URL, scored("medium", [
    finding({ category: "SAST", title: "Real one" }),
    finding({ category: "SCA", title: "Suppressed one", isFalsePositive: true }),
  ]));
  assert.ok(b.overview.includes("1 active finding(s)"));
  assert.ok(!JSON.stringify(b).includes("Suppressed one"));
});

test("compileLocalBreakdown ranks risk areas by finding count and labels categories", () => {
  const b = compileLocalBreakdown(URL, scored("medium", [
    finding({ category: "IAST", title: "H1" }),
    finding({ category: "IAST", title: "H2" }),
    finding({ category: "SAST", title: "S1" }),
  ]));
  assert.equal(b.riskAreas[0].area, "Defensive Header & Session Policy");
  assert.match(b.riskAreas[0].detail, /2 finding\(s\)/);
  assert.equal(b.riskAreas[1].area, "Static Code & Secrets Exposure");
});

test("compileLocalBreakdown orders priority actions worst-severity-first", () => {
  const b = compileLocalBreakdown(URL, scored("critical", [
    finding({ severity: "low", fix: "LOW FIX" }),
    finding({ severity: "critical", fix: "CRITICAL FIX" }),
    finding({ severity: "medium", fix: "MEDIUM FIX" }),
  ]));
  assert.deepEqual(b.priorityActions.slice(0, 3), ["CRITICAL FIX", "MEDIUM FIX", "LOW FIX"]);
});

test("compileLocalBreakdown falls back to the title when a finding has no fix", () => {
  const b = compileLocalBreakdown(URL, scored("high", [finding({ severity: "high", fix: "", title: "Titled finding" })]));
  assert.deepEqual(b.priorityActions, ["Titled finding"]);
});

test("compileLocalBreakdown caps risk areas and actions at six", () => {
  const many = Array.from({ length: 9 }, (_, i) =>
    finding({ category: `CAT${i}`, severity: "high", fix: `FIX${i}` }));
  const b = compileLocalBreakdown(URL, scored("high", many));
  assert.equal(b.riskAreas.length, 6);
  assert.equal(b.priorityActions.length, 6);
});

test("compileLocalBreakdown stays coherent with zero findings", () => {
  const b = compileLocalBreakdown(URL, scored("info", [], 100));
  assert.equal(b.riskAreas.length, 1);
  assert.match(b.riskAreas[0].area, /General Hygiene/);
  assert.match(b.priorityActions[0], /No action required/);
  assert.match(b.businessImpact, /No material business risk/);
});

// --- sanitizeBreakdown: the model's JSON is untrusted free-form input -------

test("sanitizeBreakdown returns the deterministic breakdown for junk input", () => {
  const sc = scored("medium", [finding({ title: "Real" })]);
  const fallback = compileLocalBreakdown(URL, sc);
  for (const junk of [null, undefined, "a string", 42, []]) {
    assert.deepEqual(sanitizeBreakdown(junk, URL, sc), fallback);
  }
});

test("sanitizeBreakdown keeps good model fields and backfills the missing ones", () => {
  const sc = scored("medium", [finding({ title: "Real" })]);
  const fallback = compileLocalBreakdown(URL, sc);
  const merged = sanitizeBreakdown({ overview: "  Model overview.  " }, URL, sc);
  assert.equal(merged.overview, "Model overview.");
  // Everything the model omitted comes from the deterministic breakdown.
  assert.deepEqual(merged.riskAreas, fallback.riskAreas);
  assert.equal(merged.businessImpact, fallback.businessImpact);
  assert.deepEqual(merged.priorityActions, fallback.priorityActions);
});

test("sanitizeBreakdown drops malformed riskArea entries and falls back if none survive", () => {
  const sc = scored("medium", [finding({ title: "Real" })]);
  const fallback = compileLocalBreakdown(URL, sc);
  const bad = sanitizeBreakdown({ riskAreas: [{ area: "" }, { detail: "no area" }, "nope", null] }, URL, sc);
  assert.deepEqual(bad.riskAreas, fallback.riskAreas);

  const partly = sanitizeBreakdown({ riskAreas: [{ area: " A ", detail: " D " }, { area: "x" }] }, URL, sc);
  assert.deepEqual(partly.riskAreas, [{ area: "A", detail: "D" }]);
});

test("sanitizeBreakdown coerces, trims and caps priority actions", () => {
  const sc = scored("medium", [finding()]);
  const out = sanitizeBreakdown(
    { priorityActions: ["  do this  ", "", "   ", 7, ...Array.from({ length: 8 }, (_, i) => `extra${i}`)] }, URL, sc);
  assert.equal(out.priorityActions[0], "do this");
  assert.equal(out.priorityActions[1], "7");
  assert.equal(out.priorityActions.length, 6);
});

test("sanitizeBreakdown ignores a blank overview rather than emitting emptiness", () => {
  const sc = scored("medium", [finding()]);
  const fallback = compileLocalBreakdown(URL, sc);
  assert.equal(sanitizeBreakdown({ overview: "   " }, URL, sc).overview, fallback.overview);
});
