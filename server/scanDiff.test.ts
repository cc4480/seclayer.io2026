import { test } from "node:test";
import assert from "node:assert/strict";
import { diffFindings } from "./scanDiff.js";
import type { Finding } from "../src/types.js";

function f(over: Partial<Finding> & { title: string }): Finding {
  return {
    id: Math.random().toString(16).slice(2),
    title: over.title,
    description: "d",
    severity: over.severity || "medium",
    confidence: "high",
    fix: "fix",
    category: over.category || "DAST",
    ...over,
  } as Finding;
}

test("baseline: no previous scan means nothing to diff against", () => {
  const d = diffFindings([f({ title: "A" })], undefined);
  assert.equal(d.isBaseline, true);
  assert.equal(d.newFindings.length, 0);
  assert.equal(d.fixedFindings.length, 0);
});

test("classifies new, fixed, and persisting findings by stable identity", () => {
  const prev = [f({ title: "SQLi", category: "RED_TEAM" }), f({ title: "Missing CSP", category: "IAST" })];
  const cur = [f({ title: "Missing CSP", category: "IAST" }), f({ title: "Open Redirect", category: "RED_TEAM" })];
  const d = diffFindings(cur, prev);
  assert.equal(d.isBaseline, false);
  assert.deepEqual(d.newFindings.map((x) => x.title), ["Open Redirect"]);
  assert.deepEqual(d.fixedFindings.map((x) => x.title), ["SQLi"]);
  assert.deepEqual(d.persisting.map((x) => x.title), ["Missing CSP"]);
});

test("detects a severity change on a persisting finding and the score delta", () => {
  const prev = [f({ title: "Weak Cookie", category: "IAST", severity: "low" })];
  const cur = [f({ title: "Weak Cookie", category: "IAST", severity: "high" })];
  const d = diffFindings(cur, prev, { current: 40, previous: 80 });
  assert.equal(d.severityChanges.length, 1);
  assert.equal(d.severityChanges[0].from, "low");
  assert.equal(d.severityChanges[0].to, "high");
  assert.equal(d.severityChanges[0].worsened, true);
  assert.equal(d.scoreDelta, -40);
});

test("suppressed findings are excluded from every bucket", () => {
  const prev = [f({ title: "A" })];
  const cur = [f({ title: "A", isFalsePositive: true }), f({ title: "B" })];
  const d = diffFindings(cur, prev);
  // "A" is suppressed now → it counts as fixed (gone from the active set), and is
  // never listed as persisting or new.
  assert.deepEqual(d.fixedFindings.map((x) => x.title), ["A"]);
  assert.deepEqual(d.newFindings.map((x) => x.title), ["B"]);
  assert.equal(d.persisting.length, 0);
});
