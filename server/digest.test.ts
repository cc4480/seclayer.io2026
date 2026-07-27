import { test } from "node:test";
import assert from "node:assert/strict";
import { buildDigest } from "./digest.js";
import type { Scan, Finding } from "../src/types.js";

function scan(over: Partial<Scan> & { findings?: Finding[] }): Scan {
  return { id: "s", userId: "u", url: "https://t.test", status: "complete", createdAt: "t", completedAt: "t2", ...over } as Scan;
}
function f(title: string, severity: Finding["severity"] = "medium"): Finding {
  return { id: title, title, description: "d", severity, confidence: "high", fix: "x", category: "DAST" } as Finding;
}

test("returns null when there are no monitored targets", () => {
  assert.equal(buildDigest([]), null);
});

test("summarizes score and change counts per target", () => {
  const latest = scan({ url: "https://a.test", findings: [f("SQLi", "critical"), f("CSP", "medium")] });
  const previous = scan({ url: "https://a.test", findings: [f("CSP", "medium"), f("Old", "low")] });
  const d = buildDigest([{ url: "https://a.test", latest, previous }])!;
  assert.ok(d);
  const row = d.rows[0];
  assert.equal(row.hasData, true);
  assert.equal(row.newCount, 1, "SQLi is new");
  assert.equal(row.fixedCount, 1, "Old is resolved");
  // score = 100 - 35 (critical) - 15 (medium) = 50
  assert.equal(row.score, 50);
  assert.match(d.subject, /1 new finding/);
  assert.match(d.text, /https:\/\/a\.test/);
  assert.match(d.html, /50\/100/);
});

test("handles a target with no completed scan yet", () => {
  const d = buildDigest([{ url: "https://b.test", latest: undefined }])!;
  assert.equal(d.rows[0].hasData, false);
  assert.match(d.text, /no completed scan yet/);
});

test("subject omits the new-findings clause when nothing is new", () => {
  const latest = scan({ findings: [f("CSP")] });
  const previous = scan({ findings: [f("CSP")] });
  const d = buildDigest([{ url: "https://t.test", latest, previous }])!;
  assert.doesNotMatch(d.subject, /new finding/);
});
