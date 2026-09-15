import { test } from "node:test";
import assert from "node:assert/strict";
import { mentionsScore, stripScoreClaims } from "./scoreProse.js";

const FALLBACK = "A deterministic fallback summary long enough to be useful to a reader of the report.";

test("mentionsScore catches every shape of a numeric score claim", () => {
  for (const s of [
    "The site scores 85/100 overall.",
    "It achieved 85 / 100 this pass.",
    "The target scored 42 out of 100.",
    "We assign a score of 73 here.",
    "The posture score is 12 today.",
    "Overall score: 55.",
    "This scan scored 91.",
  ]) {
    assert.equal(mentionsScore(s), true, `should flag: ${s}`);
  }
});

test("mentionsScore catches letter-grade claims", () => {
  assert.equal(mentionsScore("The site earns a grade of B."), true);
  assert.equal(mentionsScore("This is grade F territory."), true);
  assert.equal(mentionsScore("It is a D grade result."), true);
});

test("mentionsScore leaves ordinary prose alone", () => {
  for (const s of [
    "We found 3 critical issues and 2 medium ones.",
    "The certificate expires in 12 days.",
    "Improving your score should be the priority.",
    "Two of the 14 endpoints lacked authorization.",
    "HTTP 200 was returned for /.env.",
  ]) {
    assert.equal(mentionsScore(s), false, `should NOT flag: ${s}`);
  }
});

test("stripScoreClaims returns untouched prose when there is no claim", () => {
  const clean = "The target exposes an environment file and lacks a Content-Security-Policy. Fix both promptly.";
  assert.equal(stripScoreClaims(clean, FALLBACK), clean);
});

test("stripScoreClaims removes only the offending sentence, keeping the rest intact", () => {
  const input =
    "The target https://x.test exposes an environment file. Overall it scores 85/100. Remediate the exposure immediately.";
  const out = stripScoreClaims(input, FALLBACK);
  assert.ok(!out.includes("85/100"));
  assert.ok(out.includes("exposes an environment file"));
  assert.ok(out.includes("Remediate the exposure immediately."));
  assert.ok(!mentionsScore(out), "result must carry no score claim at all");
});

test("stripScoreClaims never leaves mangled half-sentences", () => {
  const out = stripScoreClaims("Posture is weak. The score of 20 reflects that. Act now on the exposed keys.", FALLBACK);
  assert.equal(out, "Posture is weak. Act now on the exposed keys.");
});

test("stripScoreClaims falls back when every sentence quoted a score", () => {
  assert.equal(stripScoreClaims("It scores 85/100. The grade of B applies.", FALLBACK), FALLBACK);
});

test("stripScoreClaims falls back when what survives is too thin to be a summary", () => {
  assert.equal(stripScoreClaims("Scored 91 across the board. Fine.", FALLBACK), FALLBACK);
});

test("stripScoreClaims falls back on empty or whitespace input", () => {
  assert.equal(stripScoreClaims("", FALLBACK), FALLBACK);
  assert.equal(stripScoreClaims("   ", FALLBACK), FALLBACK);
});

test("stripScoreClaims handles ! and ? sentence terminators", () => {
  const out = stripScoreClaims(
    "This target is in poor shape! It scores 12/100! Rotate the leaked credentials today.", FALLBACK);
  assert.ok(!out.includes("12/100"));
  assert.ok(out.includes("poor shape!"));
  assert.ok(out.includes("Rotate the leaked credentials today."));
});
