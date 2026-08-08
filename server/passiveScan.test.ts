import { test } from "node:test";
import assert from "node:assert/strict";
import { cookieFlagIssues, MAX_COOKIE_ISSUES } from "./passiveScan.js";

test("cookieFlagIssues flags missing HttpOnly regardless of scheme, and missing Secure only over HTTPS", () => {
  const httpIssues = cookieFlagIssues(["sessionId=abc"], false, 0);
  assert.deepEqual(httpIssues, ['Cookie "sessionId" is set without the HttpOnly attribute']);

  const httpsIssues = cookieFlagIssues(["sessionId=abc"], true, 0);
  assert.deepEqual(httpsIssues, [
    'Cookie "sessionId" is set without the Secure attribute over HTTPS',
    'Cookie "sessionId" is set without the HttpOnly attribute',
  ]);
});

test("cookieFlagIssues reports nothing for a properly flagged cookie", () => {
  const issues = cookieFlagIssues(["sessionId=abc; Secure; HttpOnly; SameSite=Strict"], true, 0);
  assert.deepEqual(issues, []);
});

test("cookieFlagIssues never flags missing SameSite (browsers default it to Lax)", () => {
  const issues = cookieFlagIssues(["sessionId=abc; Secure; HttpOnly"], true, 0);
  assert.deepEqual(issues, []);
});

test("cookieFlagIssues respects the running count across repeated calls (global cap, not per-call)", () => {
  // Simulates the scanner calling this once per crawled page: pass the prior
  // total back in as `alreadyFound` so the cap holds across the whole scan.
  const manyCookies = Array.from({ length: 10 }, (_, i) => `c${i}=v`); // 2 issues each over HTTPS
  const first = cookieFlagIssues(manyCookies.slice(0, 2), true, 0);
  assert.equal(first.length, 4);
  const second = cookieFlagIssues(manyCookies.slice(2), true, first.length);
  assert.equal(first.length + second.length, MAX_COOKIE_ISSUES, "total across calls never exceeds the global cap");
});
