import { test } from "node:test";
import assert from "node:assert/strict";
import { cookieFlagIssues, redactCookieValue, MAX_COOKIE_ISSUES } from "./passiveScan.js";
// cookieFlagIssues now returns { message, observed }; these assertions are
// about WHICH problems are reported, so they compare the messages.
const messages = (list: { message: string }[]) => list.map((i) => i.message);

test("cookieFlagIssues flags missing HttpOnly regardless of scheme, and missing Secure only over HTTPS", () => {
  const httpIssues = cookieFlagIssues(["sessionId=abc"], false, 0);
  assert.deepEqual(messages(httpIssues), ['Cookie "sessionId" is set without the HttpOnly attribute']);

  const httpsIssues = cookieFlagIssues(["sessionId=abc"], true, 0);
  assert.deepEqual(messages(httpsIssues), [
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

// The cookie VALUE must never reach a stored report: a Set-Cookie value can be
// a live session token, and these strings are persisted and rendered in the UI.
test('redactCookieValue strips the value but keeps every security attribute', () => {
  const raw = 'NID=534=SECRET_TOKEN_VALUE; expires=Tue, 09-Mar-2027 08:52:06 GMT; path=/; domain=.google.com; HttpOnly';
  const out = redactCookieValue(raw);
  assert.ok(!out.includes('SECRET_TOKEN_VALUE'), 'the cookie value must be redacted');
  assert.match(out, /^NID=<redacted>;/);
  // The attributes are the entire point of quoting the line back.
  assert.match(out, /HttpOnly/);
  assert.match(out, /domain=\.google\.com/);
  assert.ok(!/;\s*Secure/i.test(out), 'Secure was genuinely absent and must stay absent');
});

test('cookieFlagIssues quotes the line each issue came from, value redacted', () => {
  // The real google.com response to a non-browser UA: HttpOnly but no Secure.
  const [issue] = cookieFlagIssues(['NID=534=abc; path=/; domain=.google.com; HttpOnly'], true, 0);
  assert.match(issue.message, /without the Secure attribute/);
  assert.equal(issue.observed, 'NID=<redacted>; path=/; domain=.google.com; HttpOnly');
});
