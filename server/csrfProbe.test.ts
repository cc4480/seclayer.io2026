import { test } from "node:test";
import assert from "node:assert/strict";
import {
  formHasAntiCsrfToken,
  sessionCookieSameSiteNone,
  redactCookieValue,
  assessCsrf,
} from "./csrfProbe.js";

// --- formHasAntiCsrfToken ---------------------------------------------------

test("formHasAntiCsrfToken recognises the common framework token fields", () => {
  for (const name of ["csrf_token", "_csrf", "xsrf", "authenticity_token", "csrfmiddlewaretoken", "__RequestVerificationToken", "_token"]) {
    assert.equal(formHasAntiCsrfToken(["email", name, "submit"]), true, `should match ${name}`);
  }
});

test("formHasAntiCsrfToken is false for a form with only ordinary fields", () => {
  assert.equal(formHasAntiCsrfToken(["email", "password", "remember"]), false);
  assert.equal(formHasAntiCsrfToken([]), false);
});

// --- sessionCookieSameSiteNone ----------------------------------------------

test("sessionCookieSameSiteNone flags a session cookie explicitly set SameSite=None", () => {
  assert.equal(sessionCookieSameSiteNone(["sid=abc; Path=/; SameSite=None; Secure"]), "sid");
  assert.equal(sessionCookieSameSiteNone(["my_session=x; SameSite=None"]), "my_session");
});

test("sessionCookieSameSiteNone ignores SameSite=Lax/Strict and absent (the Lax default protects)", () => {
  assert.equal(sessionCookieSameSiteNone(["sid=abc; SameSite=Lax"]), null);
  assert.equal(sessionCookieSameSiteNone(["sid=abc; SameSite=Strict"]), null);
  assert.equal(sessionCookieSameSiteNone(["sid=abc; Path=/"]), null, "absent SameSite defaults to Lax → not exposed");
});

test("sessionCookieSameSiteNone ignores a NON-session cookie even at SameSite=None", () => {
  // An analytics/preference cookie being cross-site-sendable is not a CSRF issue.
  assert.equal(sessionCookieSameSiteNone(["_ga=GA1.2; SameSite=None; Secure"]), null);
  assert.equal(sessionCookieSameSiteNone(["theme=dark; SameSite=None"]), null);
});

// --- redactCookieValue ------------------------------------------------------

test("redactCookieValue strips the value but keeps name and attributes", () => {
  assert.equal(redactCookieValue("sid=supersecret123; Path=/; SameSite=None; Secure"), "sid=***; Path=/; SameSite=None; Secure");
});

// --- assessCsrf: the full gate ----------------------------------------------

const NONE_SESSION = "sid=abc123; Path=/; SameSite=None; Secure";
const tokenlessForm = { url: "https://t.test/transfer", method: "POST", params: ["amount", "to"], discoveredOnPage: "https://t.test/account" };
const tokenForm = { url: "https://t.test/transfer", method: "POST", params: ["amount", "to", "csrf_token"] };

test("assessCsrf fires when a SameSite=None session cookie meets a tokenless POST form", () => {
  const f = assessCsrf([NONE_SESSION], [tokenlessForm]);
  assert.ok(f, "expected a CSRF finding");
  assert.equal(f.severity, "medium");
  assert.equal(f.confidence, "medium");
  assert.match(f.testName, /Cross-Site Request Forgery/i);
  assert.equal(f.endpoint, "https://t.test/transfer");
  // Never PROVEN, and the cookie value must not leak into the receipt.
  assert.equal(f.evidence.method, "observation");
  assert.ok(!JSON.stringify(f.evidence).includes("abc123"), "cookie value must be redacted from evidence");
});

test("assessCsrf does NOT fire without a SameSite=None session cookie", () => {
  assert.equal(assessCsrf(["sid=abc; SameSite=Lax"], [tokenlessForm]), null, "Lax session → no finding");
  assert.equal(assessCsrf([], [tokenlessForm]), null, "no cookie at all (e.g. Bearer auth) → no finding");
});

test("assessCsrf does NOT fire when every state-changing form carries a token", () => {
  assert.equal(assessCsrf([NONE_SESSION], [tokenForm]), null);
});

test("assessCsrf ignores GET forms (not state-changing)", () => {
  const getForm = { url: "https://t.test/search", method: "GET", params: ["q"] };
  assert.equal(assessCsrf([NONE_SESSION], [getForm]), null);
});

test("assessCsrf reports the form's origin page when it differs from the action", () => {
  const f = assessCsrf([NONE_SESSION], [tokenlessForm]);
  assert.match(f.description, /form on https:\/\/t\.test\/account/);
});
