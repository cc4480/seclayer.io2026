import { test } from "node:test";
import assert from "node:assert/strict";
import {
  looksLikeHtml,
  parseAuthHeader,
  renderRawRequest,
  windowAround,
  extractIdentityMarker,
  buildObservationEvidence,
} from "./evidence.js";

// --- parseAuthHeader: how a user's credential becomes request headers --------

test("parseAuthHeader returns nothing for an absent or blank credential", () => {
  assert.deepEqual(parseAuthHeader(undefined), {});
  assert.deepEqual(parseAuthHeader(""), {});
  assert.deepEqual(parseAuthHeader("   "), {});
});

test("parseAuthHeader treats a bare scheme value as an Authorization header", () => {
  assert.deepEqual(parseAuthHeader("Bearer tok-abc"), { Authorization: "Bearer tok-abc" });
  assert.deepEqual(parseAuthHeader("Basic dXNlcjpwYXNz"), { Authorization: "Basic dXNlcjpwYXNz" });
});

test("parseAuthHeader honours an explicit 'Header-Name: value' form", () => {
  assert.deepEqual(parseAuthHeader("Cookie: session=abc123"), { Cookie: "session=abc123" });
  assert.deepEqual(parseAuthHeader("X-API-Key: k-123"), { "X-API-Key": "k-123" });
});

test("parseAuthHeader does NOT mistake a scheme for a header name", () => {
  // "Bearer: x" must stay an Authorization value, not become a `Bearer` header —
  // otherwise an authenticated scan would silently send no credential at all.
  assert.deepEqual(parseAuthHeader("Bearer: x"), { Authorization: "Bearer: x" });
  assert.deepEqual(parseAuthHeader("Basic: y"), { Authorization: "Basic: y" });
});

test("parseAuthHeader rejects an invalid header name and falls back to Authorization", () => {
  // A name with spaces/illegal characters isn't a header; treat the whole thing
  // as an Authorization value rather than emitting a malformed header.
  assert.deepEqual(parseAuthHeader("not a header: v"), { Authorization: "not a header: v" });
});

// --- renderRawRequest: receipts must never leak the credential --------------

test("renderRawRequest redacts every sensitive header in the stored receipt", () => {
  const raw = renderRawRequest("GET", "https://target.test/admin?a=1", {
    Authorization: "Bearer super-secret-token",
    Cookie: "session=do-not-store-me",
    "X-API-Key": "k-live-secret",
    "User-Agent": "seclayer",
  });
  assert.ok(!raw.includes("super-secret-token"), "Authorization value must not be stored");
  assert.ok(!raw.includes("do-not-store-me"), "Cookie value must not be stored");
  assert.ok(!raw.includes("k-live-secret"), "API key must not be stored");
  assert.ok(raw.includes("***(redacted)"));
  assert.ok(raw.includes("User-Agent: seclayer"), "non-sensitive headers survive");
  assert.ok(raw.startsWith("GET /admin?a=1 HTTP/1.1\nHost: target.test"));
});

test("renderRawRequest degrades gracefully on an unparseable URL", () => {
  assert.equal(renderRawRequest("GET", "::not a url::", {}), "GET ::not a url::");
});

// --- windowAround: the invariant the entire PROVEN tier rests on ------------

test("windowAround returns a short body untouched", () => {
  assert.equal(windowAround("small body", 0, 5, 2000), "small body");
});

test("windowAround ALWAYS preserves the proof verbatim, wherever it sits", () => {
  const quote = "SQL-SYNTAX-ERROR-MARKER";
  // Place the proof at the start, middle and very end of an oversized body.
  for (const at of [0, 5000, 10_000 - quote.length]) {
    const body = "x".repeat(at) + quote + "y".repeat(Math.max(0, 10_000 - at - quote.length));
    const windowed = windowAround(body, at, quote.length, 500);
    assert.ok(
      windowed.includes(quote),
      `proof at offset ${at} must survive truncation — this is what makes a finding PROVEN`,
    );
    assert.ok(windowed.length < body.length, "an oversized body is actually truncated");
  }
});

test("windowAround marks what it removed, on whichever side it removed it", () => {
  const quote = "MARKER";
  const body = "a".repeat(4000) + quote + "b".repeat(4000);
  const windowed = windowAround(body, 4000, quote.length, 200);
  assert.ok(windowed.includes(quote));
  assert.match(windowed, /\[…truncated \d+ bytes\]/);
});

// --- extractIdentityMarker: the BOLA cross-tenant proof helper --------------

test("extractIdentityMarker prefers a caller-supplied marker that is present", () => {
  assert.equal(extractIdentityMarker('{"owner":"bob@vulnshop.test"}', "bob@vulnshop.test"), "bob@vulnshop.test");
});

test("extractIdentityMarker ignores a supplied marker that is absent, falling back to an email", () => {
  assert.equal(extractIdentityMarker('{"owner":"alice@vulnshop.test"}', "bob@vulnshop.test"), "alice@vulnshop.test");
});

test("extractIdentityMarker returns null when there is nothing identifying", () => {
  assert.equal(extractIdentityMarker('{"id":1,"total":42}'), null);
});

// --- buildObservationEvidence ----------------------------------------------

test("buildObservationEvidence never claims to be an exploit and keeps quote a real substring", () => {
  const ev = buildObservationEvidence({
    url: "https://target.test/",
    requestHeaders: { "User-Agent": "seclayer" },
    responseStatus: 200,
    responseHeaders: { "content-type": "text/html" },
    quote: "content-type: text/html",
    why: "the header was read directly off the response",
    demonstration: "We requested the page and read its headers.",
  });
  assert.equal(ev.method, "observation");
  assert.ok(ev.attack.response.includes(ev.signal.quote), "quote must be a literal substring of the stored response");
  assert.equal(ev.attack.response.indexOf(ev.signal.quote), ev.signal.offsetInResponse);
});

test("buildObservationEvidence drops a quote that is not actually in the response", () => {
  // A 'missing header' finding has nothing to quote — the absence IS the
  // evidence — and an invented quote would break the substring invariant.
  const ev = buildObservationEvidence({
    url: "https://target.test/",
    requestHeaders: {},
    responseStatus: 200,
    responseHeaders: { server: "nginx" },
    quote: "content-security-policy",
    why: "the header is absent",
    demonstration: "The response head visibly lacks the header.",
  });
  assert.equal(ev.signal.quote, "");
  assert.equal(ev.signal.offsetInResponse, 0);
});

// --- looksLikeHtml: SPA-shell false-positive suppression --------------------

test("looksLikeHtml recognises an SPA shell but not a real exposed file", () => {
  assert.equal(looksLikeHtml("<!DOCTYPE html><html><head><title>App</title>"), true);
  assert.equal(looksLikeHtml('<div id="root"></div>'), true);
  assert.equal(looksLikeHtml("AWS_SECRET_ACCESS_KEY=AKIA...\nDB_PASSWORD=hunter2"), false);
  assert.equal(looksLikeHtml('{"ok":true}'), false);
});
