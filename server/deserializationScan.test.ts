import { test } from "node:test";
import assert from "node:assert/strict";
import { scanCookiesForSerialized } from "./deserializationScan.js";

test("flags a Java serialized object (rO0AB…) stored in a cookie", () => {
  const f = scanCookiesForSerialized(["state=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA; Path=/; HttpOnly"]);
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, "high");
  assert.match(f[0].testName, /Java serialized object/);
  assert.equal(f[0].endpoint, "cookie:state");
  assert.equal(f[0].evidence.method, "observation");
  assert.match(f[0].evidence.signal.quote, /^rO0AB/);
  // The receipt must not carry the full cookie value.
  assert.match(f[0].evidence.attack.response, /value redacted/);
});

test("flags a PHP serialized object (O:…) in a cookie, including URL-encoded", () => {
  const raw = 'user=O:4:"User":1:{s:2:"id";i:1;}';
  const f = scanCookiesForSerialized([`${encodeURIComponent(raw)}`.replace(/^/, "user=") ]);
  // The value above is percent-encoded; the scanner decodes once and matches.
  const g = scanCookiesForSerialized([`data=${encodeURIComponent('O:8:"stdClass":0:{}')}`]);
  assert.ok(g.length === 1 && /PHP serialized object/.test(g[0].testName), "URL-encoded PHP object must be detected after one decode");
  void f;
});

test("flags a Ruby Marshal cookie (BAh…) and a Python pickle cookie (gA…)", () => {
  const ruby = scanCookiesForSerialized(["_session=BAh7B0kiD3Nlc3Npb25faWQGOgZFVEkiJexampleexample"]);
  assert.ok(ruby.length === 1 && /Ruby \(Marshal\)/.test(ruby[0].testName), "Ruby Marshal cookie must be flagged");
  const pickle = scanCookiesForSerialized(["blob=gAJ9cQBYBAAAAG5hbWVxAVgFAAAAYWxpY2Vx"]);
  assert.ok(pickle.length === 1 && /pickle/.test(pickle[0].testName), "pickle cookie must be flagged");
});

test("does NOT flag a JWT session cookie (three base64url segments)", () => {
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
  assert.equal(scanCookiesForSerialized([`token=${jwt}; HttpOnly`]).length, 0);
});

test("does NOT flag ordinary opaque/base64 session ids or short values", () => {
  assert.equal(scanCookiesForSerialized(["sid=8f3c1ab29de4f7a1b6c05e2d9f"]).length, 0);
  assert.equal(scanCookiesForSerialized(["theme=dark"]).length, 0);
  assert.equal(scanCookiesForSerialized(["csrf=aGVsbG8gd29ybGQ"]).length, 0); // "hello world" base64, no format magic
  assert.equal(scanCookiesForSerialized([""]).length, 0);
});

test("reports each distinct serialized cookie once, not per format", () => {
  const f = scanCookiesForSerialized([
    "state=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA",
    "state=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA", // same cookie again
  ]);
  assert.equal(f.length, 1, "the same cookie name+format must not be double-reported");
});
