import { test } from "node:test";
import assert from "node:assert/strict";
import { weakTokenFindings } from "./weakTokenScan.js";

test("flags a Math.random()-style reset token (short, low-entropy, matching key name)", () => {
  const body = JSON.stringify({ success: true, message: "Check your email.", token: "bo0b07i4dmg" });
  const findings = weakTokenFindings(body, "http://target/api/forgot-password");
  assert.equal(findings.length, 1);
  assert.match(findings[0].issue, /Weak\/Predictable Security Token \(token\)/);
  assert.equal(findings[0].severity, "high");
  assert.equal(findings[0].confidence, "medium");
  assert.equal(findings[0].file, "http://target/api/forgot-password");
});

test("finds a nested resetToken field by dotted path", () => {
  const body = JSON.stringify({ data: { resetToken: "a1b2c3d4e5" } });
  const findings = weakTokenFindings(body, "http://target/api/reset");
  assert.equal(findings.length, 1);
  assert.match(findings[0].issue, /data\.resetToken/);
});

test("does NOT flag a real JWT (too long, has '.' separators)", () => {
  const jwt =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJ1c2VyIn0.s1gn4tur3xxxxxxxxxxxxxxxxxxxxxx";
  const findings = weakTokenFindings(JSON.stringify({ token: jwt }), "http://target/api/login");
  assert.deepEqual(findings, []);
});

test("does NOT flag a 128-bit-class base64url token even though the key matches", () => {
  // 22 base64url chars ≈ 132 bits — well above the weak threshold.
  const strongToken = "xk9L2pQz7Rw4vN8mB3jHtA";
  const findings = weakTokenFindings(JSON.stringify({ sessionToken: strongToken }), "http://target/api/session");
  assert.deepEqual(findings, []);
});

test("does NOT flag a short numeric OTP purely by length (rate-limiting, not entropy, is the OTP threat model)", () => {
  const findings = weakTokenFindings(JSON.stringify({ otp: "482913" }), "http://target/api/verify");
  assert.deepEqual(findings, []);
});

test("does NOT flag a short non-token field like orderId (key name gate)", () => {
  const findings = weakTokenFindings(JSON.stringify({ orderId: "ord_a1b2c3" }), "http://target/api/checkout");
  assert.deepEqual(findings, []);
});

test("ignores non-JSON bodies and malformed JSON without throwing", () => {
  assert.deepEqual(weakTokenFindings("<html>not json</html>", "http://target/"), []);
  assert.deepEqual(weakTokenFindings("{not valid json", "http://target/"), []);
  assert.deepEqual(weakTokenFindings("", "http://target/"), []);
});
