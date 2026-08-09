import { test } from "node:test";
import assert from "node:assert/strict";
import { exposedCredentialListInCapture } from "./apiProbes.js";

const SRC = "http://127.0.0.1:4103/api/tokens";

test("flags a per-user credential dump (session_tokens shape) with real evidence", () => {
  const body = JSON.stringify([
    { id: "1", user_id: "aaa", token: "fake-plaintext-session-token-alice", created_at: "t" },
    { id: "2", user_id: "bbb", token: "fake-plaintext-session-token-bob", created_at: "t" },
  ]);
  const f = exposedCredentialListInCapture(body, SRC);
  assert.ok(f, "expected a credential-list finding");
  assert.equal(f!.testName, "Exposed Credential List Endpoint");
  assert.equal(f!.severity, "critical");
  // PROVEN-style: the quoted signal is a literal substring of the captured response.
  assert.ok(f!.evidence.attack.response.includes(f!.evidence.signal.quote));
  assert.match(f!.evidence.signal.quote, /fake-plaintext-session-token/);
});

test("also catches api_key / access_token field names, not just 'token'", () => {
  const body = JSON.stringify([
    { userId: 1, api_key: "sk_live_abcdefghijklmnop" },
    { userId: 2, api_key: "sk_live_qrstuvwxyz012345" },
  ]);
  const f = exposedCredentialListInCapture(body, SRC);
  assert.ok(f);
  assert.match(f!.description, /api_key/);
});

test("does NOT fire on a profile list with no credential field (left to the user-list check)", () => {
  const body = JSON.stringify([
    { user_id: "a", email: "alice@corp.test", sensitive_data: "alice-ssn" },
    { user_id: "b", email: "bob@corp.test", sensitive_data: "bob-ssn" },
  ]);
  assert.equal(exposedCredentialListInCapture(body, SRC), null);
});

test("does NOT fire on a credential value with no co-located user identifier", () => {
  // A bare list of tokens with nothing tying each to a user — far weaker
  // signal, could be one caller's rotating tokens; deliberately not flagged.
  const body = JSON.stringify([
    { token: "some-standalone-token-value-1" },
    { token: "some-standalone-token-value-2" },
  ]);
  assert.equal(exposedCredentialListInCapture(body, SRC), null);
});

test("does NOT fire when the same constant credential is repeated (not a per-user dump)", () => {
  const body = JSON.stringify([
    { user_id: "a", token: "same-token-value-constant" },
    { user_id: "b", token: "same-token-value-constant" },
  ]);
  assert.equal(exposedCredentialListInCapture(body, SRC), null);
});

test("does NOT fire on a single record, a non-array, or a short/absent value", () => {
  assert.equal(exposedCredentialListInCapture(JSON.stringify([{ user_id: "a", token: "long-enough-token-1" }]), SRC), null); // 1 element
  assert.equal(exposedCredentialListInCapture(JSON.stringify({ user_id: "a", token: "long-enough-token-1" }), SRC), null); // object, not array
  assert.equal(exposedCredentialListInCapture(JSON.stringify([{ user_id: "a", token: "short" }, { user_id: "b", token: "tiny" }]), SRC), null); // values < 8 chars
  assert.equal(exposedCredentialListInCapture("not json", SRC), null);
  assert.equal(exposedCredentialListInCapture("", SRC), null);
});

test("does NOT fire when only SOME rows carry the credential (must be every row)", () => {
  const body = JSON.stringify([
    { user_id: "a", token: "a-real-token-value-here" },
    { user_id: "b", note: "no token on this one" },
  ]);
  assert.equal(exposedCredentialListInCapture(body, SRC), null);
});
