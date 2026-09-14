import { test } from "node:test";
import assert from "node:assert/strict";
import { classifyTls, probeTls, type TlsObservation } from "./tlsProbe.js";

const NOW = Date.parse("2026-09-14T00:00:00Z");
const days = (n: number) => NOW + n * 86_400_000;

test("classifyTls: healthy cert on a current protocol yields no issues", () => {
  const obs: TlsObservation = { checked: true, reachable: true, protocol: "TLSv1.3", validToMs: days(90) };
  assert.deepEqual(classifyTls(obs, NOW), []);
});

test("classifyTls: expired certificate is a high-severity finding", () => {
  const obs: TlsObservation = { checked: true, reachable: true, protocol: "TLSv1.2", validToMs: days(-3), subject: "example.com" };
  const issues = classifyTls(obs, NOW);
  assert.equal(issues.length, 1);
  assert.equal(issues[0].kind, "expired");
  assert.equal(issues[0].severity, "high");
  assert.match(issues[0].description, /3 day\(s\) ago/);
});

test("classifyTls: expiring inside a week is medium, inside the window is low", () => {
  assert.equal(classifyTls({ checked: true, reachable: true, protocol: "TLSv1.3", validToMs: days(5) }, NOW)[0].severity, "medium");
  assert.equal(classifyTls({ checked: true, reachable: true, protocol: "TLSv1.3", validToMs: days(18) }, NOW)[0].severity, "low");
});

test("classifyTls: a cert 21+ days out on a current protocol is fine", () => {
  assert.deepEqual(classifyTls({ checked: true, reachable: true, protocol: "TLSv1.3", validToMs: days(30) }, NOW), []);
});

test("classifyTls: deprecated protocol is flagged; TLS 1.2/1.3 are not", () => {
  const dep = classifyTls({ checked: true, reachable: true, protocol: "TLSv1.1", validToMs: days(90) }, NOW);
  assert.equal(dep.length, 1);
  assert.equal(dep[0].kind, "deprecated-protocol");
  assert.equal(dep[0].severity, "medium");
  assert.deepEqual(classifyTls({ checked: true, reachable: true, protocol: "TLSv1.2", validToMs: days(90) }, NOW), []);
});

test("classifyTls: expired AND deprecated protocol yields both findings", () => {
  const issues = classifyTls({ checked: true, reachable: true, protocol: "TLSv1", validToMs: days(-1) }, NOW);
  assert.equal(issues.length, 2);
  assert.deepEqual(new Set(issues.map((i) => i.kind)), new Set(["expired", "deprecated-protocol"]));
});

test("classifyTls: an unchecked or unreachable observation yields nothing", () => {
  assert.deepEqual(classifyTls({ checked: false, reachable: false }, NOW), []);
  assert.deepEqual(classifyTls({ checked: true, reachable: false }, NOW), []);
});

test("probeTls: a plain-HTTP target is not checked (no handshake attempted)", async () => {
  const obs = await probeTls("http://example.com");
  assert.equal(obs.checked, false);
  assert.equal(obs.reachable, false);
});

test("probeTls: a malformed URL is not checked", async () => {
  const obs = await probeTls("not a url");
  assert.equal(obs.checked, false);
});
