import { test } from "node:test";
import assert from "node:assert/strict";
import { buildDomXssPayloads, domXssFinding, probeDomXss, type DomXssDriver } from "./domXss.js";

test("buildDomXssPayloads embeds the unique token in every hash payload", () => {
  const payloads = buildDomXssPayloads("TOK123");
  assert.ok(payloads.length >= 3);
  for (const p of payloads) {
    assert.ok(p.startsWith("#"), "payload targets the URL fragment");
    assert.ok(p.includes("TOK123"), "payload carries the unique token");
  }
});

test("domXssFinding builds a PROVEN high-severity finding whose signal is the token", () => {
  const f = domXssFinding("https://spa.example.com/", {
    payload: "#<img src=x onerror=\"window.__seclayerDom='TOK123'\">",
    token: "TOK123",
    html: "<html><body><img src=x></body></html>",
  });
  assert.equal(f.severity, "high");
  assert.match(f.testName, /DOM-based/);
  assert.equal(f.evidence.signal.quote, "TOK123");
  // PROVEN invariant: the quoted proof is a literal substring of the response.
  assert.ok(f.evidence.attack.response.includes(f.evidence.signal.quote));
  assert.match(f.evidence.attack.request, /spa\.example\.com/);
});

test("probeDomXss returns a finding when the injected driver reports execution", async () => {
  // Fake driver: simulates the headless browser confirming the payload ran.
  const driver: DomXssDriver = async (_url, _headers, payloads, token) => ({
    payload: payloads[0], token, html: "<html>x</html>",
  });
  const f = await probeDomXss("https://spa.example.com/", { "User-Agent": "t" }, driver);
  assert.ok(f, "expected a DOM-XSS finding");
  assert.equal(f!.severity, "high");
  assert.ok(f!.evidence.attack.response.includes(f!.evidence.signal.quote));
});

test("probeDomXss returns null when the driver finds no execution", async () => {
  const driver: DomXssDriver = async () => null;
  assert.equal(await probeDomXss("https://spa.example.com/", {}, driver), null);
});

test("probeDomXss is a no-op when rendering is disabled and no driver is injected", async () => {
  const prev = process.env.ENABLE_BROWSER_RENDERING;
  delete process.env.ENABLE_BROWSER_RENDERING;
  try {
    assert.equal(await probeDomXss("https://spa.example.com/", {}), null);
  } finally {
    if (prev === undefined) delete process.env.ENABLE_BROWSER_RENDERING; else process.env.ENABLE_BROWSER_RENDERING = prev;
  }
});
