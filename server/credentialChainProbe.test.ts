import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { extractUrlKeyPairs, probeCredentialUrlPairs } from "./credentialChainProbe.js";

async function withServer(handler: http.RequestListener, fn: (port: number) => Promise<void>) {
  const server = http.createServer(handler);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as AddressInfo).port;
  const prevEnv = process.env.NODE_ENV;
  const prevAllow = process.env.SCAN_DEV_ALLOW_HOSTS;
  try {
    process.env.NODE_ENV = "development";
    process.env.SCAN_DEV_ALLOW_HOSTS = `127.0.0.1:${port}`;
    await fn(port);
  } finally {
    if (prevEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = prevEnv;
    if (prevAllow === undefined) delete process.env.SCAN_DEV_ALLOW_HOSTS; else process.env.SCAN_DEV_ALLOW_HOSTS = prevAllow;
    await new Promise((r) => server.close(r));
  }
}

test("extractUrlKeyPairs pairs a URL with a same-prefix key (Supabase homepage shape)", () => {
  const html = `<script>
    window.SUPABASE_URL = "http://127.0.0.1:54321";
    window.SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiJ9.sig";
  </script>`;
  const pairs = extractUrlKeyPairs(html);
  assert.equal(pairs.length, 1);
  assert.equal(pairs[0].prefix, "SUPABASE");
  assert.equal(pairs[0].url, "http://127.0.0.1:54321");
  assert.match(pairs[0].key, /^eyJ/);
});

test("extractUrlKeyPairs does NOT pair a URL and key with different prefixes", () => {
  const html = `window.FOO_URL = "http://127.0.0.1:9999"; window.BAR_API_KEY = "some-totally-unrelated-key-value-here";`;
  assert.deepEqual(extractUrlKeyPairs(html), []);
});

test("extractUrlKeyPairs ignores a bare URL or bare key with nothing to pair", () => {
  assert.deepEqual(extractUrlKeyPairs('window.SUPABASE_URL = "http://127.0.0.1:54321";'), []);
  assert.deepEqual(extractUrlKeyPairs('window.SUPABASE_ANON_KEY = "some-long-enough-key-value-here";'), []);
});

test("probeCredentialUrlPairs proves unrestricted table access via PostgREST-style OpenAPI root listing", async () => {
  await withServer((req, res) => {
    if (req.url === "/rest/v1/") {
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ paths: { "/admin_config": {}, "/rpc/some_fn": {} } }));
    }
    if (req.url === "/rest/v1/admin_config?select=*&limit=5") {
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(JSON.stringify([{ id: 1, setting: "max_users", value: "1000" }]));
    }
    res.writeHead(404); res.end("not found");
  }, async (port) => {
    const pairs = [{ prefix: "SUPABASE", url: `http://127.0.0.1:${port}`, key: "fake-anon-key-value-1234567890" }];
    const finding = await probeCredentialUrlPairs(pairs);
    assert.ok(finding, "expected unrestricted table access to be proven");
    assert.match(finding!.testName, /Client-Side Key Grants Unrestricted Backend Access/);
    assert.equal(finding!.severity, "critical");
    assert.ok(finding!.evidence.attack.response.includes("max_users"));
  });
});

test("probeCredentialUrlPairs falls back to a small guess list when the root doesn't list tables", async () => {
  await withServer((req, res) => {
    if (req.url === "/rest/v1/") {
      res.writeHead(500); return res.end("nope"); // no OpenAPI doc
    }
    if (req.url === "/rest/v1/settings?select=*&limit=5") {
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(JSON.stringify([{ id: 1, key: "rate_limit", value: "unlimited" }]));
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end("[]"); // every other guess: empty, not proof of anything
  }, async (port) => {
    const pairs = [{ prefix: "SUPABASE", url: `http://127.0.0.1:${port}`, key: "fake-anon-key-value-1234567890" }];
    const finding = await probeCredentialUrlPairs(pairs);
    assert.ok(finding, "expected the guess-list fallback to find the readable table");
    assert.match(finding!.payload, /settings/);
  });
});

test("no finding when every candidate table is empty or unreachable (no false positive)", async () => {
  await withServer((_req, res) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end("[]");
  }, async (port) => {
    const pairs = [{ prefix: "SUPABASE", url: `http://127.0.0.1:${port}`, key: "fake-anon-key-value-1234567890" }];
    const finding = await probeCredentialUrlPairs(pairs);
    assert.equal(finding, null);
  });
});

test("no finding when there are no url/key pairs at all", async () => {
  const finding = await probeCredentialUrlPairs([]);
  assert.equal(finding, null);
});
