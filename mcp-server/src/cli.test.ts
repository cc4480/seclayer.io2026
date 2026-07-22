import { test } from "node:test";
import assert from "node:assert/strict";
import { parseArgs, resolveConfig } from "./cli.js";

test("parseArgs reads --flag value form", () => {
  const args = parseArgs(["--key", "abc123", "--url", "http://localhost:3000"]);
  assert.equal(args.key, "abc123");
  assert.equal(args.url, "http://localhost:3000");
});

test("parseArgs reads --flag=value form", () => {
  const args = parseArgs(["--key=abc123", "--url=http://localhost:3000"]);
  assert.equal(args.key, "abc123");
  assert.equal(args.url, "http://localhost:3000");
});

test("parseArgs supports short flags -k/-u", () => {
  const args = parseArgs(["-k", "abc123", "-u", "http://localhost:3000"]);
  assert.equal(args.key, "abc123");
  assert.equal(args.url, "http://localhost:3000");
});

test("parseArgs reads --help/--version as booleans", () => {
  assert.equal(parseArgs(["--help"]).help, true);
  assert.equal(parseArgs(["-h"]).help, true);
  assert.equal(parseArgs(["--version"]).version, true);
  assert.equal(parseArgs(["-v"]).version, true);
});

test("parseArgs ignores unrecognized flags rather than throwing", () => {
  assert.doesNotThrow(() => parseArgs(["--some-future-flag", "value", "--key", "abc"]));
  assert.equal(parseArgs(["--some-future-flag", "value", "--key", "abc"]).key, "abc");
});

test("resolveConfig prefers the --key flag over the env var", () => {
  const result = resolveConfig({ key: "from-flag" }, { SECLAYER_API_KEY: "from-env" } as any);
  assert.equal(result.ok, true);
  assert.equal((result as any).config.apiKey, "from-flag");
});

test("resolveConfig falls back to SECLAYER_API_KEY when no flag is given", () => {
  const result = resolveConfig({}, { SECLAYER_API_KEY: "from-env" } as any);
  assert.equal(result.ok, true);
  assert.equal((result as any).config.apiKey, "from-env");
});

test("resolveConfig fails fast with a clear error when no key is available anywhere", () => {
  const result = resolveConfig({}, {} as any);
  assert.equal(result.ok, false);
  assert.match((result as any).error, /No API key provided/);
});

test("resolveConfig defaults the base URL to https://seclayer.io and trims trailing slashes", () => {
  const result = resolveConfig({ key: "k" }, {} as any);
  assert.equal(result.ok, true);
  assert.equal((result as any).config.baseUrl, "https://seclayer.io");

  const withSlash = resolveConfig({ key: "k", url: "http://localhost:3000/" }, {} as any);
  assert.equal((withSlash as any).config.baseUrl, "http://localhost:3000");
});

test("resolveConfig prefers the --url flag over SECLAYER_API_URL", () => {
  const result = resolveConfig({ key: "k", url: "http://from-flag:3000" }, { SECLAYER_API_URL: "http://from-env:3000" } as any);
  assert.equal((result as any).config.baseUrl, "http://from-flag:3000");
});
