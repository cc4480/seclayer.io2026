import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { buildId, parseRole } from "./config.js";

test("parseRole defaults to 'all' (single-node, backwards-compatible) when unset or unrecognized", () => {
  assert.equal(parseRole(undefined), "all");
  assert.equal(parseRole(""), "all");
  assert.equal(parseRole("   "), "all");
  assert.equal(parseRole("nonsense"), "all");
  assert.equal(parseRole("primary"), "all"); // not one of the two explicit roles
});

test("parseRole recognizes the explicit web/worker roles, case- and whitespace-insensitively", () => {
  assert.equal(parseRole("web"), "web");
  assert.equal(parseRole("worker"), "worker");
  assert.equal(parseRole("WEB"), "web");
  assert.equal(parseRole("  Worker  "), "worker");
  assert.equal(parseRole("all"), "all");
});

// --- buildId(): operator-only build identity -------------------------------
// The split this pins: buildId() names the exact commit and goes to the boot
// LOG; config.appVersion is served by the unauthenticated health endpoint and
// rendered in the public navbar. This repository is public, so a live commit
// hash in a response body tells anyone which fixes are not yet deployed.

test("buildId falls back to 'local' when no platform supplied build metadata", () => {
  assert.equal(buildId({}), "local");
  assert.equal(buildId({ RAILWAY_GIT_COMMIT_SHA: "" }), "local");
  assert.equal(buildId({ RAILWAY_GIT_COMMIT_SHA: "   " }), "local");
});

test("buildId shortens a full 40-char SHA to the 7 chars git log prints", () => {
  const sha = "d2890d7037cb681d6cccdfbcb25e02e59d6f7784";
  assert.equal(buildId({ RAILWAY_GIT_COMMIT_SHA: sha }), "d2890d7");
  assert.equal(buildId({ VERCEL_GIT_COMMIT_SHA: sha }), "d2890d7");
  assert.equal(buildId({ SOURCE_COMMIT: sha }), "d2890d7");
  assert.equal(buildId({ GIT_COMMIT: sha }), "d2890d7");
});

test("buildId leaves a non-SHA build label (e.g. a release tag) intact", () => {
  assert.equal(buildId({ APP_BUILD_SHA: "v2.1.0" }), "v2.1.0");
});

test("an explicit APP_BUILD_SHA wins over the platform's own variable", () => {
  assert.equal(
    buildId({ APP_BUILD_SHA: "pinned", RAILWAY_GIT_COMMIT_SHA: "d2890d7037cb681d6cccdfbcb25e02e59d6f7784" }),
    "pinned",
  );
});

test("the PUBLIC appVersion never picks up a commit SHA from the platform", () => {
  // Asserted against the source rather than the value, because `config` is
  // evaluated once at import: with no commit variable set in the test process,
  // checking config.appVersion would pass no matter what the fallback chain
  // says, and prove nothing. The regression to catch is someone "helpfully"
  // adding RAILWAY_GIT_COMMIT_SHA to that chain, which would start publishing
  // the live commit of a public repo in the navbar.
  const src = fs.readFileSync(path.join(process.cwd(), "server", "config.ts"), "utf-8");
  const line = src.split(/\r?\n/).find((l) => /^\s*appVersion:/.test(l));
  assert.ok(line, "expected an appVersion line in server/config.ts");
  assert.doesNotMatch(line, /COMMIT|SHA|buildId/i, `appVersion is public surface: ${line.trim()}`);
});
