import { test } from "node:test";
import assert from "node:assert/strict";
import { parseRole } from "./config.js";

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
