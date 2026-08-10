import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeRow, normalizeRows, _camelColumns, _lowerToCamel } from "./pgRowCase.js";
import { rowToUser, rowToScan } from "../dbMappers.js";

test("remaps Postgres lower-cased keys back to camelCase", () => {
  assert.deepEqual(
    normalizeRow({ createdat: "t", userid: "u", aisummary: "s", id: "x" }),
    { createdAt: "t", userId: "u", aiSummary: "s", id: "x" },
  );
});

test("all-lowercase columns pass through untouched", () => {
  assert.deepEqual(
    normalizeRow({ id: "x", email: "e", url: "u", status: "complete", score: 10 }),
    { id: "x", email: "e", url: "u", status: "complete", score: 10 },
  );
});

test("null/undefined pass through (so `.get()` misses pipe straight to the mapper)", () => {
  assert.equal(normalizeRow(undefined), undefined);
  assert.equal(normalizeRow(null), null);
});

test("no two camelCase columns collide on their lower-cased key (remap is unambiguous)", () => {
  assert.equal(
    Object.keys(_lowerToCamel).length,
    _camelColumns.length,
    "a lower-case collision would silently drop a column in the remap",
  );
});

test("a normalized Postgres-shaped row feeds the real mappers correctly (the bug this prevents)", () => {
  // A row exactly as Postgres `SELECT *` would return it (all-lowercase keys),
  // with integer booleans and text timestamps (per schema.sql).
  const pgUserRow = {
    id: "user_1", email: "a@b.co", credits: 5, createdat: "2026-01-01T00:00:00Z",
    notifywebhook: null, emaildigest: 1, lastdigestat: null,
  };
  const user = rowToUser(normalizeRow(pgUserRow));
  assert.ok(user);
  assert.equal(user!.createdAt, "2026-01-01T00:00:00Z", "createdAt must survive the pg lowercasing");
  assert.equal(user!.emailDigest, true, "integer-boolean maps through");

  const pgScanRow = {
    id: "scan_1", userid: "user_1", url: "http://x", authheader: null, status: "complete",
    score: 10, severity: "low", findings: "[]", aisummary: "ok", aireasoning: null,
    narrationlog: null, executivebreakdown: null, evidence: null, error: null,
    createdat: "t", completedat: "t2", sharetoken: null,
  };
  const scan = rowToScan(normalizeRow(pgScanRow));
  assert.ok(scan);
  assert.equal(scan!.userId, "user_1");
  assert.equal(scan!.aiSummary, "ok");
  assert.equal(scan!.completedAt, "t2");
  assert.deepEqual(scan!.findings, []);
});

test("normalizeRows maps a result set", () => {
  assert.deepEqual(
    normalizeRows([{ userid: "a" }, { userid: "b" }]),
    [{ userId: "a" }, { userId: "b" }],
  );
});
