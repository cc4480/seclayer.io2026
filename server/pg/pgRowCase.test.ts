import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
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

test("CAMEL_COLUMNS covers every camelCase column in schema.sql", () => {
  // CAMEL_COLUMNS is hand-maintained against the schema, and the cost of
  // forgetting an entry is invisible: the column comes back lower-cased, the
  // mapper reads undefined, and the feature fails as though the DATA were
  // wrong. Adding login_codes.codeHash without this list entry made every
  // Postgres sign-in reject a correct code — nothing threw, nothing logged.
  //
  // So the schema is the source of truth and this asserts the list matches it,
  // rather than trusting the "keep in sync" comment to be obeyed.
  const sql = fs.readFileSync(path.join(process.cwd(), "server", "pg", "schema.sql"), "utf-8");
  // Column definitions only: an identifier followed by one of the types the
  // schema actually uses. This deliberately does not match CREATE TABLE /
  // CREATE INDEX / PRIMARY KEY lines, which carry no column declaration.
  const declared = new Set<string>();
  for (const m of sql.matchAll(/^[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]+(?:text|integer|bigint)\b/gm)) {
    if (/[A-Z]/.test(m[1])) declared.add(m[1]);
  }
  assert.ok(declared.size > 20, `expected to parse many camelCase columns, found ${declared.size}`);

  const known = new Set<string>(_camelColumns as readonly string[]);
  const missing = [...declared].filter((c) => !known.has(c)).sort();
  assert.deepEqual(
    missing,
    [],
    `these schema.sql columns are missing from CAMEL_COLUMNS and would read as undefined: ${missing.join(", ")}`,
  );
});
