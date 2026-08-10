import { test } from "node:test";
import assert from "node:assert/strict";
import { toPositional } from "./pgParams.js";

test("numbers each ? placeholder in order", () => {
  assert.equal(toPositional("SELECT * FROM users WHERE id = ?"), "SELECT * FROM users WHERE id = $1");
  assert.equal(
    toPositional("INSERT INTO t (a, b, c) VALUES (?, ?, ?)"),
    "INSERT INTO t (a, b, c) VALUES ($1, $2, $3)",
  );
  assert.equal(
    toPositional("UPDATE scans SET shareToken = ? WHERE id = ? AND userId = ?"),
    "UPDATE scans SET shareToken = $1 WHERE id = $2 AND userId = $3",
  );
});

test("leaves a ? inside a single-quoted string literal alone", () => {
  assert.equal(
    toPositional("SELECT * FROM t WHERE label = 'huh?' AND id = ?"),
    "SELECT * FROM t WHERE label = 'huh?' AND id = $1",
  );
  // Real query shape from db.ts (status literal, then a real placeholder).
  assert.equal(
    toPositional("SELECT * FROM scans WHERE userId = ? AND status = 'complete' AND id != ?"),
    "SELECT * FROM scans WHERE userId = $1 AND status = 'complete' AND id != $2",
  );
});

test("honors the '' escape inside a literal", () => {
  assert.equal(
    toPositional("SELECT * FROM t WHERE name = 'O''Brien?' AND id = ?"),
    "SELECT * FROM t WHERE name = 'O''Brien?' AND id = $1",
  );
});

test("no placeholders — returns the SQL unchanged", () => {
  assert.equal(toPositional("SELECT 1"), "SELECT 1");
  assert.equal(toPositional("DELETE FROM sessions WHERE expiresAt < 'x'"), "DELETE FROM sessions WHERE expiresAt < 'x'");
});
