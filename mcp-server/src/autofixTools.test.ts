import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { editFile, listDir, readFile, resolveInRepo, runTestCommand } from "./autofixTools.js";

async function withTempRepo(fn: (repoRoot: string) => Promise<void>) {
  const repoRoot = await fs.mkdtemp(path.join(os.tmpdir(), "seclayer-autofix-"));
  try {
    await fs.mkdir(path.join(repoRoot, "src"));
    await fs.writeFile(path.join(repoRoot, "src", "app.ts"), "const port = 3000;\nconst dup = 1;\nconst dup = 1;\n", "utf8");
    await fs.writeFile(path.join(repoRoot, "README.md"), "hello\n", "utf8");
    await fn(repoRoot);
  } finally {
    await fs.rm(repoRoot, { recursive: true, force: true });
  }
}

// resolveInRepo is the single highest-risk function in the autofix feature: a
// bug here turns a file-edit tool the model controls into an arbitrary-write
// primitive on the CI runner's filesystem.
test("resolveInRepo rejects paths that escape the repo root", async () => {
  await withTempRepo(async (repoRoot) => {
    assert.throws(() => resolveInRepo(repoRoot, "../../etc/passwd"));
    assert.throws(() => resolveInRepo(repoRoot, "../outside.txt"));
    assert.throws(() => resolveInRepo(repoRoot, path.join(os.tmpdir(), "elsewhere.txt")));
    // A sibling directory that merely SHARES the repo root as a string prefix
    // (e.g. "<repoRoot>-evil") must still be rejected — a naive startsWith(root)
    // check without the trailing separator would wrongly allow this.
    assert.throws(() => resolveInRepo(repoRoot, path.join(repoRoot + "-evil", "x.txt")));
  });
});

test("resolveInRepo accepts the root itself and nested relative paths", async () => {
  await withTempRepo(async (repoRoot) => {
    assert.equal(resolveInRepo(repoRoot, "."), path.resolve(repoRoot));
    assert.equal(resolveInRepo(repoRoot, "src/app.ts"), path.resolve(repoRoot, "src", "app.ts"));
  });
});

test("readFile returns file content, rejects traversal, and reports a clean error for a missing file", async () => {
  await withTempRepo(async (repoRoot) => {
    const ok = await readFile(repoRoot, "README.md");
    assert.equal(ok.ok, true);
    assert.equal(ok.output, "hello\n");

    const escape = await readFile(repoRoot, "../outside.txt");
    assert.equal(escape.ok, false);
    assert.match(escape.output, /outside the repository/);

    const missing = await readFile(repoRoot, "nope.txt");
    assert.equal(missing.ok, false);
  });
});

test("readFile truncates content past the size cap", async () => {
  await withTempRepo(async (repoRoot) => {
    await fs.writeFile(path.join(repoRoot, "big.txt"), "x".repeat(60_000), "utf8");
    const res = await readFile(repoRoot, "big.txt");
    assert.equal(res.ok, true);
    assert.match(res.output, /truncated, 60000 bytes total/);
    assert.ok(res.output.length < 60_000);
  });
});

test("listDir lists sorted entries and rejects traversal", async () => {
  await withTempRepo(async (repoRoot) => {
    const res = await listDir(repoRoot, ".");
    assert.equal(res.ok, true);
    assert.match(res.output, /d src/);
    assert.match(res.output, /- README\.md/);

    const escape = await listDir(repoRoot, "..");
    assert.equal(escape.ok, false);
  });
});

test("editFile replaces a unique match, rejects zero/ambiguous matches, and rejects traversal", async () => {
  await withTempRepo(async (repoRoot) => {
    const ok = await editFile(repoRoot, "src/app.ts", "const port = 3000;", "const port = 4000;");
    assert.equal(ok.ok, true);
    const updated = await fs.readFile(path.join(repoRoot, "src", "app.ts"), "utf8");
    assert.match(updated, /const port = 4000;/);

    const notFound = await editFile(repoRoot, "src/app.ts", "const missing = 1;", "const x = 2;");
    assert.equal(notFound.ok, false);
    assert.match(notFound.output, /not found verbatim/);

    const ambiguous = await editFile(repoRoot, "src/app.ts", "const dup = 1;", "const dup = 2;");
    assert.equal(ambiguous.ok, false);
    assert.match(ambiguous.output, /must be unique/);

    const escape = await editFile(repoRoot, "../outside.txt", "a", "b");
    assert.equal(escape.ok, false);
    assert.match(escape.output, /outside the repository/);
  });
});

test("runTestCommand reports a clean no-op when unconfigured, and reflects real success/failure", async () => {
  await withTempRepo(async (repoRoot) => {
    const unconfigured = runTestCommand(repoRoot, undefined);
    assert.equal(unconfigured.ok, false);
    assert.match(unconfigured.output, /No test command was configured/);

    const passing = runTestCommand(repoRoot, `node -e "console.log('all good')"`);
    assert.equal(passing.ok, true);
    assert.match(passing.output, /all good/);

    const failing = runTestCommand(repoRoot, `node -e "console.error('boom'); process.exit(1)"`);
    assert.equal(failing.ok, false);
    assert.match(failing.output, /boom/);
  });
});
