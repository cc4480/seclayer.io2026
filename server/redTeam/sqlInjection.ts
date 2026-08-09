// SQL injection active probe. Injects an escaped SQL boundary into the "id"
// parameter and looks for a raw database-engine error in the response — a
// signature a benign value never produces, so its appearance proves input is
// reaching the SQL engine unescaped.
import { buildProbeEvidence } from "../evidence.js";
import { probeFetch } from "./probeHttp.js";
import type { ProbeContext, RedTeamFinding } from "./types.js";

// Match specific database error signatures only — never bare "syntax error",
// which appears in unrelated content and causes false positives.
// "near "X": syntax error" is SQLite's own raw parser error text, produced
// identically by every Node SQLite binding (better-sqlite3, node:sqlite,
// sqlite3) — none of which actually throw "SQLite3::"/"SQLiteException"
// (those are PHP/Java driver class-name prefixes, not what a Node app's
// error message looks like), so real SQLite injection went undetected until
// this was added. Confirmed by scanning a genuine better-sqlite3 target
// (test-targets/tier1-owasp-foundation) — see its vulnerabilities.json. The
// quotes are matched as \\?" (an OPTIONAL backslash before each) because a
// JSON-encoded response body (e.g. `res.json({ error: err.message })`, the
// obvious way to surface this) escapes them to \" — a bare `"` in the
// pattern never matches that and silently misses the common case.
// "syntax error at (or near|end of input)" / "unterminated quoted
// string/identifier at or near" is the same story for the `pg` npm package
// (node-postgres) — the RAW message Postgres's own server sends back, not
// the "PostgreSQL.*?ERROR"/"PG::\w*Error" wrapped forms other-language
// drivers print. Confirmed empirically against a real local Postgres
// instance (test-targets/tier3-baas-supabase) — a real `pg` client's syntax
// error is exactly `unterminated quoted string at or near "' limit 10"` /
// `syntax error at or near ")"`, matching neither existing pattern.
const SQL_ERROR_SIGNATURE =
  /(SQL syntax;|valid MySQL result|mysqli?_fetch|ORA-\d{4,5}|PLS-\d{4,5}|PostgreSQL.*?ERROR|PG::\w*Error|SQLSTATE\[|SQLite3?::|SQLiteException|SQLITE_ERROR|near \\?".*?\\?": syntax error|syntax error at (?:or near|end of input)|unterminated quoted (?:string|identifier) at or near|Unclosed quotation mark after the character string|quoted string not properly terminated|Microsoft OLE DB Provider for SQL Server|ODBC SQL Server Driver|Npgsql\.)/i;

export async function probeSqlInjection(ctx: ProbeContext): Promise<RedTeamFinding | null> {
  const attackUrl = `${ctx.url}/?id=%27%20OR%201%3D1--`;
  const res = await probeFetch(attackUrl, ctx.fuzzHeaders);
  const body = await res.text();
  const match = SQL_ERROR_SIGNATURE.exec(body);
  if (!match) return null;

  // Differential guard against false positives: a database-error signature only
  // proves injection when it appears BECAUSE of our metacharacters. If a benign
  // request (id=1, no metacharacters) already returns the same error, it's
  // inherent page content — documentation, a cached error page, a WAF notice —
  // not an injection, so suppress it. This extra request runs only on a match
  // (rare), so the common no-vuln path stays a single request.
  const baselineBody = await probeFetch(`${ctx.url}/?id=1`, ctx.fuzzHeaders).then((r) => r.text()).catch(() => "");
  if (SQL_ERROR_SIGNATURE.test(baselineBody)) return null;

  // Receipt: the injected request plus the exact database-error text the engine
  // emitted — quoted verbatim so the proof can be seen, not asserted.
  return {
    testName: "Active SQL Injection Probe",
    payload: "' OR 1=1--",
    severity: "critical",
    description:
      "Active Red Team scanning detected database syntax errors reflected in the HTTP response when injecting escaped SQL boundary characters. This indicates an exploitable database injection vulnerability.",
    fix: "Implement parameterized database queries and prepared statements exclusively. Eliminate dynamic string concatenation for SQL logic.",
    evidence: buildProbeEvidence({
      method: "error-signature",
      attackUrl,
      requestHeaders: ctx.fuzzHeaders,
      res,
      body,
      matchIndex: match.index,
      quote: match[0],
      why: "This is a raw database-engine error, emitted only when our injected quote breaks the SQL query's syntax. A benign value does not produce it — so request input is reaching the database unescaped.",
      demonstration:
        'We injected the SQL boundary payload "\' OR 1=1--" into the "id" parameter and the server responded with a raw database error. That error is proof the input reaches the SQL engine unescaped — the hallmark of an exploitable injection.',
    }),
  };
}
