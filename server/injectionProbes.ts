// Injection-class red-team probes: SQL injection, reflected XSS, and OS command
// injection against the root URL. Each returns a PROVEN finding (whose signal is
// a literal substring of the captured response) or null, and swallows its own
// fetch errors so one probe can't abort the suite.
import { safeFetch } from "./ssrf.js";
import { buildProbeEvidence } from "./evidence.js";
import { xssReflectionExecutes } from "./fpFilters.js";
import crypto from "crypto";

type Headers = Record<string, string>;

export async function probeSqlInjection(url: string, fuzzHeaders: Headers): Promise<any | null> {
  try {
    const sqlCtl = new AbortController();
    const sqlId = setTimeout(() => sqlCtl.abort(), 4000);
    const sqlRes = await safeFetch(`${url}/?id=%27%20OR%201%3D1--`, { headers: fuzzHeaders, signal: sqlCtl.signal });
    clearTimeout(sqlId);
    const sqlText = await sqlRes.text();
    // Match specific database error signatures only — never bare "syntax error",
    // which appears in unrelated content and causes false positives.
    const sqlErrorSig =
      /(SQL syntax;|valid MySQL result|mysqli?_fetch|ORA-\d{4,5}|PLS-\d{4,5}|PostgreSQL.*?ERROR|PG::\w*Error|SQLSTATE\[|SQLite3?::|SQLiteException|Unclosed quotation mark after the character string|quoted string not properly terminated|Microsoft OLE DB Provider for SQL Server|ODBC SQL Server Driver|Npgsql\.)/i;
    const sqlMatch = sqlErrorSig.exec(sqlText);
    if (!sqlMatch) return null;
    const attackUrl = `${url}/?id=%27%20OR%201%3D1--`;
    return {
      testName: "Active SQL Injection Probe",
      payload: "' OR 1=1--",
      severity: "critical",
      description:
        "Active Red Team scanning detected database syntax errors reflected in the HTTP response when injecting escaped SQL boundary characters. This indicates an exploitable database injection vulnerability.",
      fix: "Implement parameterized database queries and prepared statements exclusively. Eliminate dynamic string concatenation for SQL logic.",
      evidence: buildProbeEvidence({
        method: "error-signature", attackUrl, requestHeaders: fuzzHeaders, res: sqlRes, body: sqlText,
        matchIndex: sqlMatch.index, quote: sqlMatch[0],
        why: "This is a raw database-engine error, emitted only when our injected quote breaks the SQL query's syntax. A benign value does not produce it — so request input is reaching the database unescaped.",
        demonstration:
          'We injected the SQL boundary payload "\' OR 1=1--" into the "id" parameter and the server responded with a raw database error. That error is proof the input reaches the SQL engine unescaped — the hallmark of an exploitable injection.',
      }),
    };
  } catch { return null; }
}

export async function probeReflectedXss(url: string, fuzzHeaders: Headers): Promise<any | null> {
  try {
    const xssCtl = new AbortController();
    const xssId = setTimeout(() => xssCtl.abort(), 4000);
    const uniqueTrigger = `xss_probe_${crypto.randomBytes(4).toString("hex")}`;
    const xssRes = await safeFetch(`${url}/?q=%3Cscript%3E${uniqueTrigger}%3C%2Fscript%3E`, { headers: fuzzHeaders, signal: xssCtl.signal });
    clearTimeout(xssId);
    const xssText = await xssRes.text();
    const marker = `<script>${uniqueTrigger}</script>`;
    const markerIdx = xssText.indexOf(marker);
    // Reflection alone is not XSS: require an HTML response the browser will
    // parse AND a context where the marker actually executes (not a JSON echo,
    // an HTML comment, a <textarea>/<title>, etc.).
    if (markerIdx === -1 || !xssReflectionExecutes(xssRes.headers.get("content-type"), xssText, markerIdx)) return null;
    const attackUrl = `${url}/?q=%3Cscript%3E${uniqueTrigger}%3C%2Fscript%3E`;
    return {
      testName: "Active Reflected XSS Probe",
      payload: marker,
      severity: "high",
      description:
        "Active Red Team fuzzing successfully reflected unencoded HTML/JavaScript tags directly in the immediate HTTP response, confirming a Reflected Cross-Site Scripting (XSS) vulnerability.",
      fix: "Implement deep context-aware output encoding. Deploy restrictive Content Security Policy (CSP) headers to prevent unauthorized inline script execution.",
      evidence: buildProbeEvidence({
        method: "reflection", attackUrl, requestHeaders: fuzzHeaders, res: xssRes, body: xssText,
        matchIndex: markerIdx, quote: marker,
        why: "The unique probe marker was echoed back verbatim and unescaped inside the HTML body, so a browser parses it as a live <script> element rather than text.",
        demonstration:
          `We submitted the unique marker ${marker} in the "q" query parameter, and the server reflected it back into the page unescaped. Because it is returned as live HTML — not text — an attacker-supplied script placed here would execute in a visitor's browser.`,
      }),
    };
  } catch { return null; }
}

// Oracle-first: inject an arithmetic expression with random operands and look for
// the COMPUTED SUM in the response (the literal payload never contains it, so its
// appearance can only mean the backend evaluated our command). Falls back to the
// classic `id` output signature if the arithmetic oracle doesn't land.
export async function probeCommandInjection(url: string, fuzzHeaders: Headers): Promise<any | null> {
  const cmdFix =
    "Avoid invoking underlying operating system commands entirely. If required, use strictly sanitized arguments array APIs, never shell-interpolated execution.";
  const cmdDesc =
    "Active Red Team command-injection fuzzing evaluated an injected shell command on the backend, confirming arbitrary OS command execution.";
  try {
    const a = 100000 + crypto.randomInt(899999); // 6-digit operands so the sum
    const b = 100000 + crypto.randomInt(899999); // is a distinctive, unlikely string
    const sum = String(a + b);
    const oracleUrl = `${url}/?ping=127.0.0.1%3B+expr+${a}+%2B+${b}`;
    const oCtl = new AbortController();
    const oId = setTimeout(() => oCtl.abort(), 4000);
    const oracleRes = await safeFetch(oracleUrl, { headers: fuzzHeaders, signal: oCtl.signal });
    clearTimeout(oId);
    const oracleText = await oracleRes.text();
    const sumIdx = oracleText.indexOf(sum);

    if (sumIdx !== -1) {
      return {
        testName: "Active OS Command Injection", payload: `; expr ${a} + ${b}`, severity: "critical", description: cmdDesc, fix: cmdFix,
        evidence: buildProbeEvidence({
          method: "oracle", attackUrl: oracleUrl, requestHeaders: fuzzHeaders, res: oracleRes, body: oracleText,
          matchIndex: sumIdx, quote: sum,
          why: `We injected "expr ${a} + ${b}"; the server returned ${sum}, the exact arithmetic result. The literal payload never contains that number, so the backend must have executed our injected command to produce it.`,
          demonstration: `We injected the shell command "expr ${a} + ${b}" into the "ping" parameter, and the server responded with ${sum} — the computed sum. The only way that number appears is if the server ran our command, proving arbitrary OS command execution.`,
        }),
      };
    }
    // Fallback: classic `id` output signature (uid=…gid=…).
    const idUrl = `${url}/?ping=127.0.0.1%3B+id`;
    const iCtl = new AbortController();
    const iId = setTimeout(() => iCtl.abort(), 4000);
    const idRes = await safeFetch(idUrl, { headers: fuzzHeaders, signal: iCtl.signal });
    clearTimeout(iId);
    const idText = await idRes.text();
    const idMatch = /uid=\d+\([^)]*\)\s+gid=\d+\([^)]*\)/.exec(idText);
    if (!idMatch) return null;
    return {
      testName: "Active OS Command Injection", payload: "; id", severity: "critical", description: cmdDesc, fix: cmdFix,
      evidence: buildProbeEvidence({
        method: "oracle", attackUrl: idUrl, requestHeaders: fuzzHeaders, res: idRes, body: idText,
        matchIndex: idMatch.index, quote: idMatch[0],
        why: "This is the output of the Unix `id` command (the current user's uid/gid), returned only because the backend executed our injected `; id`. It is not static page content.",
        demonstration: `We injected "; id" into the "ping" parameter and the server returned "${idMatch[0]}" — the live output of the id command. That output only appears if the server executed our injected command.`,
      }),
    };
  } catch { return null; }
}
