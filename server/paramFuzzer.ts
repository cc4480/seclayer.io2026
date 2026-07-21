// Active injection fuzzing of discovered GET parameters. Smarter than a fixed
// one-payload-per-param sweep: (1) parameters are prioritized by how injectable
// their names look, (2) XSS is reflection-guided — a benign marker is sent first,
// and real payloads only follow where it reflects, matched to the reflection
// context, and (3) SQLi tries an ordered set of context-breakers with early-exit.
// Bounded by BOTH a request cap and a wall-clock deadline, so raising the cap
// never balloons scan time on a slow target. Every finding still carries a PROVEN
// receipt (substring-verifiable signal).
import crypto from "crypto";
import { InjectableTarget } from "./crawler.js";
import { safeFetch } from "./ssrf.js";
import { buildProbeEvidence } from "./evidence.js";
import { xssReflectionExecutes } from "./fpFilters.js";

export async function fuzzDiscoveredTargets(
  targets: InjectableTarget[],
  fuzzHeaders: Record<string, string>,
): Promise<{ findings: any[]; paramsTested: number }> {
  const MAX_REQUESTS = 64;
  const MAX_PARAMS_PER_TARGET = 6;
  const DEADLINE = Date.now() + 20000; // wall-clock self-cap for slow targets
  const findings: any[] = [];
  const reported = new Set<string>(); // dedupe by testName+endpoint+param
  let budget = MAX_REQUESTS;
  let paramsTested = 0;

  const sqlErrorSig =
    /(SQL syntax;|valid MySQL result|mysqli?_fetch|ORA-\d{4,5}|PLS-\d{4,5}|PostgreSQL.*?ERROR|PG::\w*Error|SQLSTATE\[|SQLite3?::|SQLiteException|Unclosed quotation mark after the character string|quoted string not properly terminated|Microsoft OLE DB Provider for SQL Server|ODBC SQL Server Driver|Npgsql\.)/i;

  const buildUrl = (base: string, param: string, value: string): string => {
    const u = new URL(base);
    u.searchParams.set(param, value);
    return u.toString();
  };

  const probe = async (target: string): Promise<{ res: Response; text: string }> => {
    const ctl = new AbortController();
    const id = setTimeout(() => ctl.abort(), 4000);
    try {
      const res = await safeFetch(target, { headers: fuzzHeaders, signal: ctl.signal });
      return { res, text: await res.text() };
    } finally {
      clearTimeout(id);
    }
  };
  const canSpend = () => budget > 0 && Date.now() < DEADLINE;

  // SQL context-breakers, ordered by error-provoking yield. A bare unbalanced
  // quote/paren is the highest-signal error trigger (an "' OR 1=1-- -" often
  // produces VALID sql and no error); these cover single-quote, double-quote and
  // parenthesised contexts a single classic payload misses. First DB error wins.
  const SQL_BREAKERS = ["'", '"', "')", "' OR 1=1-- -"];

  // Rank an injection class by how much the parameter name suggests it, so the
  // budget is spent on the likeliest wins first.
  const classify = (name: string): { sqli: number; xss: number } => {
    const n = name.toLowerCase();
    let sqli = 1, xss = 1;
    if (/(^|_)(id|uid|pid|oid)($|_)/.test(n) || /\b(order|orderby|sort|user|account|record|row|num|count|cat|category|group|filter|page|offset|limit|col|column|table|field|key)\b/.test(n) || /id$/.test(n)) sqli += 2;
    if (/\b(q|s|query|search|term|keyword|name|title|comment|message|msg|desc|description|text|content|body|feedback|subject|label|note|tag|author|city|address|return|redirect|next|url)\b/.test(n)) xss += 2;
    return { sqli, xss };
  };

  type XssCtx = "attr" | "script" | "html";
  const xssForContext = (ctx: XssCtx, token: string): string =>
    ctx === "attr" ? `"><svg/onload=${token}>`
      : ctx === "script" ? `</script><svg/onload=${token}>`
      : `<svg/onload=${token}>`;
  // Guess the reflection context from the bytes just before the reflected marker.
  const reflectionContext = (body: string, idx: number): XssCtx => {
    const before = body.slice(Math.max(0, idx - 240), idx).toLowerCase();
    if (before.lastIndexOf("<script") > before.lastIndexOf("</script")) return "script";
    if (before.lastIndexOf("<") > before.lastIndexOf(">")) return "attr"; // inside an open tag's attribute
    return "html";
  };

  // --- per-class probes (each pushes a PROVEN finding on success) ---
  const trySqli = async (targetUrl: string, param: string, endpointPath: string): Promise<void> => {
    const key = `sqli:${endpointPath}:${param}`;
    if (reported.has(key)) return;
    for (const breaker of SQL_BREAKERS) {
      if (!canSpend()) return;
      budget--;
      try {
        const attackUrl = buildUrl(targetUrl, param, breaker);
        const { res, text } = await probe(attackUrl);
        const m = sqlErrorSig.exec(text);
        if (m) {
          reported.add(key);
          findings.push({
            // Includes the param + endpoint so two distinct vulnerable
            // endpoints never share a title — compileStaticFindings' final
            // dedup step keys on title alone, and a fixed generic title here
            // used to make it silently drop every SQLi finding after the first.
            testName: `SQL Injection (discovered parameter "${param}" on ${endpointPath})`,
            payload: `${param}=${breaker}`,
            severity: "critical",
            description: `Injecting SQL metacharacters into the discovered parameter "${param}" on ${endpointPath} provoked a database error, indicating an exploitable SQL injection.`,
            fix: "Use parameterized queries / prepared statements for this endpoint; never concatenate request input into SQL.",
            evidence: buildProbeEvidence({
              method: "error-signature", attackUrl, requestHeaders: fuzzHeaders, res, body: text,
              matchIndex: m.index, quote: m[0],
              why: `This raw database error is emitted only when the injected payload breaks the SQL query's syntax, proving the "${param}" parameter reaches the database unescaped.`,
              demonstration: `We injected ${breaker} into the "${param}" parameter on ${endpointPath} and the server returned a raw database error — proof that this parameter's value is concatenated into a SQL query unescaped.`,
            }),
          });
          return; // early-exit: confirmed for this param
        }
      } catch { /* probe failed */ }
    }
  };

  const tryXss = async (targetUrl: string, param: string, endpointPath: string): Promise<void> => {
    const key = `xss:${endpointPath}:${param}`;
    if (reported.has(key) || !canSpend()) return;
    // Reflection-guided: send a benign marker first; only fuzz XSS where it lands.
    budget--;
    let ctx: XssCtx | null = null;
    try {
      const marker = `zq${crypto.randomBytes(4).toString("hex")}`;
      const { text } = await probe(buildUrl(targetUrl, param, marker));
      const mi = text.indexOf(marker);
      if (mi !== -1) ctx = reflectionContext(text, mi);
    } catch { /* skip */ }
    if (!ctx) return; // no reflection → don't waste requests here

    // Try the context-matched payload, then an HTML fallback; verify unescaped.
    const contexts: XssCtx[] = ctx === "html" ? ["html"] : [ctx, "html"];
    for (const c of contexts) {
      if (!canSpend()) return;
      budget--;
      const token = `sx${crypto.randomBytes(4).toString("hex")}`;
      const payload = xssForContext(c, token);
      try {
        const attackUrl = buildUrl(targetUrl, param, payload);
        const { res, text } = await probe(attackUrl);
        const idx = text.indexOf(payload);
        // Verbatim reflection is confirmed, but still require the response to be
        // browser-parsed HTML and the payload to land in an executing context —
        // a non-HTML body or a comment/<textarea>/<title> reflection is inert.
        if (idx !== -1 && xssReflectionExecutes(res.headers.get("content-type"), text, idx)) {
          reported.add(key);
          findings.push({
            // Same reasoning as the SQLi finding above: the param + endpoint
            // must be in the title, not just the description, or two distinct
            // reflected-XSS endpoints collide under the title-based dedup.
            testName: `Reflected XSS (discovered parameter "${param}" on ${endpointPath})`,
            payload: `${param}=${payload}`,
            severity: "high",
            description: `The discovered parameter "${param}" on ${endpointPath} reflects unencoded HTML/JavaScript into the response, confirming a reflected Cross-Site Scripting vulnerability.`,
            fix: "Apply context-aware output encoding for this parameter and deploy a restrictive Content-Security-Policy.",
            evidence: buildProbeEvidence({
              method: "reflection", attackUrl, requestHeaders: fuzzHeaders, res, body: text,
              matchIndex: idx, quote: payload,
              why: `The payload was reflected verbatim and unescaped in ${c === "attr" ? "an attribute" : c === "script" ? "a script" : "an HTML"} context, so a browser executes the injected "${param}" value as live markup.`,
              demonstration: `We placed ${payload} in the "${param}" parameter on ${endpointPath} and the server echoed it back unescaped — an attacker-supplied script in this parameter would run in a visitor's browser.`,
            }),
          });
          return; // confirmed for this param
        }
      } catch { /* probe failed */ }
    }
  };

  for (const t of targets) {
    if (!canSpend()) break;
    let endpointPath = t.url;
    try { endpointPath = new URL(t.url).pathname; } catch {}

    // Prioritize params by injectability, dedupe, cap per target.
    const ranked = [...new Set(t.params)]
      .map((p) => ({ p, s: classify(p) }))
      .sort((a, b) => Math.max(b.s.sqli, b.s.xss) - Math.max(a.s.sqli, a.s.xss))
      .slice(0, MAX_PARAMS_PER_TARGET);

    for (const { p: param, s } of ranked) {
      if (!canSpend()) break;
      paramsTested++;
      // Run the higher-leaning class first so a tight budget hits likely wins.
      if (s.sqli >= s.xss) { await trySqli(t.url, param, endpointPath); await tryXss(t.url, param, endpointPath); }
      else { await tryXss(t.url, param, endpointPath); await trySqli(t.url, param, endpointPath); }
    }
  }

  return { findings, paramsTested };
}
