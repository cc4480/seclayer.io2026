// Active injection fuzzing of discovered parameters — GET query parameters AND
// POST form fields the crawler mapped. Smarter than a fixed one-payload-per-param
// sweep: (1) parameters are prioritized by how injectable their names look,
// (2) XSS is reflection-guided — a benign marker is sent first, and real payloads
// only follow where it reflects, matched to the reflection context, and (3) SQLi
// tries an ordered set of context-breakers with early-exit. GET puts the payload
// in the query string; POST sends a form-encoded body carrying every discovered
// field (the injected one set to the payload, the rest to a benign filler) so
// validation that requires sibling fields still reaches the sink. Bounded by BOTH
// a request cap and a wall-clock deadline, so raising the cap never balloons scan
// time on a slow target. Every finding still carries a PROVEN receipt
// (substring-verifiable signal) that reflects the exact request — GET or POST.
import crypto from "crypto";
import { InjectableTarget } from "./crawler.js";
import { guardedFetch, safeFetch } from "./ssrf.js";
import { buildProbeEvidence } from "./evidence.js";
import { buildHeaderEvidence } from "./aggressive/aggHttp.js";
import { xssReflectionExecutes } from "./fpFilters.js";
import type { EmitFn } from "./scanEvents.js";

export async function fuzzDiscoveredTargets(
  targets: InjectableTarget[],
  fuzzHeaders: Record<string, string>,
  opts: { aggressive?: boolean; emit?: EmitFn } = {},
): Promise<{ findings: any[]; paramsTested: number }> {
  // The aggressive tier adds four more injection classes per parameter, so it
  // gets a larger request budget and a longer wall-clock cap.
  const aggressive = !!opts.aggressive;
  const emit = opts.emit;
  const MAX_REQUESTS = aggressive ? 160 : 64;
  const MAX_PARAMS_PER_TARGET = 6;
  const DEADLINE = Date.now() + (aggressive ? 30000 : 20000); // wall-clock self-cap for slow targets
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
  // Raw request that does NOT follow redirects, so a 3xx and its headers are
  // returned intact — needed for the open-redirect and CRLF header proofs (see
  // aggressive/aggHttp.aggFetchRaw for the same reasoning).
  const probeRaw = async (target: string): Promise<Response> => {
    const ctl = new AbortController();
    const id = setTimeout(() => ctl.abort(), 4000);
    try {
      return await guardedFetch(target, { headers: fuzzHeaders, redirect: "manual", signal: ctl.signal });
    } finally {
      clearTimeout(id);
    }
  };
  const canSpend = () => budget > 0 && Date.now() < DEADLINE;

  // Form-encoded POST body carrying every discovered field: the injected field
  // holds the payload, the rest a benign filler, so endpoints that validate the
  // presence of sibling fields still process our value. The injected field is
  // guaranteed present even if it wasn't in the discovered list.
  const FILLER = "seclayer";
  const formBody = (allParams: string[], injectParam: string, value: string): string => {
    const usp = new URLSearchParams();
    const names = allParams.includes(injectParam) ? allParams : [...allParams, injectParam];
    for (const p of names) usp.set(p, p === injectParam ? value : FILLER);
    return usp.toString();
  };

  // A single (param=value) injection sent with the target's own method. Returns
  // the exchange plus the exact request shape, so the PROVEN receipt shows the
  // real GET or POST. The response-side proof (signal.quote appearing in the
  // body) is identical for both, so every probe below is method-agnostic.
  type Sent = {
    res: Response;
    text: string;
    attackUrl: string;
    reqMethod: "GET" | "POST";
    reqBody?: string;
    reqContentType?: string;
  };
  const sendInjection = async (t: InjectableTarget, param: string, value: string): Promise<Sent> => {
    if (t.method === "POST") {
      const body = formBody(t.params, param, value);
      const contentType = "application/x-www-form-urlencoded";
      const ctl = new AbortController();
      const id = setTimeout(() => ctl.abort(), 4000);
      try {
        const res = await safeFetch(t.url, {
          method: "POST",
          headers: { ...fuzzHeaders, "Content-Type": contentType },
          body,
          signal: ctl.signal,
        });
        return { res, text: await res.text(), attackUrl: t.url, reqMethod: "POST", reqBody: body, reqContentType: contentType };
      } finally {
        clearTimeout(id);
      }
    }
    const url = buildUrl(t.url, param, value);
    const { res, text } = await probe(url);
    return { res, text, attackUrl: url, reqMethod: "GET" };
  };

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
  const trySqli = async (t: InjectableTarget, param: string, endpointPath: string): Promise<void> => {
    const key = `sqli:${endpointPath}:${param}`;
    if (reported.has(key)) return;
    for (const breaker of SQL_BREAKERS) {
      if (!canSpend()) return;
      budget--;
      try {
        const sent = await sendInjection(t, param, breaker);
        const m = sqlErrorSig.exec(sent.text);
        if (m) {
          // Differential guard against false positives: confirm a benign value
          // for this parameter doesn't already produce the same DB error. If it
          // does, the error is inherent page content, not injection — suppress.
          // Only runs on a match (rare), so it doesn't inflate the request budget.
          budget--;
          const baseText = await sendInjection(t, param, "seclayer1").then((s) => s.text).catch(() => "");
          if (sqlErrorSig.test(baseText)) return; // inherent error → not a finding
          reported.add(key);
          findings.push({
            // Includes the param + endpoint so two distinct vulnerable
            // endpoints never share a title — compileStaticFindings' final
            // dedup step keys on title alone, and a fixed generic title here
            // used to make it silently drop every SQLi finding after the first.
            testName: `SQL Injection (discovered parameter "${param}" on ${endpointPath})`,
            payload: `${param}=${breaker}`,
            severity: "critical",
            description: `Injecting SQL metacharacters into the discovered ${sent.reqMethod} parameter "${param}" on ${endpointPath} provoked a database error, indicating an exploitable SQL injection.`,
            fix: "Use parameterized queries / prepared statements for this endpoint; never concatenate request input into SQL.",
            evidence: buildProbeEvidence({
              method: "error-signature", attackUrl: sent.attackUrl, requestHeaders: fuzzHeaders, res: sent.res, body: sent.text,
              matchIndex: m.index, quote: m[0],
              reqMethod: sent.reqMethod, reqBody: sent.reqBody, reqContentType: sent.reqContentType,
              why: `This raw database error is emitted only when the injected payload breaks the SQL query's syntax, proving the "${param}" parameter reaches the database unescaped.`,
              demonstration: `We injected ${breaker} into the "${param}" ${sent.reqMethod} parameter on ${endpointPath} and the server returned a raw database error — proof that this parameter's value is concatenated into a SQL query unescaped.`,
            }),
          });
          return; // early-exit: confirmed for this param
        }
      } catch { /* probe failed */ }
    }
  };

  const tryXss = async (t: InjectableTarget, param: string, endpointPath: string): Promise<void> => {
    const key = `xss:${endpointPath}:${param}`;
    if (reported.has(key) || !canSpend()) return;
    // Reflection-guided: send a benign marker first; only fuzz XSS where it lands.
    budget--;
    let ctx: XssCtx | null = null;
    try {
      const marker = `zq${crypto.randomBytes(4).toString("hex")}`;
      const { text } = await sendInjection(t, param, marker);
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
        const sent = await sendInjection(t, param, payload);
        const idx = sent.text.indexOf(payload);
        // Verbatim reflection is confirmed, but still require the response to be
        // browser-parsed HTML and the payload to land in an executing context —
        // a non-HTML body or a comment/<textarea>/<title> reflection is inert.
        if (idx !== -1 && xssReflectionExecutes(sent.res.headers.get("content-type"), sent.text, idx)) {
          reported.add(key);
          findings.push({
            // Same reasoning as the SQLi finding above: the param + endpoint
            // must be in the title, not just the description, or two distinct
            // reflected-XSS endpoints collide under the title-based dedup.
            testName: `Reflected XSS (discovered parameter "${param}" on ${endpointPath})`,
            payload: `${param}=${payload}`,
            severity: "high",
            description: `The discovered ${sent.reqMethod} parameter "${param}" on ${endpointPath} reflects unencoded HTML/JavaScript into the response, confirming a reflected Cross-Site Scripting vulnerability.`,
            fix: "Apply context-aware output encoding for this parameter and deploy a restrictive Content-Security-Policy.",
            evidence: buildProbeEvidence({
              method: "reflection", attackUrl: sent.attackUrl, requestHeaders: fuzzHeaders, res: sent.res, body: sent.text,
              matchIndex: idx, quote: payload,
              reqMethod: sent.reqMethod, reqBody: sent.reqBody, reqContentType: sent.reqContentType,
              why: `The payload was reflected verbatim and unescaped in ${c === "attr" ? "an attribute" : c === "script" ? "a script" : "an HTML"} context, so a browser executes the injected "${param}" value as live markup.`,
              demonstration: `We placed ${payload} in the "${param}" ${sent.reqMethod} parameter on ${endpointPath} and the server echoed it back unescaped — an attacker-supplied script in this parameter would run in a visitor's browser.`,
            }),
          });
          return; // confirmed for this param
        }
      } catch { /* probe failed */ }
    }
  };

  // --- AGGRESSIVE-tier per-parameter probes (opt-in) ---
  const PASSWD_SIG = /root:[^:\n]*:0:0:/;
  const REDIRECT_MARKER = "seclayer-openredirect-probe.example";

  // SSTI: arithmetic oracle. The product only appears if the engine evaluated
  // our expression; the literal payload never contains it.
  const trySsti = async (t: InjectableTarget, param: string, endpointPath: string): Promise<void> => {
    const key = `ssti:${endpointPath}:${param}`;
    if (reported.has(key)) return;
    const a = 1000 + crypto.randomInt(8999), b = 1000 + crypto.randomInt(8999);
    const product = String(a * b);
    for (const expr of [`{{${a}*${b}}}`, `\${${a}*${b}}`, `#{${a}*${b}}`, `<%= ${a}*${b} %>`]) {
      if (!canSpend()) return;
      budget--;
      try {
        const sent = await sendInjection(t, param, expr);
        const idx = sent.text.indexOf(product);
        if (idx !== -1 && !sent.text.includes(expr)) {
          reported.add(key);
          findings.push({
            testName: `Server-Side Template Injection (discovered parameter "${param}" on ${endpointPath})`,
            payload: `${param}=${expr}`,
            severity: "critical",
            description: `The discovered ${sent.reqMethod} parameter "${param}" on ${endpointPath} is evaluated by a server-side template engine: injecting "${expr}" returned its computed result. SSTI frequently escalates to remote code execution.`,
            fix: "Never render user input as a template. Pass untrusted values only as data to a pre-compiled/sandboxed template for this parameter.",
            evidence: buildProbeEvidence({
              method: "oracle", attackUrl: sent.attackUrl, requestHeaders: fuzzHeaders, res: sent.res, body: sent.text,
              matchIndex: idx, quote: product,
              reqMethod: sent.reqMethod, reqBody: sent.reqBody, reqContentType: sent.reqContentType,
              why: `We injected the template expression "${expr}"; the response contained ${product}, the exact product of ${a}×${b}, which the literal payload never contains — so the "${param}" value was evaluated as a template.`,
              demonstration: `We placed "${expr}" in the "${param}" ${sent.reqMethod} parameter on ${endpointPath} and the server rendered ${product} — proof the backend evaluated our expression (SSTI).`,
            }),
          });
          return;
        }
      } catch { /* probe failed */ }
    }
  };

  // Path traversal / LFI: retrieve /etc/passwd via a discovered parameter.
  const tryLfi = async (t: InjectableTarget, param: string, endpointPath: string): Promise<void> => {
    const key = `lfi:${endpointPath}:${param}`;
    if (reported.has(key)) return;
    for (const payload of ["../../../../../../../../etc/passwd", "....//....//....//....//....//etc/passwd", "/etc/passwd"]) {
      if (!canSpend()) return;
      budget--;
      try {
        const sent = await sendInjection(t, param, payload);
        const m = PASSWD_SIG.exec(sent.text);
        if (m) {
          reported.add(key);
          findings.push({
            testName: `Path Traversal / Local File Inclusion (discovered parameter "${param}" on ${endpointPath})`,
            payload: `${param}=${payload}`,
            severity: "critical",
            description: `The discovered ${sent.reqMethod} parameter "${param}" on ${endpointPath} reads an attacker-supplied filesystem path: a traversal payload returned the contents of /etc/passwd. An attacker can read arbitrary files the app can access.`,
            fix: "Resolve the path and confirm it stays within an allowed base directory (canonicalize then prefix-check), or map inputs to an allow-list; reject path separators/traversal for this parameter.",
            evidence: buildProbeEvidence({
              method: "error-signature", attackUrl: sent.attackUrl, requestHeaders: fuzzHeaders, res: sent.res, body: sent.text,
              matchIndex: m.index, quote: m[0],
              reqMethod: sent.reqMethod, reqBody: sent.reqBody, reqContentType: sent.reqContentType,
              why: `This "root" line from /etc/passwd is outside the web root and only appears because our traversal payload in "${param}" reached the filesystem.`,
              demonstration: `We requested "${payload}" via the "${param}" ${sent.reqMethod} parameter on ${endpointPath} and the server returned /etc/passwd contents ("${m[0]}") — arbitrary file read.`,
            }),
          });
          return;
        }
      } catch { /* probe failed */ }
    }
  };

  // Open redirect: a discovered parameter used as an unvalidated redirect target.
  // GET-only: the proof is a 3xx Location header, which the raw GET probe
  // captures; a form POST rarely drives an offsite redirect via a body field.
  const tryOpenRedirect = async (t: InjectableTarget, param: string, endpointPath: string): Promise<void> => {
    if (t.method !== "GET") return;
    const key = `redirect:${endpointPath}:${param}`;
    if (reported.has(key)) return;
    for (const payload of [`https://${REDIRECT_MARKER}/`, `//${REDIRECT_MARKER}/`]) {
      if (!canSpend()) return;
      budget--;
      try {
        const attackUrl = buildUrl(t.url, param, payload);
        const res = await probeRaw(attackUrl);
        const location = res.headers.get("location") || "";
        let offsite = false;
        if (res.status >= 300 && res.status < 400 && location) {
          try { offsite = new URL(location, t.url).host === REDIRECT_MARKER; } catch { offsite = location.includes(REDIRECT_MARKER); }
        }
        if (offsite) {
          reported.add(key);
          findings.push({
            testName: `Open Redirect (discovered parameter "${param}" on ${endpointPath})`,
            payload: `${param}=${payload}`,
            severity: "medium",
            description: `The discovered parameter "${param}" on ${endpointPath} is an unvalidated redirect target: the app issued an HTTP redirect to an attacker-controlled external host. Used for phishing and OAuth token theft.`,
            fix: "Redirect only to an allow-list of paths/hosts, or force a relative path; reject absolute/protocol-relative targets that aren't your origin.",
            evidence: buildHeaderEvidence({
              method: "reflection", reqMethod: "GET", attackUrl, requestHeaders: fuzzHeaders, res,
              proofHeaders: [`Location: ${location}`], quote: REDIRECT_MARKER,
              why: `The server answered with an HTTP ${res.status} redirect whose Location points at "${REDIRECT_MARKER}", supplied via "${param}".`,
              demonstration: `We set "${param}" to "${payload}" on ${endpointPath} and the server redirected to ${location} — an external host we control.`,
            }),
          });
          return;
        }
      } catch { /* probe failed */ }
    }
  };

  // CRLF / response-header injection via a discovered parameter. The %0d%0a must
  // stay percent-encoded in the URL, so this builds the query manually (buildUrl
  // would re-encode the '%'). GET-only: the proof is an injected response header,
  // captured by the raw GET probe.
  const tryCrlf = async (t: InjectableTarget, param: string, endpointPath: string): Promise<void> => {
    if (t.method !== "GET") return;
    const key = `crlf:${endpointPath}:${param}`;
    if (reported.has(key)) return;
    const marker = `x-seclayer-crlf-${crypto.randomBytes(4).toString("hex")}`;
    let base: string;
    try {
      const u = new URL(t.url);
      u.searchParams.delete(param);
      base = u.toString();
    } catch { return; }
    for (const seq of [`probe%0d%0a${marker}%3a%20injected`, `probe%0a${marker}%3a%20injected`]) {
      if (!canSpend()) return;
      budget--;
      try {
        const attackUrl = `${base}${base.includes("?") ? "&" : "?"}${param}=${seq}`;
        const res = await probeRaw(attackUrl);
        if (res.headers.has(marker)) {
          reported.add(key);
          findings.push({
            testName: `CRLF / HTTP Response Header Injection (discovered parameter "${param}" on ${endpointPath})`,
            payload: `${param}=probe\\r\\n${marker}: injected`,
            severity: "high",
            description: `The discovered parameter "${param}" on ${endpointPath} is written into a response header unsanitized: an injected CRLF added an attacker-defined header. Enables response splitting, cookie injection, and cache poisoning.`,
            fix: "Strip CR/LF from any input that reaches a response header for this endpoint; use framework APIs that encode header values.",
            evidence: buildHeaderEvidence({
              method: "reflection", reqMethod: "GET", attackUrl, requestHeaders: fuzzHeaders, res,
              proofHeaders: [`${marker}: ${res.headers.get(marker)}`], quote: marker,
              why: `We injected an encoded newline plus "${marker}" into "${param}" and the server emitted "${marker}" as a real response header.`,
              demonstration: `A CRLF sequence in the "${param}" parameter on ${endpointPath} made the server add our own header "${marker}" to its response.`,
            }),
          });
          return;
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
      emit?.("probe", `→ Fuzzing "${param}" on ${endpointPath} — ${aggressive ? "SQLi/XSS/SSTI/LFI/redirect/CRLF" : "SQLi/XSS"} payloads…`);
      const before = findings.length;
      // Run the higher-leaning class first so a tight budget hits likely wins.
      if (s.sqli >= s.xss) { await trySqli(t, param, endpointPath); await tryXss(t, param, endpointPath); }
      else { await tryXss(t, param, endpointPath); await trySqli(t, param, endpointPath); }

      // Aggressive tier: the four param-injection classes, on the same discovered
      // parameter. Endpoint/header classes (CORS, XXE, NoSQL) run at the root +
      // candidate-path level in server/aggressiveProbes.ts, not per-param.
      // trySsti/tryLfi run for GET and POST; open-redirect/CRLF are GET-only.
      if (aggressive) {
        await trySsti(t, param, endpointPath);
        await tryLfi(t, param, endpointPath);
        await tryOpenRedirect(t, param, endpointPath);
        await tryCrlf(t, param, endpointPath);
      }
      // Report any injections confirmed on this parameter to the live ticker.
      for (let i = before; i < findings.length; i++) {
        emit?.("result", `✓ CONFIRMED: ${findings[i].testName} [${String(findings[i].severity || "").toUpperCase()}] — payload: ${findings[i].payload}`);
      }
    }
  }

  return { findings, paramsTested };
}
