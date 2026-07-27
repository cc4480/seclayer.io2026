// Stored / persistent XSS detection over discovered POST forms. Unlike reflected
// XSS (which echoes in the SAME response), stored XSS persists server-side and
// surfaces on a LATER request. This probe proves that two-step flow: it submits
// a unique executing-HTML marker through a discovered form, then re-fetches
// candidate display pages with a FRESH GET — a GET that never carried the
// payload. If the exact marker comes back unescaped in an executing HTML context
// on that separate GET, it can only have been stored, so the finding is PROVEN
// (signal.quote is a literal substring of the captured GET response). Submitting
// persists a benign <svg> marker, so this is gated behind the aggressive tier
// (verified ownership + explicit opt-in), like the other mutating probes.
import crypto from "crypto";
import { InjectableTarget } from "./crawler.js";
import { safeFetch } from "./ssrf.js";
import { buildProbeEvidence } from "./evidence.js";
import { xssReflectionExecutes } from "./fpFilters.js";

// Fields whose values are most likely to be displayed back to users — the
// natural home of a stored-XSS sink. We inject into the best candidate per form.
const DISPLAY_FIELD = /\b(comment|message|msg|body|content|text|desc|description|feedback|subject|note|title|name|review|bio|about|post|reply|author|nick|username)\b/i;

const FILLER = "seclayer";

function pickField(params: string[]): string | null {
  if (!params.length) return null;
  return params.find((p) => DISPLAY_FIELD.test(p)) || params[0];
}

function formBody(allParams: string[], injectParam: string, value: string): string {
  const usp = new URLSearchParams();
  const names = allParams.includes(injectParam) ? allParams : [...allParams, injectParam];
  for (const p of names) usp.set(p, p === injectParam ? value : FILLER);
  return usp.toString();
}

async function timedFetch(url: string, init: RequestInit): Promise<Response> {
  const ctl = new AbortController();
  const id = setTimeout(() => ctl.abort(), 5000);
  try {
    return await safeFetch(url, { ...init, signal: ctl.signal });
  } finally {
    clearTimeout(id);
  }
}

// Candidate pages a stored value might surface on: the form's own action URL
// (many simple apps post to and render the same URL) and the origin root.
function displayCandidates(actionUrl: string): string[] {
  const out = [actionUrl];
  try {
    out.push(new URL(actionUrl).origin + "/");
  } catch { /* actionUrl not absolute — skip the root candidate */ }
  return [...new Set(out)];
}

export async function probeStoredXss(
  formTargets: InjectableTarget[],
  headers: Record<string, string>,
  opts: { maxForms?: number } = {},
): Promise<any[]> {
  const findings: any[] = [];
  const reported = new Set<string>();
  const maxForms = opts.maxForms ?? 4;
  let processed = 0;

  for (const t of formTargets) {
    if (processed >= maxForms) break;
    if (t.method !== "POST" || t.params.length === 0) continue;
    const field = pickField(t.params);
    if (!field) continue;

    let endpointPath = t.url;
    try { endpointPath = new URL(t.url).pathname; } catch { /* keep raw */ }
    const key = `${endpointPath}:${field}`;
    if (reported.has(key)) continue;
    processed++;

    const token = `stx${crypto.randomBytes(6).toString("hex")}`;
    // Executing HTML with the unique token embedded, so a verbatim match is both
    // unguessable (proving persistence) and browser-executable (proving XSS).
    const payload = `<svg/onload=alert('${token}')>`;

    try {
      // 1. Submit the marker through the form.
      const body = formBody(t.params, field, payload);
      await timedFetch(t.url, {
        method: "POST",
        headers: { ...headers, "Content-Type": "application/x-www-form-urlencoded" },
        body,
      });

      // 2. Re-fetch candidate display pages with a fresh GET that never carried
      //    the payload. If it comes back, it was stored.
      for (const displayUrl of displayCandidates(t.url)) {
        let res: Response;
        try {
          res = await timedFetch(displayUrl, { headers });
        } catch {
          continue;
        }
        const text = await res.text().catch(() => "");
        const idx = text.indexOf(payload);
        if (idx === -1) continue;
        // Persisted — now require it to be in an executing HTML context (not a
        // JSON echo, a comment, a <textarea>/<title>) to avoid a false positive.
        if (!xssReflectionExecutes(res.headers.get("content-type"), text, idx)) continue;

        reported.add(key);
        findings.push({
          testName: `Stored XSS (discovered form field "${field}" on ${endpointPath})`,
          payload: `${field}=${payload}`,
          severity: "critical",
          description: `A payload submitted to the discovered form field "${field}" on ${endpointPath} was stored server-side and later served, unescaped, on ${displayUrl}. Stored XSS runs in every visitor's browser that loads the affected page — no interaction needed — so it is materially worse than reflected XSS.`,
          fix: "Apply context-aware output encoding wherever this stored value is rendered (not only on input), and deploy a restrictive Content-Security-Policy. Validate/normalize on the way in as defense-in-depth, but encoding on output is the fix.",
          evidence: buildProbeEvidence({
            method: "reflection",
            attackUrl: displayUrl,
            requestHeaders: headers,
            res,
            body: text,
            matchIndex: idx,
            quote: payload,
            why: `This GET of ${displayUrl} did NOT carry our payload, yet the response contains the exact unique marker we earlier POSTed to "${field}" on ${endpointPath}. The only way it appears here is that the server stored it and rendered it unescaped — persistent XSS.`,
            demonstration: `We submitted the unique marker ${payload} to the "${field}" field, then loaded ${displayUrl} in a separate request — and the server served our marker back as live HTML. Every visitor to that page would execute it.`,
          }),
        });
        break; // one confirmed display page is enough for this form/field
      }
    } catch {
      /* one form's failure never aborts the rest */
    }
  }

  return findings;
}
