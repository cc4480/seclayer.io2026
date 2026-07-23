// Reflected XSS active probe. Submits a unique <script> marker in the "q"
// parameter and confirms it is echoed back into an HTML response in a context
// where the browser would actually execute it (not a JSON echo, HTML comment,
// <textarea>/<title>, etc.). Reflection alone is not XSS — the execution gate
// removes the dominant false positive.
import crypto from "crypto";
import { buildProbeEvidence } from "../evidence.js";
import { xssReflectionExecutes } from "../fpFilters.js";
import { probeFetch } from "./probeHttp.js";
import type { ProbeContext, RedTeamFinding } from "./types.js";

export async function probeReflectedXss(ctx: ProbeContext): Promise<RedTeamFinding | null> {
  const uniqueTrigger = `xss_probe_${crypto.randomBytes(4).toString("hex")}`;
  const attackUrl = `${ctx.url}/?q=%3Cscript%3E${uniqueTrigger}%3C%2Fscript%3E`;
  const res = await probeFetch(attackUrl, ctx.fuzzHeaders);
  const body = await res.text();
  const marker = `<script>${uniqueTrigger}</script>`;
  const markerIdx = body.indexOf(marker);
  if (markerIdx === -1 || !xssReflectionExecutes(res.headers.get("content-type"), body, markerIdx)) {
    return null;
  }

  // Receipt: the request that carried the payload and the response that
  // reflected it back verbatim (windowed so the marker survives truncation).
  return {
    testName: "Active Reflected XSS Probe",
    payload: marker,
    severity: "high",
    description:
      "Active Red Team fuzzing successfully reflected unencoded HTML/JavaScript tags directly in the immediate HTTP response, confirming a Reflected Cross-Site Scripting (XSS) vulnerability.",
    fix: "Implement deep context-aware output encoding. Deploy restrictive Content Security Policy (CSP) headers to prevent unauthorized inline script execution.",
    evidence: buildProbeEvidence({
      method: "reflection",
      attackUrl,
      requestHeaders: ctx.fuzzHeaders,
      res,
      body,
      matchIndex: markerIdx,
      quote: marker,
      why: "The unique probe marker was echoed back verbatim and unescaped inside the HTML body, so a browser parses it as a live <script> element rather than text.",
      demonstration: `We submitted the unique marker ${marker} in the "q" query parameter, and the server reflected it back into the page unescaped. Because it is returned as live HTML — not text — an attacker-supplied script placed here would execute in a visitor's browser.`,
    }),
  };
}
