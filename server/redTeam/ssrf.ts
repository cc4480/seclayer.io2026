// Reflected SSRF active probe. Asks the app to fetch its own loopback SSH port
// and looks for an SSH service banner in the response — internal-only content a
// public target could not otherwise return, so its presence proves the server
// fetched an attacker-chosen internal address on our behalf. The blind (no
// inline reflection) case is covered separately by blindSsrf.ts.
import { buildProbeEvidence } from "../evidence.js";
import { probeFetch } from "./probeHttp.js";
import type { ProbeContext, RedTeamFinding } from "./types.js";

const SSH_BANNER_SIGNATURE = /SSH-2\.0-\S+|Protocol mismatch\.?/;

export async function probeSsrf(ctx: ProbeContext): Promise<RedTeamFinding | null> {
  const attackUrl = `${ctx.url}/?url=http://127.0.0.1:22`;
  const res = await probeFetch(attackUrl, ctx.fuzzHeaders);
  const body = await res.text();
  const match = SSH_BANNER_SIGNATURE.exec(body);
  if (!match) return null;

  // Quote the exact banner so the proof is the leaked internal data itself,
  // not merely a boolean.
  return {
    testName: "Active Server-Side Request Forgery (SSRF)",
    payload: "http://127.0.0.1:22",
    severity: "critical",
    description:
      "Active Red Team scanning identified an insecure proxy/fetch behavior that permitted requests returning local loopback (SSH) banner data, confirming an SSRF vulnerability.",
    fix: "Enforce strict network path isolation for backend fetches. Implement allow-listing filters and block internal Class A/B/C IP architectures.",
    evidence: buildProbeEvidence({
      method: "oracle",
      attackUrl,
      requestHeaders: ctx.fuzzHeaders,
      res,
      body,
      matchIndex: match.index,
      quote: match[0],
      why: "This is an SSH service banner from 127.0.0.1 — the target's own loopback interface, unreachable from the public internet. Its presence in the response means the server fetched an attacker-chosen internal address on our behalf.",
      demonstration: `We asked the app to fetch "http://127.0.0.1:22" (its own internal loopback), and the response came back carrying "${match[0]}" — an internal SSH banner a public visitor can never reach. That proves the server can be steered to make requests to internal systems.`,
    }),
  };
}
