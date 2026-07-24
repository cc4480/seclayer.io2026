// CRLF / HTTP response-header injection active probe (AGGRESSIVE tier). Injects
// an encoded CRLF followed by a unique marker header into common parameters and
// checks whether that header appears in the RESPONSE — proof the app writes
// unsanitized input into the response headers (enabling response splitting,
// header/cookie injection, and cache poisoning). Non-destructive: it only sets a
// harmless custom header on the probe's own response.
import crypto from "crypto";
import { aggFetchRaw, buildHeaderEvidence } from "./aggHttp.js";
import type { ProbeContext, RedTeamFinding } from "../redTeam/types.js";

const CRLF_PARAMS = ["redirect", "url", "next", "lang", "page", "q", "return"];

export async function probeCrlf(ctx: ProbeContext): Promise<RedTeamFinding | null> {
  const marker = `x-seclayer-crlf-${crypto.randomBytes(4).toString("hex")}`;
  const injected = `${marker}: injected`;
  // Encoded CRLF variants: standard %0d%0a and the %0a-only form some parsers accept.
  const seqs = [`%0d%0a${marker}%3a%20injected`, `%0a${marker}%3a%20injected`];

  for (const param of CRLF_PARAMS) {
    for (const seq of seqs) {
      const attackUrl = `${ctx.url}/?${param}=probe${seq}`;
      let res: Response;
      try {
        res = await aggFetchRaw(attackUrl, { headers: ctx.fuzzHeaders });
      } catch {
        continue;
      }
      // The injected marker header echoed back into the response = CRLF injection.
      if (res.headers.has(marker)) {
        return {
          testName: "Active CRLF / HTTP Response Header Injection",
          payload: `${param}=probe\\r\\n${injected}`,
          severity: "high",
          description:
            "Active Red Team fuzzing injected a CRLF sequence into a request parameter and the server reflected an attacker-defined header into its HTTP response, confirming CRLF / response-header injection. This enables response splitting, arbitrary header/cookie injection, and web cache poisoning.",
          fix: "Strip or reject CR (\\r) and LF (\\n) from any user input that reaches a response header (redirect Location, cookies, custom headers). Prefer framework APIs that encode header values, and never concatenate raw input into a header line.",
          evidence: buildHeaderEvidence({
            method: "reflection",
            reqMethod: "GET",
            attackUrl,
            requestHeaders: ctx.fuzzHeaders,
            res,
            proofHeaders: [`${marker}: ${res.headers.get(marker)}`],
            quote: marker,
            why: `We injected an encoded newline plus "${marker}" into the "${param}" parameter, and the server emitted "${marker}" as a real response header. Only input written unsanitized into the response header block can produce a new header this way.`,
            demonstration: `We put a CRLF sequence in the "${param}" parameter and the server added our own header "${marker}" to its response. That means an attacker can inject arbitrary headers — including Set-Cookie or a split response body — into what victims receive.`,
          }),
        };
      }
    }
  }
  return null;
}
