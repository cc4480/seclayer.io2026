// Two-identity BOLA / IDOR probe (docs/confirmed-evidence-spec.md §3.1a). Given two
// owned test identities A and B, it proves — or disproves — that A can read B's
// object. A PROVEN result requires all three: A reads its own object (baseline),
// A reads B's object and gets B's data back (attack), and an unauthenticated request
// to the same object is denied (control). Anything short of that is reported
// honestly at a lower tier — never as a Confirmed BOLA.
import type { BolaIdentity, RawExchange } from "../src/types.js";
import type { DiagnosticResult } from "./scanner.js";
import { safeFetch } from "./ssrf.js";
import { parseAuthHeader, extractIdentityMarker, renderRawRequest, renderRawResponse, windowAround } from "./evidence.js";

export async function bolaProbe(
  baseOrigin: string,
  identities: [BolaIdentity, BolaIdentity],
  baseHeaders: Record<string, string>,
): Promise<DiagnosticResult["apiSecFindings"]> {
  const out: NonNullable<DiagnosticResult["apiSecFindings"]> = [];
  const [A, B] = identities;
  const withAuth = (id: BolaIdentity) => ({ ...baseHeaders, ...parseAuthHeader(id.authHeader) });

  const get = async (u: string, headers: Record<string, string>) => {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), 4000);
    try {
      const res = await safeFetch(u, { headers, signal: ctl.signal });
      return { res, text: await res.text() };
    } finally {
      clearTimeout(t);
    }
  };
  const exchange = (label: string, method: string, u: string, headers: Record<string, string>, res: Response, text: string, focus?: string): RawExchange => {
    const idx = focus ? Math.max(0, text.indexOf(focus)) : 0;
    return {
      identity: label,
      request: renderRawRequest(method, u, headers),
      response: renderRawResponse(res, windowAround(text, idx, focus ? focus.length : 0, 1500)),
    };
  };

  let aUrl: string, bUrl: string;
  try {
    aUrl = new URL(A.ownResource, baseOrigin).toString();
    bUrl = new URL(B.ownResource, baseOrigin).toString();
  } catch {
    return out;
  }

  try {
    // baseline (A reads own) + setup (B reads own) → establish distinct markers.
    const aOwn = await get(aUrl, withAuth(A));
    const bOwn = await get(bUrl, withAuth(B));
    const aMarker = extractIdentityMarker(aOwn.text, A.ownMarker);
    const bMarker = extractIdentityMarker(bOwn.text, B.ownMarker);

    if (!aMarker || !bMarker || aMarker === bMarker) {
      out.push({
        testName: "Cross-Tenant Access (needs verification)",
        endpoint: `${A.ownResource} vs ${B.ownResource}`,
        severity: "medium",
        description:
          "Two distinct identity markers could not be established from the supplied test accounts, so a cross-tenant read could neither be proven nor ruled out. A PROVEN BOLA check needs a value unique to each account's data.",
        fix: "Supply a distinct ownMarker for each identity (e.g. each test user's email) so the scanner can prove or disprove cross-tenant access.",
      });
      return out;
    }

    // attack (A reads B's object) + control (unauthenticated reads B's object).
    const attack = await get(bUrl, withAuth(A));
    const control = await get(bUrl, baseHeaders);
    const attackHasB = attack.res.status === 200 && attack.text.includes(bMarker);
    const controlHasB = control.res.status === 200 && control.text.includes(bMarker);
    // The marker must be B-exclusive: if it also appears in A's own object it is
    // shared/common data, not proof A crossed a tenant boundary.
    const bMarkerExclusive = !aOwn.text.includes(bMarker);

    if (controlHasB) {
      // The resource is world-readable → unauthenticated exposure (§3.1b), not BOLA.
      out.push({
        testName: "Unauthenticated Access to Protected Resource",
        endpoint: B.ownResource,
        severity: "critical",
        description: `An unauthenticated request to ${B.ownResource} returned ${B.label}'s object data (identified by "${bMarker}"). This per-user resource is readable with no credentials at all.`,
        fix: "Require authentication on this endpoint and enforce that the caller owns the requested object before returning it.",
        evidence: {
          method: "differential",
          attack: exchange("unauthenticated", "GET", bUrl, baseHeaders, control.res, control.text, bMarker),
          signal: { quote: bMarker, offsetInResponse: 0, why: `"${bMarker}" belongs to ${B.label} and was returned to a request carrying no credentials.` },
          demonstration: `We requested ${B.label}'s resource with no login at all, and the server returned their private data ("${bMarker}"). Anyone on the internet can read it.`,
          reproduction: `curl -s "${bUrl}"`,
          capturedAt: new Date().toISOString(),
        },
      });
    } else if (attackHasB && bMarkerExclusive) {
      // The real thing: a proven cross-tenant authorized read.
      out.push({
        testName: "Broken Object Level Authorization (BOLA)",
        endpoint: B.ownResource,
        severity: "critical",
        description: `${A.label}, authenticated as itself, read ${B.label}'s object at ${B.ownResource}. The response contained ${B.label}'s data ("${bMarker}") — absent from ${A.label}'s own object — and an unauthenticated request to the same resource was denied (HTTP ${control.res.status}), confirming the resource is access-controlled.`,
        fix: "Enforce object-level authorization: verify the authenticated principal owns (or may access) the specific object id before returning it.",
        evidence: {
          method: "differential",
          baseline: exchange(A.label, "GET", aUrl, withAuth(A), aOwn.res, aOwn.text, aMarker),
          attack: exchange(A.label, "GET", bUrl, withAuth(A), attack.res, attack.text, bMarker),
          control: exchange("unauthenticated", "GET", bUrl, baseHeaders, control.res, control.text),
          signal: { quote: bMarker, offsetInResponse: 0, why: `"${bMarker}" is ${B.label}'s data; it appears in ${A.label}'s cross-tenant read, yet a logged-out request is denied.` },
          demonstration: `Logged in as ${A.label}, we opened ${B.label}'s record and the server returned it — including "${bMarker}", which is ${B.label}'s data, not ${A.label}'s. A logged-out visitor is denied, so this data is meant to be private.`,
          reproduction: `curl -s "${bUrl}" -H "Authorization: <${A.label} token>"`,
          capturedAt: new Date().toISOString(),
        },
      });
    } else if (attackHasB && !bMarkerExclusive) {
      // A got B's marker but it also appears in A's own object → not a clean proof.
      out.push({
        testName: "Cross-Tenant Access (needs verification)",
        endpoint: B.ownResource,
        severity: "medium",
        description: `${A.label} received ${B.label}'s marker from ${B.ownResource}, but that value also appears in ${A.label}'s own object, so it may be shared data rather than a tenant-boundary break. Use a marker that is unique to ${B.label} to prove or rule this out.`,
        fix: "Re-test with an ownMarker unique to each identity's data to confirm whether object-level authorization is actually broken.",
      });
    } else {
      // Authorization held — a passing result, surfaced as a coverage win.
      out.push({
        testName: "Object-Level Authorization Enforced",
        endpoint: B.ownResource,
        severity: "info",
        description: `Cross-tenant check passed: ${A.label} could not read ${B.label}'s object at ${B.ownResource} (HTTP ${attack.res.status}) and ${B.label}'s marker was not exposed. Object-level authorization is being enforced here.`,
        fix: "No action required — this is a passing authorization control, shown for coverage.",
      });
    }
  } catch {
    /* best-effort probe */
  }
  return out;
}
