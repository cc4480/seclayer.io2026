// API SECURITY active probes — GraphQL introspection exposure, a fixed-path
// exposed-user-object heuristic, and the two-identity BOLA/IDOR proof. Each
// finding is signature-confirmed (a real introspection result, an actual JSON
// user record, or a proven cross-tenant read), not a status code alone. Caller
// gates invocation on verified domain ownership.
import type { BolaIdentity } from "../src/types.js";
import { safeFetch } from "./ssrf.js";
import { buildProbeEvidence, renderRawRequest, renderRawResponse, windowAround } from "./evidence.js";
import { bolaProbe } from "./bola.js";

// Distinct API-security checks run per scan (for coverage reporting): GraphQL
// introspection, exposed-object endpoint, and the BOLA/IDOR authorization probe.
export const API_PROBE_COUNT = 3;

// Guessable paths for a single admin record OR a "list every user" admin
// panel. Kept short and specific (not a huge wordlist) to stay a targeted
// heuristic, not a brute-force directory scan.
const EXPOSED_USER_OBJECT_PATHS = [
  "/api/v1/users/admin",
  "/admin/users",
  "/api/admin/users",
  "/api/v1/admin/users",
];

// Pulls a real identifying value (or, failing that, the key name) out of a
// JSON body that looks like a user record — a single object (optionally
// wrapped in .user/.data) OR a list of them, taking the first element. Empty
// string when nothing recognizable is present, so callers can treat that as
// "not a match" without a separate boolean.
function extractUserMarker(jsonText: string): string {
  try {
    const obj = JSON.parse(jsonText);
    let candidate: any = obj?.user ?? obj?.data ?? obj;
    if (Array.isArray(candidate)) candidate = candidate[0];
    if (!candidate || typeof candidate !== "object") return "";
    for (const k of ["email", "username", "role"]) {
      const v = candidate[k];
      if (typeof v === "string" && v) return v;
    }
    for (const k of ["email", "username", "role"]) {
      if (k in candidate) return `"${k}"`;
    }
  } catch {
    /* not JSON */
  }
  return "";
}

export async function runApiSecProbes(
  url: string,
  host: string,
  headers: Record<string, string>,
  opts: { bolaIdentities?: [BolaIdentity, BolaIdentity] } = {},
): Promise<any[]> {
  const apiSecFindings: any[] = [];
  try {
    const apiHeaders = { ...headers, "Cache-Control": "no-cache" };

    // 1. GraphQL Introspection Probe
    try {
      const gqlCtl = new AbortController();
      const gqlId = setTimeout(() => gqlCtl.abort(), 4000);
      const gqlBody = JSON.stringify({ query: "{__schema{types{name}}}" });

      const gqlRes = await safeFetch(`${url}/graphql`, {
        method: "POST",
        headers: { ...apiHeaders, "Content-Type": "application/json" },
        body: gqlBody,
        signal: gqlCtl.signal,
      });
      clearTimeout(gqlId);
      const gqlText = await gqlRes.text();

      // Confirm a real introspection RESULT (data.__schema.types), not merely
      // the echoed query string or an error mentioning "__schema".
      let typeCount = 0;
      try {
        const parsed = JSON.parse(gqlText);
        if (Array.isArray(parsed?.data?.__schema?.types)) typeCount = parsed.data.__schema.types.length;
      } catch {
        typeCount = 0;
      }
      if (typeCount > 0) {
        // Receipt: the introspection query and the schema dump it returned. The
        // returned schema IS the evidence — quote the "__schema" result marker.
        const quote = '"__schema"';
        const schemaIdx = gqlText.indexOf(quote);
        const requestText = renderRawRequest(
          "POST",
          `${url}/graphql`,
          { ...apiHeaders, "Content-Type": "application/json" },
          gqlBody,
        );
        const responseText = renderRawResponse(gqlRes, windowAround(gqlText, Math.max(0, schemaIdx), quote.length, 2000));
        apiSecFindings.push({
          testName: "GraphQL Schema Introspection Exposed",
          endpoint: "/graphql",
          // Disclosure, not exploitation — the schema is the evidence. Kept at
          // `high`, never `critical` (spec §3.6 / open decision #3).
          severity: "high",
          description:
            "An active API endpoint probe discovered that GraphQL introspection is globally reachable. Attackers can effortlessly dump the entire undocumented internal schema definitions.",
          fix: "Disable introspection blocks in the production GraphQL backend. Shield API with explicit token authentication schemas.",
          evidence: {
            method: "introspection",
            attack: { request: requestText, response: responseText },
            signal: {
              quote,
              offsetInResponse: responseText.indexOf(quote),
              why: `The endpoint answered a standard introspection query with a full schema result (data.__schema.types — ${typeCount} types), so the entire internal API schema is publicly dumpable.`,
            },
            demonstration: `We sent a standard GraphQL introspection query to /graphql and the server returned its full schema — ${typeCount} types — with no authentication required. Anyone can map your entire API surface, including undocumented fields.`,
            reproduction: `curl -s -X POST "${url}/graphql" -H "Content-Type: application/json" --data '${gqlBody}'`,
            capturedAt: new Date().toISOString(),
          },
        });
      }
    } catch (e) {
      /* Ignore fetch errors */
    }

    // 2. Exposed user-object endpoint probe (fixed-path guesses). This is a
    // single-request heuristic per path: it does NOT prove a cross-tenant
    // authorization break — that is the separate two-identity BOLA probe
    // below. So it is titled honestly ("Exposed User Object Endpoint"), never
    // "BOLA", which also keeps it from colliding with the PROVEN BOLA finding
    // during title-dedup. Covers both a single guessable admin-record path AND
    // a few common "list every user" admin-panel shapes — the latter returns
    // an ARRAY, not one object, so the marker extraction below checks the
    // first array element too. `apiHeaders` already carries any caller-supplied
    // auth (Bearer/Cookie/etc.), so this also catches the case the PRD calls
    // "broken access control": an endpoint that checks SOME session exists but
    // never checks the caller is actually authorized (any logged-in user, not
    // just an admin, gets the full list).
    for (const path of EXPOSED_USER_OBJECT_PATHS) {
      try {
        const idorCtl = new AbortController();
        const idorId = setTimeout(() => idorCtl.abort(), 4000);
        const idorUrl = `${url}${path}`;
        const idorRes = await safeFetch(idorUrl, { headers: apiHeaders, signal: idorCtl.signal });
        clearTimeout(idorId);
        const idorText = await idorRes.text();
        const idorCt = idorRes.headers.get("content-type") || "text/plain";

        // Only flag when a JSON user object/list is actually returned — a 200
        // HTML page that happens to contain the word "email" is not an exposed
        // record. Quote a real identifying value (or the key name) so the
        // receipt shows the leak.
        if (idorRes.status !== 200 || !/application\/json/i.test(idorCt)) continue;
        const marker = extractUserMarker(idorText);
        if (!marker || !idorText.includes(marker)) continue;

        apiSecFindings.push({
          testName: "Exposed User Object Endpoint",
          endpoint: path,
          severity: "critical",
          description: `A request to ${path} returned a JSON user/admin record directly. Protected user objects should not be served from a guessable path, and access to any user-list endpoint must be authorized per-caller, not just gated behind "some session exists".`,
          fix: "Require authentication AND role-based authorization on user endpoints; do not expose admin/user records at predictable paths.",
          evidence: buildProbeEvidence({
            method: "oracle",
            attackUrl: idorUrl,
            requestHeaders: apiHeaders,
            res: idorRes,
            body: idorText,
            matchIndex: idorText.indexOf(marker),
            quote: marker,
            why: "The endpoint returned a JSON user record carrying this identifying field, proving the user/admin object is served directly at this path.",
            demonstration: `We requested ${path} and the server returned a user record containing ${marker}. A protected user object is reachable directly at this path.`,
          }),
        });
        break; // one confirmed hit is enough — the remaining candidates are redundant signal of the same flaw
      } catch (e) {
        /* one path's fetch failure never aborts the rest — try the next candidate */
      }
    }

    // 3. Two-identity BOLA / IDOR — proves (or disproves) a cross-tenant read when
    // the caller supplied two owned test identities. Uses a clean, auth-free base
    // for the control request so "unauthenticated" really means no credentials.
    if (opts.bolaIdentities && opts.bolaIdentities.length === 2) {
      try {
        const bolaBase = {
          "User-Agent": headers["User-Agent"] || "Seclayer-Security-Scanner/2.0",
          "Cache-Control": "no-cache",
        };
        const bolaResults = await bolaProbe(host, opts.bolaIdentities, bolaBase);
        if (bolaResults) apiSecFindings.push(...bolaResults);
      } catch (e) {
        /* best-effort */
      }
    }
  } catch (globalErr) {
    console.warn("API Security fuzzing encounted top-level error", globalErr);
  }
  return apiSecFindings;
}
