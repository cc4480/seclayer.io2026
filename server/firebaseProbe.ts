// Firebase Realtime Database open-rules probe. Firebase's web config is public
// BY DESIGN — the apiKey/databaseURL ship in every client bundle, so their mere
// presence is never the flaw. The flaw is when the database's SECURITY RULES
// allow unauthenticated reads: then anyone who reads the (public) databaseURL
// out of the bundle can read the whole database. We prove exactly that by GETting
// `<databaseURL>/.json` with NO credentials.
//
// The oracle is unambiguous and false-positive-proof: a locked-down database
// answers a denied read with HTTP 401 {"error":"Permission denied"}, so a 200 is
// positive proof the rules permit a public read — no guessing, no heuristics.
//
// Bounded and read-only (a GET or two per discovered database). The database
// origin is one the scanned app's OWN content named, not a guess, and reuses
// safeFetch's SSRF allow/deny logic unchanged — same discipline and trust bar as
// server/credentialChainProbe.ts, the other cross-origin BaaS probe.
import { safeFetch } from "./ssrf.js";
import { renderRawRequest, windowAround } from "./evidence.js";
import type { ExploitEvidence } from "../src/types.js";

// Matches a Firebase Realtime Database origin in served content — both the
// classic `<name>.firebaseio.com` and the regional
// `<name>-default-rtdb.<region>.firebasedatabase.app` forms.
const RTDB_URL_RE =
  /https?:\/\/[a-z0-9-]+\.(?:firebaseio\.com|(?:[a-z0-9-]+\.)?firebasedatabase\.app)/gi;

// Pulls distinct Realtime Database base URLs out of served content, capped at 3.
export function extractFirebaseDbUrls(bodyText: string): string[] {
  if (!bodyText) return [];
  const out = new Set<string>();
  let m: RegExpExecArray | null;
  RTDB_URL_RE.lastIndex = 0;
  while ((m = RTDB_URL_RE.exec(bodyText)) !== null) {
    out.add(m[0].replace(/\/+$/, ""));
    if (out.size >= 3) break;
  }
  return [...out];
}

export interface RtdbVerdict {
  // The rules permit an unauthenticated read (HTTP 200, not a 401 denial).
  open: boolean;
  // The root actually returned data (vs. an empty/null root that is still open).
  hasData: boolean;
}

// Pure classifier for a `/.json` read — the false-positive-critical decision,
// unit-tested without any network. A denied read is HTTP 401/403 (typically
// {"error":"Permission denied"}); ONLY a 200 with valid JSON proves open rules.
export function classifyRtdbRead(status: number, text: string): RtdbVerdict {
  if (status !== 200) return { open: false, hasData: false };
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    // A 200 that isn't valid JSON isn't the RTDB REST response we're proving on
    // (e.g. an HTML interstitial) — don't claim anything.
    return { open: false, hasData: false };
  }
  const hasData =
    data !== null &&
    !(typeof data === "object" && data !== null && Object.keys(data as object).length === 0);
  return { open: true, hasData };
}

async function timedGet(url: string, headers: Record<string, string>): Promise<{ res: Response; text: string } | null> {
  const ctl = new AbortController();
  const id = setTimeout(() => ctl.abort(), 5000);
  try {
    const res = await safeFetch(url, { headers, signal: ctl.signal });
    return { res, text: await res.text().catch(() => "") };
  } catch {
    return null;
  } finally {
    clearTimeout(id);
  }
}

// Probes each discovered Realtime Database for public-read rules. Returns an
// API-security finding (apiSecFindings-shaped) on the first open database, else
// null. `dbUrls` are pre-extracted by the caller (see extractFirebaseDbUrls).
export async function probeFirebaseOpenDb(
  dbUrls: string[],
  headers: Record<string, string>,
): Promise<any | null> {
  const ua = headers["User-Agent"] || "Seclayer-Security-Scanner/2.0";
  for (const base of dbUrls.slice(0, 3)) {
    const probeUrl = `${base}/.json`;
    const r = await timedGet(probeUrl, { "User-Agent": ua });
    if (!r) continue;
    const verdict = classifyRtdbRead(r.res.status, r.text);
    if (!verdict.open) continue; // 401/permission-denied → secured, no finding

    const proof = (verdict.hasData ? r.text.slice(0, 300) : "null") || "null";
    const attackResponse =
      `HTTP/1.1 ${r.res.status} ${r.res.statusText}\n\n` +
      windowAround(r.text || "null", 0, Math.min(proof.length, (r.text || "null").length), 1200);

    const why = verdict.hasData
      ? `An unauthenticated GET of the Realtime Database root returned HTTP 200 with real data, which only happens when the security rules permit public reads — a locked-down database answers a denied read with HTTP 401 {"error":"Permission denied"}.`
      : `An unauthenticated GET of the Realtime Database root returned HTTP 200 (empty at root), which only happens when the security rules permit public reads — a locked-down database answers with HTTP 401 {"error":"Permission denied"} instead.`;

    const evidence: ExploitEvidence = {
      method: "oracle",
      attack: { request: renderRawRequest("GET", probeUrl, {}), response: attackResponse },
      signal: { quote: proof, offsetInResponse: Math.max(0, attackResponse.indexOf(proof)), why },
      demonstration: `We requested ${probeUrl} with NO credentials and the database answered HTTP 200${verdict.hasData ? " and returned data" : ""} — a public read the rules should have denied.`,
      reproduction: `curl -s "${probeUrl}"`,
      capturedAt: new Date().toISOString(),
    };

    return {
      testName: verdict.hasData
        ? "Firebase Realtime Database Publicly Readable (data exposed)"
        : "Firebase Realtime Database Rules Allow Unauthenticated Reads",
      payload: probeUrl,
      severity: verdict.hasData ? "critical" : "high",
      description: verdict.hasData
        ? `The Firebase Realtime Database at ${base} returns data to an unauthenticated request at /.json — its security rules allow public reads, exposing the database contents to anyone. (The Firebase web config being public is expected; the permissive database RULES are the flaw.)`
        : `The Firebase Realtime Database at ${base} accepts an unauthenticated read at /.json (HTTP 200, currently empty at root) — its security rules permit public reads, so any data written under this database would be world-readable.`,
      fix: `Tighten the Realtime Database security rules so reads require an authenticated, authorized user — e.g. {"rules":{".read":"auth != null",".write":"auth != null"}} scoped per node, never {".read": true}. Then confirm an unauthenticated GET of /.json returns HTTP 401.`,
      evidence,
    };
  }
  return null;
}
