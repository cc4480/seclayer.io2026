// Insecure deserialization exposure (PASSIVE). Detects a serialized object
// stored in a COOKIE the server issued — a value the client controls and the
// server must deserialize on its next request, which is the root condition for
// an insecure-deserialization attack (CWE-502 / OWASP A08).
//
// Cookie-scoped deliberately. A serialized blob that only appears in a response
// BODY may be display-only and never fed back to a deserializer, but one
// round-tripped through a cookie is, by definition, deserialized server-side —
// so the cookie form is the low-false-positive signal. This is DETECTION, not
// exploitation: no gadget chain is attempted, so the finding is HIGH, never
// critical, matching the codebase's disclosure-vs-exploitation severity rule.

import type { ExploitEvidence } from "../src/types.js";

export interface DeserializationFinding {
  testName: string;
  endpoint: string;
  severity: "high";
  description: string;
  fix: string;
  // 'observation' — a passive read of a Set-Cookie header, never an exploit;
  // isProven() is false for it. Same receipt shape every finding carries.
  evidence: ExploitEvidence;
}

interface Marker {
  format: string;
  rx: RegExp;
  note: string;
}

// Each marker is anchored to a serialization format's magic bytes / grammar, not
// to loose base64 — the same discipline the SQL/LDAP error signatures use. A
// generic base64 or JWT (three dot-separated base64url segments) must not match.
const MARKERS: Marker[] = [
  // Java: AC ED 00 05 → base64 "rO0AB". Extremely specific.
  { format: "Java", rx: /rO0AB[A-Za-z0-9+/=]{8,}/, note: "base64 of the Java serialization stream header (AC ED 00 05)" },
  // PHP serialized object: O:<len>:"<Class>":<n>:{ …
  { format: "PHP", rx: /(?:^|[^A-Za-z0-9])O:\d{1,3}:"[^"]{1,120}":\d{1,4}:\{/, note: 'a PHP serialized object (O:len:"Class":n:{…})' },
  // PHP serialized array: a:<n>:{ followed by a typed element.
  { format: "PHP", rx: /(?:^|[^A-Za-z0-9])a:\d{1,4}:\{[isbdOa]:/, note: "a PHP serialized array (a:n:{…})" },
  // Ruby Marshal: 04 08 → base64 "BAh". Anchored long to avoid a chance match.
  { format: "Ruby (Marshal)", rx: /BAh[A-Za-z0-9+/=]{16,}/, note: "base64 of the Ruby Marshal magic (04 08)" },
  // Python pickle: 80 02/03/04/05 → base64 "gAJ"/"gAN"/"gAQ"/"gAU"-ish; match the opcode family, anchored long.
  { format: "Python (pickle)", rx: /gA[JNQU][A-Za-z0-9+/=]{12,}/, note: "base64 of a Python pickle protocol opcode (80 0x)" },
];

// A JWT is three base64url segments joined by dots — legitimate, and never a
// serialized-object exposure. Exclude it up front so a JWT session cookie can't
// trip the base64 markers.
const JWT_RE = /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/;

function decodeOnce(value: string): string {
  try { return decodeURIComponent(value); } catch { return value; }
}

/**
 * Scan the RAW Set-Cookie lines (values intact) a server issued for a serialized
 * object. Pass the real values, not the redacted ones — the serialization header
 * is a format marker, not secret material, and only a short prefix is retained.
 */
export function scanCookiesForSerialized(setCookieLines: string[], source = "the scanned response"): DeserializationFinding[] {
  const out: DeserializationFinding[] = [];
  const seen = new Set<string>();

  for (const line of setCookieLines || []) {
    const first = (line || "").split(";")[0];
    const eq = first.indexOf("=");
    if (eq <= 0) continue;
    const name = first.slice(0, eq).trim();
    const rawVal = first.slice(eq + 1).trim();
    if (!name || rawVal.length < 12) continue;

    // Consider both the raw and once-URL-decoded value (cookies are often
    // percent-encoded). A JWT is excluded — it is not a deserialization sink.
    for (const val of [rawVal, decodeOnce(rawVal)]) {
      if (JWT_RE.test(val)) continue;
      let matched = false;
      for (const m of MARKERS) {
        const hit = m.rx.exec(val);
        if (!hit) continue;
        const key = `${name}|${m.format}`;
        if (seen.has(key)) { matched = true; break; }
        seen.add(key);
        // The value is redacted to its format-header prefix (generic serialization
        // magic, not the payload/secret), so the receipt proves the format without
        // leaking a session token.
        const sample = hit[0].slice(0, 24);
        const receiptResponse = `Set-Cookie: ${name}=${sample}… (value redacted)`;
        out.push({
          testName: `Insecure Deserialization Exposure — ${m.format} serialized object in cookie "${name}"`,
          endpoint: `cookie:${name}`,
          severity: "high",
          description:
            `The cookie "${name}" carries a ${m.format} serialized object. Because the client returns this cookie on every request, the server deserializes an attacker-modifiable value — the root condition for insecure deserialization (CWE-502), which frequently escalates to remote code execution through a gadget chain.`,
          fix:
            `Do not deserialize native ${m.format} objects from client-supplied data. Store only an opaque server-side session id in the cookie (with the object held server-side), or use a data-only format (JSON) with strict schema validation and a signature/MAC (e.g. HMAC) so a tampered value is rejected before deserialization.`,
          evidence: {
            method: "observation",
            attack: { request: `Observed in the HTTP response from ${source}`, response: receiptResponse },
            signal: {
              quote: sample,
              offsetInResponse: receiptResponse.indexOf(sample),
              why: `This is ${m.note}, which appears only when a native ${m.format} object has been serialized into the cookie — proving the server round-trips and deserializes this client-controlled value.`,
            },
            demonstration: `The response from ${source} set a cookie "${name}" whose value is a ${m.format} serialized object — a value the browser sends back and the server deserializes on every request.`,
            reproduction: `curl -s -i "${source}" | grep -i "^set-cookie: ${name}="`,
            capturedAt: new Date().toISOString(),
          },
        });
        matched = true;
        break; // one format per cookie
      }
      if (matched) break; // don't double-report the decoded variant
    }
  }
  return out;
}
