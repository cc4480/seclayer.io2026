import crypto from "crypto";
import * as dns from "dns/promises";

// Domain-ownership verification. Gates the scanner's ACTIVE offensive probes
// (SQLi/XSS/command-injection/SSRF/GraphQL/BOLA fuzzing) so the platform
// cannot be used as an anonymous attack proxy against arbitrary third-party
// sites: only a verified owner unlocks exploit-attempt testing. Passive
// black-box recon (headers, TLS, DNS, exposed files) remains available for
// any target regardless of verification status.
//
// Callers MUST validate the target with assertScanTargetSafe() (SSRF guard)
// before calling checkWellKnownFile, since it issues a real outbound request.

export function extractDomain(rawUrl: string): string {
  let u = (rawUrl || "").trim();
  if (!/^https?:\/\//i.test(u)) u = "https://" + u;
  return new URL(u).hostname.toLowerCase();
}

export function generateVerificationToken(): string {
  return "sl-verify-" + crypto.randomBytes(16).toString("hex");
}

export function txtRecordName(domain: string): string {
  return `_seclayer-challenge.${domain}`;
}

export const WELL_KNOWN_PATH = "/.well-known/seclayer-verification.txt";

// Checks the DNS TXT record at _seclayer-challenge.<domain> for the token.
export async function checkTxtRecord(domain: string, token: string): Promise<boolean> {
  try {
    const records = await dns.resolveTxt(txtRecordName(domain));
    return records.some((chunks) => chunks.join("").trim() === token);
  } catch {
    return false;
  }
}

// Checks for a well-known file on the target host containing the token.
// Redirects are not followed (manual) so a verification pass can't be routed
// through a hop the caller's SSRF check never saw.
export async function checkWellKnownFile(domain: string, token: string): Promise<boolean> {
  try {
    const ctl = new AbortController();
    const id = setTimeout(() => ctl.abort(), 5000);
    const res = await fetch(`https://${domain}${WELL_KNOWN_PATH}`, {
      redirect: "manual",
      signal: ctl.signal,
    }).finally(() => clearTimeout(id));
    if (!res.ok) return false;
    const body = await res.text();
    return body.trim() === token;
  } catch {
    return false;
  }
}
