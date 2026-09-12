// Baseline differential for signature-matching probes.
//
// A probe that fires a payload, greps the response for a signature and reports
// on a match is asserting that the payload CAUSED the signature. It has not
// checked that. If the signature is already in the page — a security tutorial
// quoting /etc/passwd, an operator runbook showing an SSH banner, a log viewer,
// a paste site, this project's own documentation — the match proves nothing and
// the finding is false.
//
// That is not hypothetical. The hardened reference target
// (test-targets/hardened-app.mjs) carries those signatures as static prose, and
// on its first run it produced seven CRITICAL findings at high confidence:
// one SSRF from a documented SSH banner and six Path Traversal / LFI from a
// documented passwd line, on a target with neither flaw.
//
// It is also the single error the false-positive audit has recorded most often:
// reading the PRESENCE of something as the MEANING of it.
//
// The fix is to ask the cheap question the probe skipped — "was this here
// before I sent anything?" — and only when a match has already been found, so
// a clean scan pays nothing for it.

import { probeFetch } from "./probeHttp.js";

/**
 * Whether `signature` is already present WITHOUT the attack payload.
 *
 * `true` means the signature is static page content and the caller must NOT
 * report a finding, however convincing the match looked.
 *
 * Fails CLOSED on a transport error: if the baseline cannot be fetched we
 * cannot show the payload caused anything, so the caller suppresses. A probe
 * that reported a critical vulnerability because its control request happened
 * to time out would be worse than one that occasionally stays quiet — and the
 * next scan re-tests it anyway.
 */
export async function signaturePreexists(
  baselineUrl: string,
  headers: Record<string, string>,
  signature: RegExp,
): Promise<boolean> {
  try {
    const res = await probeFetch(baselineUrl, headers);
    const body = await res.text();
    // Fresh lastIndex each call — a shared /g regex would otherwise carry state
    // between the attack test and this one and silently miss.
    return new RegExp(signature.source, signature.flags.replace("g", "")).test(body);
  } catch {
    return true;
  }
}
