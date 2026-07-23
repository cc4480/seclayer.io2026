// Shared fetch helper for the red-team probes. Wraps safeFetch (the SSRF-guarded
// fetch) in the AbortController + setTimeout + clearTimeout pattern every probe
// otherwise repeated verbatim. The timer guards the request only — the body read
// happens after the timer is cleared, matching the original per-probe behavior.
import { safeFetch } from "../ssrf.js";

// Each active probe caps a single request at 4s so one slow endpoint can't stall
// the whole scan pipeline.
export const PROBE_TIMEOUT_MS = 4000;

export async function probeFetch(
  url: string,
  headers: Record<string, string>,
  timeoutMs = PROBE_TIMEOUT_MS,
): Promise<Response> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    return await safeFetch(url, { headers, signal: ctl.signal });
  } finally {
    clearTimeout(timer);
  }
}
