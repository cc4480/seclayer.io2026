// Shared helpers for the AGGRESSIVE tier probes (SSTI / LFI / SSRF-family / CORS
// / CRLF / XXE / NoSQL). Like the red-team probes these are SSRF-guarded and
// bounded, but several of them prove the flaw from a RESPONSE HEADER or an
// out-of-band callback rather than a body substring — buildHeaderEvidence and
// buildPostOobEvidence assemble those receipts while preserving the PROVEN
// invariant (signal.quote is a literal substring of the stored attack.response).
import type { ExploitEvidence, OobEvent } from "../../src/types.js";
import { renderRawRequest } from "../evidence.js";
import { guardedFetch, safeFetch } from "../ssrf.js";

export const AGG_TIMEOUT_MS = 4000;

// GET/POST with the SSRF-guarded fetch + the AbortController timeout the probes
// otherwise repeat. safeFetch FOLLOWS redirects (re-validating each hop), which
// is right for body-content probes but wrong for header-level ones.
export async function aggFetch(
  url: string,
  init: RequestInit,
  timeoutMs = AGG_TIMEOUT_MS,
): Promise<Response> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    return await safeFetch(url, { ...init, signal: ctl.signal });
  } finally {
    clearTimeout(timer);
  }
}

// Single SSRF-guarded request that does NOT follow redirects, so a 3xx response
// and its headers are returned raw. Required for header-level proofs (open
// redirect, CRLF): safeFetch would follow the 3xx — re-validating an off-site
// Location and throwing, or discarding the injected header — destroying the
// evidence. guardedFetch still pins the connection to a validated, non-internal
// IP, so it is not an SSRF bypass.
export async function aggFetchRaw(
  url: string,
  init: RequestInit,
  timeoutMs = AGG_TIMEOUT_MS,
): Promise<Response> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    return await guardedFetch(url, { ...init, redirect: "manual", signal: ctl.signal });
  } finally {
    clearTimeout(timer);
  }
}

// Receipt whose proof lives in the response STATUS LINE + selected headers (open
// redirect, CORS, CRLF). proofHeaders are rendered verbatim into the stored
// response so signal.quote (a substring of one of them) stays a literal match.
export function buildHeaderEvidence(p: {
  method: ExploitEvidence["method"];
  reqMethod: string;
  attackUrl: string;
  requestHeaders: Record<string, string>;
  requestBody?: string;
  res: Response;
  proofHeaders: string[];
  quote: string;
  why: string;
  demonstration: string;
  reproduction?: string;
}): ExploitEvidence {
  const response = [`HTTP/1.1 ${p.res.status} ${p.res.statusText}`, ...p.proofHeaders].join("\n");
  return {
    method: p.method,
    attack: {
      request: renderRawRequest(p.reqMethod, p.attackUrl, p.requestHeaders, p.requestBody),
      response,
    },
    signal: { quote: p.quote, offsetInResponse: response.indexOf(p.quote), why: p.why },
    demonstration: p.demonstration,
    reproduction: p.reproduction || `curl -s -i "${p.attackUrl}"`,
    capturedAt: new Date().toISOString(),
  };
}

// Out-of-band receipt for a POST-triggered blind flaw (XXE). Mirrors
// evidence.buildOobEvidence but renders the POST request + body that carried the
// payload; the proof is the recorded callback carrying our unique token.
export function buildPostOobEvidence(p: {
  reqMethod: string;
  attackUrl: string;
  requestHeaders: Record<string, string>;
  requestBody: string;
  callbackUrl: string;
  token: string;
  event: OobEvent;
  why: string;
  demonstration: string;
}): ExploitEvidence {
  const response = [
    `Out-of-band callback received by Seclayer collaborator:`,
    `${p.event.method} ${p.event.path} HTTP/1.1`,
    `From: ${p.event.sourceIp}`,
    p.event.userAgent ? `User-Agent: ${p.event.userAgent}` : undefined,
    `Received-At: ${p.event.receivedAt}`,
    `Correlation-Token: ${p.token}`,
  ]
    .filter((l): l is string => l != null)
    .join("\n");
  return {
    method: "out-of-band",
    attack: {
      request: renderRawRequest(p.reqMethod, p.attackUrl, p.requestHeaders, p.requestBody),
      response,
    },
    signal: { quote: p.token, offsetInResponse: response.indexOf(p.token), why: p.why },
    demonstration: p.demonstration,
    reproduction: `# POST the XXE payload to ${p.attackUrl}, then observe a callback to ${p.callbackUrl}`,
    capturedAt: new Date().toISOString(),
  };
}
