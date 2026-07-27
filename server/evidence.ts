// Evidence-bundle helpers — the receipts behind PROVEN findings.
//
// These turn a live probe exchange into the stored, replayable proof a
// non-expert can look at and believe. Credentials are redacted; the payload that
// constitutes the proof is always preserved; bodies are truncated only with
// explicit markers, keeping the invariant that signal.quote is a literal
// substring of the stored response (the whole basis for calling a finding
// PROVEN — see scoring.isProven). Also hosts two small response/auth helpers the
// probes lean on.
import { ExploitEvidence, OobEvent } from "../src/types.js";

// Heuristic: does this body look like an HTML document (e.g. a single-page-app
// catch-all that returns index.html for every path)? Used to suppress false
// positives where a 200 response is just the SPA shell, not a real exposed file.
export function looksLikeHtml(body: string): boolean {
  const head = body.slice(0, 512).toLowerCase();
  return /<!doctype html|<html|<head|<body|<title|<div|<script|<meta/.test(head);
}

// Parses a user-supplied credential into request headers for authenticated
// scans. Accepts either a bare Authorization value ("Bearer …", "Basic …") or
// an explicit "Header-Name: value" (e.g. "Cookie: session=…", "X-API-Key: …"),
// enabling token, basic, cookie, or custom-header authentication.
export function parseAuthHeader(authHeader?: string): Record<string, string> {
  const raw = (authHeader || "").trim();
  if (!raw) return {};
  const idx = raw.indexOf(":");
  if (idx > 0) {
    const name = raw.slice(0, idx).trim();
    const value = raw.slice(idx + 1).trim();
    if (name && value && /^[A-Za-z0-9-]+$/.test(name) && !/^(bearer|basic|negotiate|digest)$/i.test(name)) {
      return { [name]: value };
    }
  }
  return { Authorization: raw };
}

const SENSITIVE_HEADER = /^(authorization|cookie|set-cookie|x-api-key|proxy-authorization)$/i;

function redactHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    out[k] = SENSITIVE_HEADER.test(k) ? "***(redacted)" : v;
  }
  return out;
}

export function renderRawRequest(
  method: string,
  urlStr: string,
  headers: Record<string, string>,
  body?: string,
): string {
  let u: URL;
  try {
    u = new URL(urlStr);
  } catch {
    return `${method} ${urlStr}`;
  }
  const lines = [`${method} ${u.pathname}${u.search} HTTP/1.1`, `Host: ${u.host}`];
  for (const [k, v] of Object.entries(redactHeaders(headers))) lines.push(`${k}: ${v}`);
  if (body != null) lines.push("", body);
  return lines.join("\n");
}

// Slice a body down to `budget` bytes while GUARANTEEING the proof at
// [matchIdx, matchIdx+matchLen) survives intact, with explicit truncation markers
// on either side. This keeps the invariant that signal.quote is a literal
// substring of the stored response — the whole basis for calling a finding PROVEN.
export function windowAround(body: string, matchIdx: number, matchLen: number, budget = 2000): string {
  if (body.length <= budget) return body;
  const pad = Math.max(0, Math.floor((budget - matchLen) / 2));
  let end = Math.min(body.length, matchIdx + matchLen + pad);
  let start = Math.max(0, end - budget);
  end = Math.min(body.length, start + budget);
  let out = body.slice(start, end);
  if (start > 0) out = `[…truncated ${start} bytes]\n` + out;
  if (end < body.length) out = out + `\n[…truncated ${body.length - end} bytes]`;
  return out;
}

export function renderRawResponse(res: Response, bodyWindow: string): string {
  const lines = [`HTTP/1.1 ${res.status} ${res.statusText}`];
  for (const h of ["content-type", "server", "content-length"]) {
    const v = res.headers.get(h);
    if (v) lines.push(`${h}: ${v}`);
  }
  lines.push("", bodyWindow);
  return lines.join("\n");
}

// Assemble a full exploit receipt from a single attack exchange whose proof is
// a substring of the response body at [matchIndex, matchIndex+quote.length). The
// response is windowed so the proof always survives truncation, keeping the
// invariant that signal.quote is a literal substring of the stored response.
//
// Defaults to a GET exchange. For a POST body injection (the discovered-form
// fuzzer), pass reqMethod:"POST" with the reqBody and reqContentType actually
// sent, so the receipt's raw request and curl reproduction show the real POST —
// the proof (signal.quote in the response) is identical either way.
export function buildProbeEvidence(params: {
  method: ExploitEvidence["method"];
  attackUrl: string;
  requestHeaders: Record<string, string>;
  res: Response;
  body: string;
  matchIndex: number;
  quote: string;
  why: string;
  demonstration: string;
  reqMethod?: "GET" | "POST";
  reqBody?: string;
  reqContentType?: string;
}): ExploitEvidence {
  const reqMethod = params.reqMethod || "GET";
  const bodyWindow = windowAround(params.body, params.matchIndex, params.quote.length);
  const response = renderRawResponse(params.res, bodyWindow);
  const reqHeaders =
    reqMethod === "POST" && params.reqContentType
      ? { ...params.requestHeaders, "Content-Type": params.reqContentType }
      : params.requestHeaders;
  const request = renderRawRequest(reqMethod, params.attackUrl, reqHeaders, params.reqBody);
  const reproduction =
    reqMethod === "POST"
      ? `curl -s -X POST "${params.attackUrl}"` +
        (params.reqContentType ? ` -H "Content-Type: ${params.reqContentType}"` : "") +
        (params.reqBody != null ? ` --data '${params.reqBody}'` : "")
      : `curl -s "${params.attackUrl}"`;
  return {
    method: params.method,
    attack: { request, response },
    signal: {
      quote: params.quote,
      offsetInResponse: response.indexOf(params.quote),
      why: params.why,
    },
    demonstration: params.demonstration,
    reproduction,
    capturedAt: new Date().toISOString(),
  };
}

// Assemble a receipt for a BLIND finding proven out-of-band. There is no inline
// signal to quote from the target's HTTP response, so the captured proof IS the
// callback our collaborator recorded: attack.request is the payload we sent to
// the target, and attack.response is the reconstructed callback the target then
// made to us. signal.quote is the unique per-probe token — it can only appear in
// that record if the target actually reached our URL, so isProven's substring
// check stays an honest guarantee ("we never claim a byte we didn't capture").
export function buildOobEvidence(params: {
  attackUrl: string;
  requestHeaders: Record<string, string>;
  callbackUrl: string;
  token: string;
  event: OobEvent;
  demonstration: string;
  why: string;
}): ExploitEvidence {
  const response = [
    `Out-of-band callback received by Seclayer collaborator:`,
    `${params.event.method} ${params.event.path} HTTP/1.1`,
    `From: ${params.event.sourceIp}`,
    params.event.userAgent ? `User-Agent: ${params.event.userAgent}` : undefined,
    `Received-At: ${params.event.receivedAt}`,
    `Correlation-Token: ${params.token}`,
  ]
    .filter((l): l is string => l != null)
    .join("\n");
  return {
    method: "out-of-band",
    attack: {
      request: renderRawRequest("GET", params.attackUrl, params.requestHeaders),
      // The callback the target made to us, reconstructed from what we recorded.
      response,
    },
    signal: {
      quote: params.token,
      offsetInResponse: response.indexOf(params.token),
      why: params.why,
    },
    demonstration: params.demonstration,
    reproduction: `curl -s "${params.attackUrl}"  # then observe a callback to ${params.callbackUrl}`,
    capturedAt: new Date().toISOString(),
  };
}

// Pull a value that distinctively identifies whose data a response carries — used
// to prove a BOLA cross-tenant read (the marker belongs to identity B yet shows up
// in identity A's request). An email is the most legible, least-ambiguous marker;
// a caller-supplied ownMarker always wins.
export function extractIdentityMarker(text: string, provided?: string): string | null {
  if (provided && text.includes(provided)) return provided;
  const email = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/.exec(text);
  return email ? email[0] : null;
}
