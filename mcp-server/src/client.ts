import type { AgentMessage, AgentToolCall, ScanErrorBody, ScanListSuccess, ScanReport, ScanSuccess } from "./types.js";

export interface ScanRequest {
  url: string;
  authHeader?: string;
  // Opt into the more-invasive aggressive tier (SSTI/LFI/XXE/CORS/CRLF/
  // open-redirect/NoSQL/host-header + stored XSS). Still non-destructive; still
  // gated on the same domain-ownership unlock as active probing.
  aggressive?: boolean;
}

export type ScanOutcome =
  | { ok: true; data: ScanSuccess }
  | {
      ok: false;
      kind: "bad_request" | "unauthorized" | "rate_limited" | "server_error" | "network" | "timeout" | "malformed";
      message: string;
      retryAfterSeconds?: number;
    };

// The backend runs the full synchronous diagnostic + AI pipeline per call
// (headers/secrets/library checks, subdomain enum, path probing, crawl +
// param fuzzing, then a thinking-mode AI report) — a real scan can
// legitimately take well over a minute, so this needs a generous bound.
export const DEFAULT_TIMEOUT_MS = 180_000;

// The aggressive tier adds more probes, more out-of-band waits, and heavier
// discovered-parameter fuzzing, so an aggressive scan legitimately runs longer
// than a standard one. It gets a larger bound so the client doesn't abort a scan
// the backend will still complete (which would surface a misleading timeout even
// though the result is retrievable via seclayer_get_report).
export const AGGRESSIVE_TIMEOUT_MS = 300_000;

// Calls POST /api/mcp/scan and never throws — every failure mode (HTTP error,
// network error, timeout, malformed response) is returned as a typed outcome
// so the caller (server.ts) can turn it into a clear MCP tool result instead
// of crashing the process. Mirrors the AbortController + setTimeout(abort)
// pattern used for the same reason in the main app's server/deepseekClient.ts.
export async function scan(
  baseUrl: string,
  apiKey: string,
  request: ScanRequest,
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
): Promise<ScanOutcome> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  let response: Response;
  try {
    response = await fetch(`${baseUrl}/api/mcp/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: request.url, apiKey, authHeader: request.authHeader, aggressiveProbes: request.aggressive }),
      signal: ctl.signal,
    });
  } catch (err: any) {
    if (err?.name === "AbortError") {
      return {
        ok: false,
        kind: "timeout",
        message: `The scan timed out after ${timeoutMs}ms contacting the Seclayer backend at ${baseUrl}. A full pen-test can take a while on a large target — retry, or check that ${baseUrl} is the correct backend.`,
      };
    }
    return {
      ok: false,
      kind: "network",
      message: `Could not reach the Seclayer backend at ${baseUrl}: ${err?.message || err}. Check connectivity and the --url / SECLAYER_API_URL setting.`,
    };
  } finally {
    clearTimeout(timer);
  }

  if (response.ok) {
    let data: ScanSuccess;
    try {
      data = (await response.json()) as ScanSuccess;
    } catch {
      return {
        ok: false,
        kind: "malformed",
        message: "Received an unparseable response from the Seclayer backend (expected JSON).",
      };
    }
    if (!data || data.success !== true) {
      return {
        ok: false,
        kind: "malformed",
        message: "Received an unexpected response shape from the Seclayer backend (missing success:true).",
      };
    }
    return { ok: true, data };
  }

  const body = (await response.json().catch(() => ({}))) as ScanErrorBody;
  const detail = body.error || body.message || body.details || `HTTP ${response.status}`;

  if (response.status === 400) {
    return {
      ok: false,
      kind: "bad_request",
      message: `Scan rejected: the target URL is invalid, unreachable, or blocked for safety (SSRF protection). Details: ${detail}. Check the URL and try again.`,
    };
  }
  if (response.status === 401) {
    return {
      ok: false,
      kind: "unauthorized",
      message: `Authentication or credit failure: the Seclayer API key is invalid/inactive, or the account is out of credits (the backend does not distinguish these two cases). Details: ${detail}. Verify the key and check your credit balance at https://seclayer.io.`,
    };
  }
  if (response.status === 429) {
    const retryAfterHeader = response.headers.get("retry-after");
    const retryAfterSeconds = retryAfterHeader ? Number(retryAfterHeader) : undefined;
    return {
      ok: false,
      kind: "rate_limited",
      message: `Rate limited: Seclayer allows a limited number of scans per minute. ${
        retryAfterSeconds ? `Wait ${retryAfterSeconds}s and retry.` : "Wait a moment and retry."
      }`,
      retryAfterSeconds,
    };
  }
  if (response.status >= 500) {
    return {
      ok: false,
      kind: "server_error",
      message: `The scan pipeline failed server-side. If a credit was spent for this attempt it has been automatically refunded${
        body.creditsRemaining !== undefined ? ` (credits remaining: ${body.creditsRemaining})` : ""
      }. Details: ${detail}. This is usually a transient target or backend issue — retry shortly.`,
    };
  }

  return {
    ok: false,
    kind: "malformed",
    message: `Received an unexpected ${response.status} response from the Seclayer backend. Details: ${detail}.`,
  };
}

// Read calls (list history, fetch a report) are cheap and never spend a credit,
// so they use a much shorter bound than a full scan.
export const READ_TIMEOUT_MS = 30_000;

export type ReadFailure = {
  ok: false;
  kind: "bad_request" | "unauthorized" | "not_found" | "not_ready" | "rate_limited" | "server_error" | "network" | "timeout" | "malformed";
  message: string;
  retryAfterSeconds?: number;
};

// Shared error mapping for the read endpoints — same typed-outcome discipline as
// scan() so a retrieval never throws, it returns a clear tool result.
async function mapReadError(baseUrl: string, response: Response, what: string): Promise<ReadFailure> {
  const body = (await response.json().catch(() => ({}))) as ScanErrorBody & { status?: string };
  const detail = body.error || body.message || `HTTP ${response.status}`;
  if (response.status === 401) {
    return { ok: false, kind: "unauthorized", message: `Authentication failed: the Seclayer API key is invalid or inactive. Details: ${detail}. Verify the key you passed with --key / SECLAYER_API_KEY.` };
  }
  if (response.status === 404) {
    return { ok: false, kind: "not_found", message: `${what} not found for this API key. Details: ${detail}. Use seclayer_list_scans to see the scans this key can access.` };
  }
  if (response.status === 409) {
    return { ok: false, kind: "not_ready", message: `That scan is not finished yet${body.status ? ` (status: ${body.status})` : ""}, so it has no report. Re-check with seclayer_list_scans, or wait for it to complete.` };
  }
  if (response.status === 429) {
    const retryAfterSeconds = response.headers.get("retry-after") ? Number(response.headers.get("retry-after")) : undefined;
    return { ok: false, kind: "rate_limited", message: `Rate limited by the Seclayer backend. ${retryAfterSeconds ? `Wait ${retryAfterSeconds}s and retry.` : "Wait a moment and retry."}`, retryAfterSeconds };
  }
  if (response.status >= 500) {
    return { ok: false, kind: "server_error", message: `The Seclayer backend errored fetching ${what.toLowerCase()}. Details: ${detail}. Usually transient — retry shortly.` };
  }
  return { ok: false, kind: "malformed", message: `Unexpected ${response.status} response from ${baseUrl}. Details: ${detail}.` };
}

async function readGet(baseUrl: string, path: string, apiKey: string, timeoutMs: number): Promise<{ ok: true; response: Response } | ReadFailure> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const response = await fetch(`${baseUrl}${path}`, { headers: { "X-API-Key": apiKey }, signal: ctl.signal });
    return { ok: true, response };
  } catch (err: any) {
    if (err?.name === "AbortError") {
      return { ok: false, kind: "timeout", message: `Timed out after ${timeoutMs}ms contacting the Seclayer backend at ${baseUrl}.` };
    }
    return { ok: false, kind: "network", message: `Could not reach the Seclayer backend at ${baseUrl}: ${err?.message || err}. Check connectivity and the --url / SECLAYER_API_URL setting.` };
  } finally {
    clearTimeout(timer);
  }
}

export type ListOutcome = { ok: true; data: ScanListSuccess } | ReadFailure;

// GET /api/mcp/scans — the key owner's recent scan history (compact).
export async function listScans(
  baseUrl: string,
  apiKey: string,
  limit?: number,
  timeoutMs: number = READ_TIMEOUT_MS,
): Promise<ListOutcome> {
  const qs = limit ? `?limit=${encodeURIComponent(String(limit))}` : "";
  const got = await readGet(baseUrl, `/api/mcp/scans${qs}`, apiKey, timeoutMs);
  if (!got.ok) return got;
  const { response } = got;
  if (!response.ok) return mapReadError(baseUrl, response, "Scan history");
  let data: ScanListSuccess;
  try {
    data = (await response.json()) as ScanListSuccess;
  } catch {
    return { ok: false, kind: "malformed", message: "Received an unparseable scan-history response (expected JSON)." };
  }
  if (!data || data.success !== true || !Array.isArray(data.scans)) {
    return { ok: false, kind: "malformed", message: "Received an unexpected scan-history response shape from the Seclayer backend." };
  }
  return { ok: true, data };
}

export type ReportOutcome = { ok: true; data: ScanReport } | ReadFailure;

// GET /api/mcp/scans/:id — one completed scan's full report (no credit cost).
export async function getReport(
  baseUrl: string,
  apiKey: string,
  scanId: string,
  timeoutMs: number = READ_TIMEOUT_MS,
): Promise<ReportOutcome> {
  const got = await readGet(baseUrl, `/api/mcp/scans/${encodeURIComponent(scanId)}`, apiKey, timeoutMs);
  if (!got.ok) return got;
  const { response } = got;
  if (!response.ok) return mapReadError(baseUrl, response, "Scan report");
  let data: ScanReport;
  try {
    data = (await response.json()) as ScanReport;
  } catch {
    return { ok: false, kind: "malformed", message: "Received an unparseable report response (expected JSON)." };
  }
  if (!data || data.success !== true) {
    return { ok: false, kind: "malformed", message: "Received an unexpected report response shape from the Seclayer backend." };
  }
  return { ok: true, data };
}

// --- Autofix: agentic tool-calling loop backing `seclayer-mcp autofix` ---
// The backend proxies each turn to DeepSeek and returns the model's next
// move; this client never sees or needs the model's raw API key — only the
// caller's own Seclayer API key, exactly like every other MCP call.

export type AutofixStartOutcome =
  | { ok: true; sessionId: string; creditsRemaining: number }
  | {
      ok: false;
      kind: "bad_request" | "unauthorized" | "rate_limited" | "server_error" | "network" | "timeout" | "malformed";
      message: string;
      retryAfterSeconds?: number;
    };

// POST /api/mcp/autofix/start — spends 1 credit and opens one fix attempt for
// one finding. Never throws; every failure mode is a typed outcome.
export async function startAutofixSession(
  baseUrl: string,
  apiKey: string,
  input: { url: string; findingTitle: string; findingCategory: string },
  timeoutMs: number = READ_TIMEOUT_MS,
): Promise<AutofixStartOutcome> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  let response: Response;
  try {
    response = await fetch(`${baseUrl}/api/mcp/autofix/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ apiKey, url: input.url, findingTitle: input.findingTitle, findingCategory: input.findingCategory }),
      signal: ctl.signal,
    });
  } catch (err: any) {
    if (err?.name === "AbortError") {
      return { ok: false, kind: "timeout", message: `Timed out after ${timeoutMs}ms starting an autofix session at ${baseUrl}.` };
    }
    return { ok: false, kind: "network", message: `Could not reach the Seclayer backend at ${baseUrl}: ${err?.message || err}.` };
  } finally {
    clearTimeout(timer);
  }

  if (response.ok) {
    const data = await response.json().catch(() => null) as { success?: boolean; sessionId?: string; creditsRemaining?: number } | null;
    if (!data || data.success !== true || !data.sessionId) {
      return { ok: false, kind: "malformed", message: "Received an unexpected response starting the autofix session (expected {success:true, sessionId})." };
    }
    return { ok: true, sessionId: data.sessionId, creditsRemaining: data.creditsRemaining ?? 0 };
  }

  const body = (await response.json().catch(() => ({}))) as ScanErrorBody;
  const detail = body.error || body.message || body.details || `HTTP ${response.status}`;
  if (response.status === 400) {
    return { ok: false, kind: "bad_request", message: `Autofix session rejected: ${detail}.` };
  }
  if (response.status === 401) {
    return { ok: false, kind: "unauthorized", message: `Authentication or credit failure starting autofix: ${detail}. Verify the key and check your credit balance at https://seclayer.io.` };
  }
  if (response.status === 429) {
    const retryAfterHeader = response.headers.get("retry-after");
    const retryAfterSeconds = retryAfterHeader ? Number(retryAfterHeader) : undefined;
    return {
      ok: false,
      kind: "rate_limited",
      message: `Rate limited starting an autofix session. ${retryAfterSeconds ? `Wait ${retryAfterSeconds}s and retry.` : "Wait a moment and retry."}`,
      retryAfterSeconds,
    };
  }
  if (response.status >= 500) {
    return { ok: false, kind: "server_error", message: `Autofix session failed server-side: ${detail}. Usually transient — retry shortly.` };
  }
  return { ok: false, kind: "malformed", message: `Received an unexpected ${response.status} response starting autofix: ${detail}.` };
}

export type AutofixTurnOutcome =
  | { ok: true; content: string | null; toolCalls: AgentToolCall[]; turnsUsed: number; turnsRemaining: number; sessionDone: boolean }
  | {
      ok: false;
      kind: "bad_request" | "unauthorized" | "not_found" | "conflict" | "rate_limited" | "server_error" | "network" | "timeout" | "malformed";
      message: string;
      retryAfterSeconds?: number;
    };

// Agent-turn calls run a real DeepSeek completion server-side, so this gets a
// generous bound — longer than a plain read, shorter than a full scan.
export const AUTOFIX_TURN_TIMEOUT_MS = 130_000;

// POST /api/mcp/autofix/turn — sends the transcript so far, gets back the
// model's next move. Never throws.
export async function autofixTurn(
  baseUrl: string,
  apiKey: string,
  sessionId: string,
  messages: AgentMessage[],
  timeoutMs: number = AUTOFIX_TURN_TIMEOUT_MS,
): Promise<AutofixTurnOutcome> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  let response: Response;
  try {
    response = await fetch(`${baseUrl}/api/mcp/autofix/turn`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ apiKey, sessionId, messages }),
      signal: ctl.signal,
    });
  } catch (err: any) {
    if (err?.name === "AbortError") {
      return { ok: false, kind: "timeout", message: `Timed out after ${timeoutMs}ms waiting for an autofix turn at ${baseUrl}.` };
    }
    return { ok: false, kind: "network", message: `Could not reach the Seclayer backend at ${baseUrl}: ${err?.message || err}.` };
  } finally {
    clearTimeout(timer);
  }

  if (response.ok) {
    const data = (await response.json().catch(() => null)) as
      | { success?: boolean; content?: string | null; toolCalls?: AgentToolCall[]; turnsUsed?: number; turnsRemaining?: number; sessionDone?: boolean }
      | null;
    if (!data || data.success !== true) {
      return { ok: false, kind: "malformed", message: "Received an unexpected response for an autofix turn (expected {success:true, ...})." };
    }
    return {
      ok: true,
      content: data.content ?? null,
      toolCalls: data.toolCalls ?? [],
      turnsUsed: data.turnsUsed ?? 0,
      turnsRemaining: data.turnsRemaining ?? 0,
      sessionDone: data.sessionDone ?? false,
    };
  }

  const body = (await response.json().catch(() => ({}))) as ScanErrorBody;
  const detail = body.error || body.message || body.details || `HTTP ${response.status}`;
  if (response.status === 400) {
    return { ok: false, kind: "bad_request", message: `Autofix turn rejected: ${detail}.` };
  }
  if (response.status === 401) {
    return { ok: false, kind: "unauthorized", message: `Authentication failed for an autofix turn: ${detail}.` };
  }
  if (response.status === 404) {
    return { ok: false, kind: "not_found", message: `Autofix session not found: ${detail}.` };
  }
  if (response.status === 409) {
    return { ok: false, kind: "conflict", message: `Autofix session can't continue: ${detail}.` };
  }
  if (response.status === 429) {
    const retryAfterHeader = response.headers.get("retry-after");
    const retryAfterSeconds = retryAfterHeader ? Number(retryAfterHeader) : undefined;
    return {
      ok: false,
      kind: "rate_limited",
      message: `Rate limited on an autofix turn. ${retryAfterSeconds ? `Wait ${retryAfterSeconds}s and retry.` : "Wait a moment and retry."}`,
      retryAfterSeconds,
    };
  }
  if (response.status >= 500) {
    return { ok: false, kind: "server_error", message: `Autofix turn failed server-side: ${detail}. Usually transient — retry shortly.` };
  }
  return { ok: false, kind: "malformed", message: `Received an unexpected ${response.status} response on an autofix turn: ${detail}.` };
}
