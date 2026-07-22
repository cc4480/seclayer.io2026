import type { ScanErrorBody, ScanSuccess } from "./types.js";

export interface ScanRequest {
  url: string;
  authHeader?: string;
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
      body: JSON.stringify({ url: request.url, apiKey, authHeader: request.authHeader }),
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
