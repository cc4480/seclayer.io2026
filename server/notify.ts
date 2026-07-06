import { Scan, Finding } from "../src/types.js";
import { assertScanTargetSafe } from "./scanner.js";

// Outbound scan-completion alerts to a user-configured webhook (Slack incoming
// webhooks and generic JSON endpoints both accept the { text, ... } payload).
// Fires only for actionable results so monitoring isn't noisy.

export interface ScanNotification {
  text: string;
  scanId: string;
  url: string;
  score?: number;
  severity?: string;
  critical: number;
  high: number;
}

function activeFindings(scan: Scan): Finding[] {
  return (scan.findings || []).filter((f) => !f.isFalsePositive);
}

// True when a completed scan is worth alerting on (any active high/critical).
export function shouldNotify(scan: Scan): boolean {
  if (scan.status !== "complete") return false;
  return activeFindings(scan).some((f) => f.severity === "critical" || f.severity === "high");
}

export function buildScanNotification(scan: Scan): ScanNotification {
  const active = activeFindings(scan);
  const critical = active.filter((f) => f.severity === "critical").length;
  const high = active.filter((f) => f.severity === "high").length;
  const parts = [
    `🛡️ Seclayer scan complete for ${scan.url}`,
    `Posture score: ${scan.score ?? "n/a"}/100 (${(scan.severity || "n/a").toUpperCase()})`,
    `${critical} critical, ${high} high finding(s).`,
  ];
  return {
    text: parts.join("\n"),
    scanId: scan.id,
    url: scan.url,
    score: scan.score,
    severity: scan.severity,
    critical,
    high,
  };
}

// Posts the notification if the user opted in and the result is actionable.
// Never throws — notification failures must not affect the scan.
export async function notifyScanComplete(webhook: string | undefined, scan: Scan): Promise<void> {
  if (!webhook || !shouldNotify(scan)) return;
  // SSRF guard: the webhook host is user-controlled, so apply the same internal/
  // reserved-address block used for scan targets (also defeats DNS rebinding by
  // validating at delivery time). Refuse internal/non-http destinations.
  try {
    await assertScanTargetSafe(webhook);
  } catch {
    console.warn("[notify] webhook destination blocked (internal/invalid host); skipping delivery.");
    return;
  }
  try {
    const payload = buildScanNotification(scan);
    const ctl = new AbortController();
    const id = setTimeout(() => ctl.abort(), 5000);
    await fetch(webhook, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: ctl.signal,
    }).finally(() => clearTimeout(id));
  } catch (err: any) {
    console.warn(`[notify] webhook delivery failed: ${err?.message || err}`);
  }
}
