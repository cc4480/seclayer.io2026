import { Scan, Finding } from "../src/types.js";
import { assertScanTargetSafe, guardedFetch } from "./scanner.js";

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

// Outcome of comparing a freshly completed scan against the target's previous
// completed scan. `shouldAlert` gates delivery so monitoring only pings on a
// real change in posture, not on every cycle a standing issue is re-found.
export interface RegressionResult {
  shouldAlert: boolean;
  isBaseline: boolean;       // no prior scan existed — this establishes the baseline
  reason: string;            // human summary of what regressed (empty when nothing did)
  newFindings: Finding[];    // active high/critical findings not present last time
  scoreDelta?: number;       // current − previous score (negative = worse)
}

function activeFindings(scan: Scan): Finding[] {
  return (scan.findings || []).filter((f) => !f.isFalsePositive);
}

function highOrCritical(f: Finding): boolean {
  return f.severity === "critical" || f.severity === "high";
}

// Stable cross-scan identity for a finding, so "the same issue as last time"
// isn't counted as new. Title + category + endpoint is stable across re-scans;
// the per-scan random `id` is not, and must not be used here.
function signature(f: Finding): string {
  return `${f.category}|${f.title}|${f.endpoint || ""}`.toLowerCase();
}

// True when a completed scan is worth alerting on (any active high/critical).
// Retained for callers/tests that want the raw "is this actionable" predicate;
// notifyScanComplete now gates on detectRegression instead.
export function shouldNotify(scan: Scan): boolean {
  if (scan.status !== "complete") return false;
  return activeFindings(scan).some(highOrCritical);
}

// Compares a completed scan against the previous completed scan of the same
// target and decides whether the change is worth an alert. First scan with any
// high/critical → baseline alert; later scans → alert only when a new
// high/critical appears or the posture score drops.
export function detectRegression(current: Scan, previous?: Scan): RegressionResult {
  const base: RegressionResult = { shouldAlert: false, isBaseline: !previous, reason: "", newFindings: [] };
  if (current.status !== "complete") return base;

  const currentHC = activeFindings(current).filter(highOrCritical);

  if (!previous || previous.status !== "complete") {
    if (currentHC.length === 0) return { ...base, isBaseline: true };
    return {
      shouldAlert: true,
      isBaseline: true,
      reason: `Initial monitoring scan found ${currentHC.length} high/critical finding(s).`,
      newFindings: currentHC,
    };
  }

  const priorSignatures = new Set(activeFindings(previous).filter(highOrCritical).map(signature));
  const newFindings = currentHC.filter((f) => !priorSignatures.has(signature(f)));
  const scoreDelta =
    current.score != null && previous.score != null ? current.score - previous.score : undefined;
  const scoreWorse = scoreDelta != null && scoreDelta < 0;

  if (newFindings.length === 0 && !scoreWorse) {
    return { shouldAlert: false, isBaseline: false, reason: "", newFindings: [], scoreDelta };
  }

  const reasons: string[] = [];
  if (newFindings.length > 0) reasons.push(`${newFindings.length} new high/critical finding(s)`);
  if (scoreWorse) reasons.push(`posture score dropped ${previous.score}→${current.score}`);
  return {
    shouldAlert: true,
    isBaseline: false,
    reason: `Regression detected: ${reasons.join("; ")}.`,
    newFindings,
    scoreDelta,
  };
}

export function buildScanNotification(scan: Scan, regression?: RegressionResult): ScanNotification {
  const active = activeFindings(scan);
  const critical = active.filter((f) => f.severity === "critical").length;
  const high = active.filter((f) => f.severity === "high").length;

  let headline = `🛡️ Seclayer scan complete for ${scan.url}`;
  if (regression?.isBaseline) headline = `🛡️ Seclayer monitoring baseline for ${scan.url}`;
  else if (regression && !regression.isBaseline) headline = `⚠️ Seclayer regression on ${scan.url}`;

  const parts = [
    headline,
    `Posture score: ${scan.score ?? "n/a"}/100 (${(scan.severity || "n/a").toUpperCase()})`,
    `${critical} critical, ${high} high finding(s).`,
  ];
  if (regression?.reason) parts.push(regression.reason);
  if (regression?.newFindings?.length) {
    const shown = regression.newFindings.slice(0, 5).map((f) => `• [${f.severity.toUpperCase()}] ${f.title}`);
    parts.push("New:", ...shown);
    if (regression.newFindings.length > 5) parts.push(`…and ${regression.newFindings.length - 5} more.`);
  }
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

// Posts the notification if the user opted in and the result represents a real
// regression against the target's previous scan (or a first-scan baseline with
// active high/critical findings). Never throws — notification failures must not
// affect the scan.
export async function notifyScanComplete(
  webhook: string | undefined,
  scan: Scan,
  previous?: Scan,
): Promise<void> {
  if (!webhook) return;
  const regression = detectRegression(scan, previous);
  if (!regression.shouldAlert) return;
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
    const payload = buildScanNotification(scan, regression);
    const ctl = new AbortController();
    const id = setTimeout(() => ctl.abort(), 5000);
    // guardedFetch pins the connection to a validated IP, so the delivery
    // cannot be DNS-rebound onto an internal address after the check above.
    await guardedFetch(webhook, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: ctl.signal,
    }).finally(() => clearTimeout(id));
  } catch (err: any) {
    console.warn(`[notify] webhook delivery failed: ${err?.message || err}`);
  }
}
