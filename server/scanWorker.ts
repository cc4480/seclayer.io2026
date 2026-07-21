// Background scan worker. Drives a queued scan through its real lifecycle —
// diagnostics → AI analysis → complete (or failed) — with status reflecting
// actual work boundaries, no artificial delays. Bound to an optional OOB
// collaborator for blind-vuln proofs. Returned as a closure so both the HTTP
// routes and the monitoring worker share one implementation.
import { db, recalculateScore } from "./db.js";
import {
  runDiagnostics, compileStaticFindings, compileScanEvidence, parseAuthHeader,
} from "./scanner.js";
import { captureScreenshot } from "./render.js";
import { generateAiReport } from "./deepseek.js";
import { narrateScanning, narrateAnalysis } from "./narrate.js";
import { notifyScanComplete } from "./notify.js";
import type { OobCollaborator } from "./oob.js";
import type { BolaIdentity } from "../src/types.js";

export function makeProcessScanJob(oobCollaborator?: OobCollaborator) {
  return async function processScanJob(
    scanId: string,
    allowActiveProbes: boolean,
    bolaIdentities?: [BolaIdentity, BolaIdentity],
  ): Promise<void> {
    try {
      console.log(`[Job Worker] Starting scan ${scanId}`);

      const scan = db.getScan(scanId);
      if (!scan) return;

      let narration: string[] = [];

      // Active diagnostics (HTTP probing, header/secret/SCA/path checks, fuzzing).
      db.updateScan(scanId, { status: "scanning" });
      const diagnostics = await runDiagnostics(scan.url, scan.authHeader, { allowActiveProbes, bolaIdentities, oob: oobCollaborator, scanId });

      // Fast (flash), cheap narration of what the sweep actually found — read
      // by the progress UI in place of scripted filler text.
      narration = narration.concat(await narrateScanning(diagnostics, scan.url));
      db.updateScan(scanId, { status: "analyzing", narrationLog: narration });

      // Compile findings and generate the analysis report.
      const staticCompiled = compileStaticFindings(diagnostics);
      const outputReport = await generateAiReport(scan.url, diagnostics, staticCompiled);

      // Narrate the score the UI will actually display: every read path
      // (getScanWithSuppressedFindings) recalculates it deterministically
      // from finding severities, which can differ from the AI's own
      // subjective adjustedScore stored below — narrating the raw AI figure
      // would show the user a number that contradicts the report they open next.
      const { score: displayScore, severity: displaySeverity } = recalculateScore(outputReport.findings);
      narration = narration.concat(await narrateAnalysis({ score: displayScore, severity: displaySeverity, findings: outputReport.findings }, scan.url));

      // Best-effort visual capture of the target's landing page (opt-in via
      // ENABLE_TARGET_SCREENSHOT). Returns null — never throws — when disabled,
      // unavailable, or blocked, so it can never fail the scan. Reuses the same
      // auth headers the diagnostics used.
      const evidence = compileScanEvidence(diagnostics);
      const shot = await captureScreenshot(scan.url, {
        "User-Agent": "Seclayer-Security-Scanner/2.0 (+https://seclayer.io)",
        ...parseAuthHeader(scan.authHeader),
      });
      if (shot) evidence.screenshot = shot;

      const completed = db.updateScan(scanId, {
        status: "complete",
        score: outputReport.score,
        severity: outputReport.severity,
        findings: outputReport.findings,
        aiSummary: outputReport.aiSummary,
        aiReasoning: outputReport.aiReasoning,
        narrationLog: narration,
        executiveBreakdown: outputReport.executiveBreakdown,
        evidence,
        completedAt: new Date().toISOString(),
      });
      console.log(`[Job Worker] Completed scan ${scanId}`);

      // Fire the user's alert webhook when posture regresses vs the previous
      // scan of this target (non-blocking). Both current and baseline are read
      // through the suppression read-model so a suppressed finding never counts.
      const owner = db.getUser(completed.userId);
      const current = db.getScanWithSuppressedFindings(completed);
      const prior = db.getPreviousCompletedScan(completed.userId, completed.url, completed.id);
      const priorSuppressed = prior ? db.getScanWithSuppressedFindings(prior) : undefined;
      notifyScanComplete(owner?.notifyWebhook, current, priorSuppressed);
    } catch (err: any) {
      console.error(`[Job Worker] FAILED scan ${scanId}:`, err?.message || err);
      db.updateScan(scanId, {
        status: "failed",
        error: err?.message || "The scan could not be completed.",
      });
    }
  };
}
