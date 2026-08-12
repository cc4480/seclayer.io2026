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
import { narrateScanning, narrateAnalysis, narrateLiveBatch } from "./narrate.js";
import { notifyScanComplete } from "./notify.js";
import * as scanEvents from "./scanEvents.js";
import type { ScanEventStream } from "./scanEvents.js";
import type { OobCollaborator } from "./oob.js";
import type { BolaIdentity, LoginCredentials } from "../src/types.js";
import { Semaphore } from "./semaphore.js";
import { config } from "./config.js";

// There is no cancellation token threaded through the probe pipeline (see
// db.cancelScan's doc comment), so a canceled scan's in-flight network work
// still runs to completion — this only stops the worker from writing a stale
// status/result over the user's cancellation once each stage finishes, and
// skips starting the next (most importantly, the AI report call) once a
// cancellation is seen.
async function isCanceled(scanId: string): Promise<boolean> {
  return (await db.getScan(scanId))?.status === "canceled";
}

export function makeProcessScanJob(oobCollaborator?: OobCollaborator) {
  // Cap concurrent in-process scans so a burst can't spawn unbounded
  // runDiagnostics work and exhaust this instance. Shared across every caller
  // (dashboard "scan now", MCP, and the monitoring worker) so none can bypass
  // the cap. Excess scans wait here while their row stays 'queued' — crash-safe,
  // since recoverStuckScans sweeps 'queued' on the next boot.
  const scanSlots = new Semaphore(config.maxConcurrentScans);

  const runScanJob = async function (
    scanId: string,
    allowActiveProbes: boolean,
    bolaIdentities?: [BolaIdentity, BolaIdentity],
    allowAggressiveProbes?: boolean,
    loginCredentials?: LoginCredentials,
  ): Promise<void> {
    // Live ticker plumbing, declared out here so the finally can always tear it
    // down regardless of which return/throw path the scan takes.
    let stream: ScanEventStream | undefined;
    let liveNarrator: ReturnType<typeof setInterval> | undefined;
    try {
      console.log(`[Job Worker] Starting scan ${scanId}`);

      const scan = (await db.getScan(scanId));
      if (!scan || await isCanceled(scanId)) return;

      // The scan owner's personal DeepSeek key (BYOK), when set — used for AI
      // report generation and narration so a user can bring their own AI budget.
      // Falls back to the server-wide key, then local summaries (see resolveApiKey).
      const userDeepseekKey = (await db.getUserDeepseekKey(scan.userId));

      let narration: string[] = [];

      // Open the real-time event stream and start a background narrator: every
      // ~2s it drains the newest raw probe/recon events and asks Flash for a
      // couple of plain-English "why" lines, emitted back on the 'flash' channel.
      // A busy-guard prevents overlapping calls; the whole thing is torn down in
      // the finally. The raw events themselves carry built-in descriptions, so
      // the ticker stays fully explanatory even if Flash returns nothing.
      stream = scanEvents.openStream(scanId);
      const emit = stream.emit;
      emit("system", `Launching scan of ${scan.url} — validating target & resolving DNS…`);
      let narrateCursor = 0;
      let narrating = false;
      liveNarrator = setInterval(() => {
        if (narrating) return;
        const { events, cursor } = scanEvents.getSince(scanId, narrateCursor);
        narrateCursor = cursor;
        const batch = events.filter((e) => e.channel !== "flash"); // never feed Flash its own output
        if (batch.length === 0) return;
        narrating = true;
        narrateLiveBatch(batch, scan.url, userDeepseekKey)
          .then((lines) => { for (const l of lines) emit("flash", l); })
          .catch(() => {})
          .finally(() => { narrating = false; });
      }, 2000);

      // Active diagnostics (HTTP probing, header/secret/SCA/path checks, fuzzing).
      (await db.updateScan(scanId, { status: "scanning" }));
      const diagnostics = await runDiagnostics(scan.url, scan.authHeader, { allowActiveProbes, allowAggressiveProbes, bolaIdentities, loginCredentials, oob: oobCollaborator, scanId, emit });
      if (await isCanceled(scanId)) { console.log(`[Job Worker] Scan ${scanId} was canceled mid-flight — skipping analysis.`); return; }

      // The rich per-injection events are done; stop the live narrator so the
      // analysis phase doesn't rack up extra Flash calls.
      clearInterval(liveNarrator);
      liveNarrator = undefined;
      emit("system", "Diagnostics complete — compiling findings & scoring…");

      // Fast (flash), cheap narration of what the sweep actually found — read
      // by the progress UI in place of scripted filler text.
      narration = narration.concat(await narrateScanning(diagnostics, scan.url, userDeepseekKey));
      (await db.updateScan(scanId, { status: "analyzing", narrationLog: narration }));

      // Compile findings and generate the analysis report.
      const staticCompiled = compileStaticFindings(diagnostics);
      const outputReport = await generateAiReport(scan.url, diagnostics, staticCompiled, userDeepseekKey);
      if (await isCanceled(scanId)) { console.log(`[Job Worker] Scan ${scanId} was canceled mid-flight — discarding the finished report.`); return; }

      // Narrate the score the UI will actually display: every read path
      // (getScanWithSuppressedFindings) recalculates it deterministically
      // from finding severities, which can differ from the AI's own
      // subjective adjustedScore stored below — narrating the raw AI figure
      // would show the user a number that contradicts the report they open next.
      const { score: displayScore, severity: displaySeverity } = recalculateScore(outputReport.findings);
      narration = narration.concat(await narrateAnalysis({ score: displayScore, severity: displaySeverity, findings: outputReport.findings }, scan.url, userDeepseekKey));
      emit("result", `Report compiled — score ${displayScore}/100 (${displaySeverity.toUpperCase()}).`);

      // Best-effort visual capture of the target's landing page (opt-in via
      // ENABLE_TARGET_SCREENSHOT). Returns null — never throws — when disabled,
      // unavailable, or blocked, so it can never fail the scan. Reuses the same
      // auth headers the diagnostics used.
      const evidence = compileScanEvidence(diagnostics);
      const shot = await captureScreenshot(scan.url, {
        "User-Agent": "Seclayer-Security-Scanner/2.0 (+https://seclayerio.ai)",
        ...parseAuthHeader(scan.authHeader),
      });
      if (shot) evidence.screenshot = shot;

      if (await isCanceled(scanId)) { console.log(`[Job Worker] Scan ${scanId} was canceled mid-flight — discarding the finished report.`); return; }
      const completed = (await db.updateScan(scanId, {
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
      }));
      console.log(`[Job Worker] Completed scan ${scanId}`);

      // Fire the user's alert webhook when posture regresses vs the previous
      // scan of this target (non-blocking). Both current and baseline are read
      // through the suppression read-model so a suppressed finding never counts.
      const owner = (await db.getUser(completed.userId));
      const current = (await db.getScanWithSuppressedFindings(completed));
      const prior = (await db.getPreviousCompletedScan(completed.userId, completed.url, completed.id));
      const priorSuppressed = prior ? (await db.getScanWithSuppressedFindings(prior)) : undefined;
      notifyScanComplete(owner?.notifyWebhook, current, priorSuppressed);
    } catch (err: any) {
      console.error(`[Job Worker] FAILED scan ${scanId}:`, err?.message || err);
      if (stream && !await isCanceled(scanId)) stream.emit("system", `Scan failed: ${err?.message || "The scan could not be completed."}`);
      if (await isCanceled(scanId)) return; // don't overwrite the user's cancellation with a failure
      (await db.updateScan(scanId, {
        status: "failed",
        error: err?.message || "The scan could not be completed.",
      }));
    } finally {
      // Always tear down the live ticker plumbing, whatever path we exited on.
      // close() marks the stream closed; getSince keeps serving its buffered
      // tail until the lazy 5-minute eviction, so a poller can drain the end.
      if (liveNarrator) clearInterval(liveNarrator);
      if (stream) stream.close();
    }
  };

  // Public entry point: acquire a scan slot (waiting while over the concurrency
  // cap — the row stays 'queued' until then) and run the job. Same signature and
  // fire-and-forget/awaitable contract as before, so every call site is unchanged.
  return function processScanJob(
    scanId: string,
    allowActiveProbes: boolean,
    bolaIdentities?: [BolaIdentity, BolaIdentity],
    allowAggressiveProbes?: boolean,
    loginCredentials?: LoginCredentials,
  ): Promise<void> {
    return scanSlots.run(() => runScanJob(scanId, allowActiveProbes, bolaIdentities, allowAggressiveProbes, loginCredentials));
  };
}
