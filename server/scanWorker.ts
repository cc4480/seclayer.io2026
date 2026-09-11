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
import { config, SCANNER_USER_AGENT } from "./config.js";
import type { ProcessScanJob } from "./routes/context.js";
import { INSTANCE_ID } from "./instance.js";

// There is no cancellation token threaded through the probe pipeline (see
// db.cancelScan's doc comment), so a canceled scan's in-flight network work
// still runs to completion — this only stops the worker from writing a stale
// status/result over the user's cancellation once each stage finishes, and
// skips starting the next (most importantly, the AI report call) once a
// cancellation is seen.
async function isCanceled(scanId: string): Promise<boolean> {
  return (await db.getScan(scanId))?.status === "canceled";
}

// Comfortably inside STALE_LEASE_MS (5 min) so a slow tick, a long probe or a
// brief database blip never lets a healthy scan's lease lapse.
// ONE pool of scan slots per process, shared by every path that runs a scan.
//
// This used to live inside makeProcessScanJob, which meant it only governed the
// dashboard/queue path. /api/mcp/scan runs runDiagnostics synchronously in its
// own request handler and so was capped by nothing at all: N concurrent MCP
// requests started N concurrent scans on that instance, which is exactly the
// unbounded burst maxConcurrentScans exists to prevent, and the quickest way to
// OOM a replica and take every other scan on it down too.
//
// Module scope, so both entry points draw from the same slots rather than each
// getting their own allowance.
export const scanSlots = new Semaphore(config.maxConcurrentScans);

const LEASE_REFRESH_MS = 30 * 1000;

// How often an idle worker looks for queued work. Short enough that a scan
// submitted while the fleet is idle starts promptly, long enough that idle
// workers are not hammering the database.
const QUEUE_POLL_MS = 2000;

export function makeProcessScanJob(oobCollaborator?: OobCollaborator) {
  // Cap concurrent in-process scans so a burst can't spawn unbounded
  // runDiagnostics work and exhaust this instance. Shared across every caller
  // (dashboard "scan now", MCP, and the monitoring worker) so none can bypass
  // the cap. Excess scans wait here while their row stays 'queued' — crash-safe,
  // since recoverStuckScans sweeps 'queued' on the next boot.


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
      console.log(`[Job Worker] [${INSTANCE_ID}] Starting scan ${scanId}`);

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
      liveNarrator = setInterval(async () => {
        if (narrating) return;
        // getSince is async now that a feed can live in the shared store; the
        // `narrating` guard above already prevents overlapping passes.
        const { events, cursor } = await scanEvents.getSince(scanId, narrateCursor);
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
        "User-Agent": SCANNER_USER_AGENT,
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
    // Hold a liveness lease for as long as THIS process owns the scan — which
    // starts here, not when the scan begins running: a scan can sit behind the
    // semaphore for a long time, and during that wait it is owned but idle. If
    // the lease only covered execution, another replica booting mid-wait would
    // see a stale lease and fail a scan that is simply queued behind a slot.
    //
    // Recovery treats a lease older than STALE_LEASE_MS as abandoned, so the
    // refresh interval has to be comfortably shorter than that.
    void db.touchScan(scanId).catch(() => {});
    const lease = setInterval(() => {
      // Best effort: a missed refresh is harmless, and a database blip must not
      // take down a scan that is otherwise progressing.
      void db.touchScan(scanId).catch(() => {});
    }, LEASE_REFRESH_MS);
    lease.unref?.();
    return scanSlots
      .run(() => runScanJob(scanId, allowActiveProbes, bolaIdentities, allowAggressiveProbes, loginCredentials))
      .finally(() => clearInterval(lease));
  };
}

// Pull-based scan execution.
//
// Callers used to PUSH: whichever process received the request ran the scan
// itself, gated by a per-process semaphore. That ties throughput to which
// instance a request happened to land on, lets N replicas run N x the cap
// between them, and puts minutes of scan CPU in the same event loop that is
// serving pages.
//
// Workers now PULL instead. A submitted scan is queued, and any worker with a
// free slot claims it. Throughput becomes a dial: add workers. A burst of a
// thousand submissions no longer tries to run a thousand scans — they queue,
// and drain at whatever rate the fleet is sized for.
//
// The claim is atomic and doubles as the lease (see claimNextQueuedScan), so a
// scan is run by exactly one worker and is immediately protected from the
// recovery sweep.
export function startScanQueueWorker(processScanJob: ProcessScanJob): NodeJS.Timeout {
  let inFlight = 0;
  let draining = false;

  const drain = async (): Promise<void> => {
    // One drain pass at a time: overlapping passes would both see free slots
    // and over-claim past the cap.
    if (draining) return;
    draining = true;
    try {
      // ONE claim per tick, not a greedy fill.
      //
      // Claiming until this worker's slots were full meant whichever instance
      // polled first took the whole burst: four scans submitted together went
      // 3/1/0 across three workers, so they ran mostly on one box while two sat
      // idle. Since a scan takes minutes, that is minutes of avoidable latency.
      //
      // Taking one per tick lets the other workers claim before this one comes
      // back. A worker still reaches full capacity, just over a few ticks — a
      // couple of seconds of ramp against jobs measured in minutes, and under a
      // deep queue every worker saturates anyway.
      if (inFlight < config.maxConcurrentScans) {
        // Hesitate in proportion to how loaded this worker already is.
        //
        // Claiming one-per-tick alone did NOT spread a burst: with scans
        // submitted seconds apart, each one goes to whichever worker's timer
        // fires next, so a worker whose phase happens to lead wins every race
        // no matter how much it is already running. Observed twice in
        // production: three scans on one instance, one on another, one idle.
        //
        // An idle worker (inFlight 0) claims immediately and therefore wins;
        // a loaded one waits long enough for an idle peer to take the job
        // first. The jitter stops two equally-loaded workers from lockstepping
        // on the same phase forever. Costs nothing when the queue is deep —
        // the busy worker still claims once no idle peer takes it.
        if (inFlight > 0) {
          await new Promise((r) => setTimeout(r, inFlight * 300 + Math.random() * 200));
        }
        const job = await db.claimNextQueuedScan();
        if (!job) return; // queue empty — wait for the next tick
        // Stamped with the instance so the fleet's behaviour is observable:
        // without it there is no way to tell whether three workers are sharing
        // the queue or one is doing everything.
        console.log(`[scan queue] [${INSTANCE_ID}] claimed ${job.scanId}`);
        inFlight += 1;
        // Not awaited: this worker must stay free to claim again on the next
        // tick while this scan runs, otherwise it would process the queue one
        // scan at a time and maxConcurrentScans would mean nothing.
        // processScanJob keeps the lease refreshed for as long as it holds it.
        // ProcessScanJob is declared as returning void (routes fire and forget)
        // while the implementation returns a promise. Normalise rather than
        // widen a type every route depends on — and the slot MUST be released
        // on both paths, or the worker leaks capacity until it stops claiming.
        void Promise.resolve(processScanJob(job.scanId, job.params.allowActiveProbes, undefined, job.params.allowAggressiveProbes))
          .catch((err: any) => console.error(`[scan queue] job ${job.scanId} failed:`, err?.message || err))
          .finally(() => { inFlight -= 1; });
      }
    } catch (err: any) {
      // A database blip must not kill the loop — the next tick retries.
      console.warn('[scan queue] claim failed:', err?.message || err);
    } finally {
      draining = false;
    }
  };

  console.log(`[scan queue] [${INSTANCE_ID}] Pulling queued scans (up to ${config.maxConcurrentScans} concurrent on this instance).`);
  void drain();
  const timer = setInterval(() => { void drain(); }, QUEUE_POLL_MS);
  timer.unref();
  return timer;
}
