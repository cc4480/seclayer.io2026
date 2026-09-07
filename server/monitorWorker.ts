// Continuous-monitoring worker. On a 60s tick it runs real scheduled scans for
// due monitored targets: re-validates safety, re-checks the credit balance
// (deferring rather than retrying when it can't currently scan), spends a
// credit, and launches the same pipeline as a manual scan — rescheduling on the
// target's real cadence (weekday + time-of-day). Returns the interval handle.
import { db } from "./db.js";
import { config } from "./config.js";
import { computeNextRun } from "./schedule.js";
import { assertScanTargetSafe } from "./scanner.js";
import { activeProbesUnlocked } from "./activeProbeGate.js";
import type { ProcessScanJob } from "./routes/context.js";

let monitorTickRunning = false;

// Exported (rather than trapped in the setInterval closure below) so tests
// can drive a single tick directly instead of waiting on a real 60s timer.
// How long a tick lease survives an instance dying mid-tick. Only matters for
// crash recovery — a healthy tick releases the lease as soon as it finishes.
const MONITOR_LEASE_MS = 5 * 60 * 1000;

export async function runDueMonitoredScans(processScanJob: ProcessScanJob): Promise<void> {
  if (monitorTickRunning) return;
  monitorTickRunning = true;
  try {
    const due = (await db.listDueMonitoredTargets(new Date().toISOString()));
    for (const target of due) {
      // Reschedule on the target's real cadence (weekday + time-of-day), not a
      // fixed now+N days, so the next run lands when the user actually chose.
      const next = computeNextRun(new Date(), {
        frequencyDays: target.frequencyDays,
        hour: target.scanHour,
        minute: target.scanMinute,
        weekday: target.scanWeekday,
      }).toISOString();
      // Only one instance may process this target. monitorTickRunning above
      // serialises ticks within a process; each replica has its own copy of it,
      // so without this all three see the same due target and launch the same
      // scan — three times the credits and three times the load on the target.
      //
      // The lease is separate from nextRun and released in the finally below, so
      // every scheduling decision this loop makes is exactly as it was: a target
      // skipped for want of credits keeps its due time and is retried on the
      // next tick, rather than being silently rescheduled by the act of claiming.
      if (!(await db.claimMonitoredTick(target.id, new Date(Date.now() - MONITOR_LEASE_MS).toISOString(), new Date().toISOString()))) {
        continue; // another instance is processing this one
      }
      try {
        const user = (await db.getUser(target.userId));
        if (!user) {
          (await db.markMonitoredError(target.id, "Skipped: the owning account no longer exists."));
          continue;
        }
        // In free mode scans cost nothing; the credit gate is skipped entirely.
        if (!config.freeMode && user.credits < 1) {
          // Retry next tick once credits exist — scheduling is untouched,
          // but the reason is recorded so the dashboard doesn't just show
          // a silent "ACTIVE" monitor that never actually scans anything.
          (await db.markMonitoredError(target.id, "Skipped: insufficient credits. Will retry automatically once the balance is topped up."));
          continue;
        }
        await assertScanTargetSafe(target.url);
        // Re-checks the balance at the moment of deduction — the credits
        // check above ran before the await, so it could be stale if a
        // manual scan spent the last credit in the meantime. Skipped in free mode.
        if (!config.freeMode && !(await db.deductCredits(target.userId, 1))) {
          (await db.markMonitoredError(target.id, "Skipped: insufficient credits. Will retry automatically once the balance is topped up."));
          continue;
        }
        const scan = (await db.createScan(target.userId, target.url));
        (await db.markMonitoredScanned(target.id, new Date().toISOString(), next));
        const allowActiveProbes = await activeProbesUnlocked(target.userId, target.url);
        processScanJob(scan.id, allowActiveProbes);
      } catch (err: any) {
        // Invalid/unsafe target: defer instead of retrying every tick.
        const message = err?.message || "This target could not be scanned (invalid or unsafe URL).";
        (await db.markMonitoredSkipped(target.id, next, message));
        console.warn(`[monitor] Skipped ${target.url}: ${message}`);
      } finally {
        // Release immediately: the lease exists to stop CONCURRENT instances,
        // not to change how often a target is looked at. Holding it until it
        // expired would suppress the retry-next-tick behaviour above.
        await db.releaseMonitoredTick(target.id);
      }
    }
  } finally {
    monitorTickRunning = false;
  }
}

export function startMonitorWorker(processScanJob: ProcessScanJob): NodeJS.Timeout {
  const monitorInterval = setInterval(() => {
    runDueMonitoredScans(processScanJob).catch((e) => console.error("[monitor] tick error:", e));
  }, 60 * 1000);
  monitorInterval.unref();
  return monitorInterval;
}
