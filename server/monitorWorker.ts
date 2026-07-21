// Continuous-monitoring worker. On a 60s tick it runs real scheduled scans for
// due monitored targets: re-validates safety, re-checks the credit balance
// (deferring rather than retrying when it can't currently scan), spends a
// credit, and launches the same pipeline as a manual scan — rescheduling on the
// target's real cadence (weekday + time-of-day). Returns the interval handle.
import { db } from "./db.js";
import { computeNextRun } from "./schedule.js";
import { assertScanTargetSafe } from "./scanner.js";
import { extractDomain } from "./domainVerify.js";
import type { ProcessScanJob } from "./routes/context.js";

export function startMonitorWorker(processScanJob: ProcessScanJob): NodeJS.Timeout {
  let monitorTickRunning = false;

  async function runDueMonitoredScans() {
    if (monitorTickRunning) return;
    monitorTickRunning = true;
    try {
      const due = db.listDueMonitoredTargets(new Date().toISOString());
      for (const target of due) {
        // Reschedule on the target's real cadence (weekday + time-of-day), not a
        // fixed now+N days, so the next run lands when the user actually chose.
        const next = computeNextRun(new Date(), {
          frequencyDays: target.frequencyDays,
          hour: target.scanHour,
          minute: target.scanMinute,
          weekday: target.scanWeekday,
        }).toISOString();
        try {
          const user = db.getUser(target.userId);
          if (!user || user.credits < 1) continue; // retry next tick once credits exist
          await assertScanTargetSafe(target.url);
          // Re-checks the balance at the moment of deduction — the credits
          // check above ran before the await, so it could be stale if a
          // manual scan spent the last credit in the meantime.
          if (!db.deductCredits(target.userId, 1)) continue; // retry next tick once credits exist
          const scan = db.createScan(target.userId, target.url);
          db.markMonitoredScanned(target.id, new Date().toISOString(), next);
          const allowActiveProbes = db.isDomainVerified(target.userId, extractDomain(target.url));
          processScanJob(scan.id, allowActiveProbes);
        } catch (err: any) {
          // Invalid/unsafe target: defer instead of retrying every tick.
          db.markMonitoredScanned(target.id, target.lastScannedAt || new Date().toISOString(), next);
          console.warn(`[monitor] Skipped ${target.url}: ${err?.message || err}`);
        }
      }
    } finally {
      monitorTickRunning = false;
    }
  }

  const monitorInterval = setInterval(() => {
    runDueMonitoredScans().catch((e) => console.error("[monitor] tick error:", e));
  }, 60 * 1000);
  monitorInterval.unref();
  return monitorInterval;
}
