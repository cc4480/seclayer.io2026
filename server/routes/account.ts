// Account-scoped routes: continuous-monitoring targets, the Slack-compatible
// alert webhook, credit balance + Stripe checkout, and developer API keys.
import express from "express";
import { db, cleanUrl } from "../db.js";
import { config } from "../config.js";
import { deepseekKeyStatus } from "./deepseekKeyStatus.js";
import { assertScanTargetSafe } from "../scanner.js";
import { computeNextRun } from "../schedule.js";
import { extractDomain } from "../domainVerify.js";
import { createCheckoutSession, isStripeConfigured } from "../stripe.js";
import type { RouteContext } from "./context.js";

export function registerAccountRoutes(app: express.Express, ctx: RouteContext) {
  const { requireAuth, getUserId, processScanJob } = ctx;

  // The next automated run for a target, from its own cadence — used by
  // "scan now" to reset the countdown after a manual run.
  const nextRunFor = (t: { frequencyDays: number; scanHour?: number | null; scanMinute?: number | null; scanWeekday?: number | null }) =>
    computeNextRun(new Date(), {
      frequencyDays: t.frequencyDays,
      hour: t.scanHour,
      minute: t.scanMinute,
      weekday: t.scanWeekday,
    }).toISOString();

  // --- Continuous Monitoring ---
  // Each target is enriched with its most recent scan (any status) so the
  // dashboard can show the last result and link straight to that report.
  app.get("/api/monitoring", requireAuth, (req, res) => {
    const userId = getUserId(req);
    const monitoredTargets = db.listMonitoredTargets(userId).map((t) => {
      const last = db.getLatestScanForUrl(userId, t.url);
      return {
        ...t,
        lastScan: last
          ? {
              id: last.id,
              status: last.status,
              score: last.score,
              severity: last.severity,
              createdAt: last.createdAt,
              completedAt: last.completedAt,
            }
          : null,
      };
    });
    res.json({ monitoredTargets });
  });

  app.post("/api/monitoring", requireAuth, async (req, res) => {
    const { url, frequencyDays = 7, hour, minute, weekday } = req.body || {};
    if (!url || typeof url !== "string") {
      return res.status(400).json({ error: "url is required" });
    }

    // Reject SSRF/malformed targets up front — every other endpoint that
    // accepts a URL (scans, MCP, domain verification, the alert webhook)
    // validates at the moment it's supplied, not only once a scan attempt
    // eventually happens. Without this, a bad or unsafe target was silently
    // accepted and would just fail forever on every tick with only a
    // server-side log line, no feedback to the user.
    try {
      await assertScanTargetSafe(url);
    } catch (e: any) {
      return res.status(400).json({ error: e?.message || "Target URL cannot be monitored." });
    }

    const userId = getUserId(req);
    const normalized = cleanUrl(url);
    if (db.listMonitoredTargets(userId).some((t) => cleanUrl(t.url) === normalized)) {
      return res.status(409).json({ error: "This URL is already being monitored." });
    }

    const target = db.addMonitoredTarget(userId, url, {
      frequencyDays: Number(frequencyDays) || 7,
      hour: hour == null || hour === "" ? null : Number(hour),
      minute: minute == null || minute === "" ? null : Number(minute),
      weekday: weekday == null || weekday === "" ? null : Number(weekday),
    });
    res.json({ status: "ok", target });
  });

  // Pause/resume a monitor. Paused targets keep their configuration but are
  // never picked up by the worker (see db.listDueMonitoredTargets).
  app.patch("/api/monitoring/:id", requireAuth, (req, res) => {
    const { paused } = req.body || {};
    if (typeof paused !== "boolean") {
      return res.status(400).json({ error: "paused (boolean) is required" });
    }
    if (!db.setMonitoredPaused(getUserId(req), req.params.id, paused)) {
      return res.status(404).json({ error: "Monitored target not found" });
    }
    res.json({ status: "ok", paused });
  });

  // Run a monitored target's scan immediately, on demand — the same launch path
  // the worker uses (credit check + deduct, SSRF re-validation, active-probe
  // gating), then reset the countdown to the next automated run so an on-demand
  // scan doesn't cause an immediate duplicate on the next tick.
  app.post("/api/monitoring/:id/scan-now", requireAuth, async (req, res) => {
    const userId = getUserId(req);
    const target = db.getMonitoredTarget(userId, req.params.id);
    if (!target) {
      return res.status(404).json({ error: "Monitored target not found" });
    }

    const user = db.getUser(userId);
    if (!user) {
      return res.status(404).json({ error: "User profile not found" });
    }
    // In free mode scans cost nothing; the credit gate is skipped entirely.
    if (!config.freeMode && user.credits < 1) {
      return res.status(402).json({ error: "No credits remaining. Please purchase scan credits to run a scan." });
    }

    try {
      await assertScanTargetSafe(target.url);
    } catch (e: any) {
      return res.status(400).json({ error: e?.message || "This target cannot be scanned." });
    }

    // Re-check the balance at the moment of deduction (single synchronous
    // read-then-write) so a concurrent launch can't share one credit. Skipped
    // in free mode.
    if (!config.freeMode && !db.deductCredits(userId, 1)) {
      return res.status(402).json({ error: "No credits remaining. Please purchase scan credits to run a scan." });
    }

    const scan = db.createScan(userId, target.url);
    db.markMonitoredScanned(target.id, new Date().toISOString(), nextRunFor(target));
    const allowActiveProbes = db.isDomainVerified(userId, extractDomain(target.url));
    processScanJob(scan.id, allowActiveProbes);
    res.json({ status: "ok", scan });
  });

  app.delete("/api/monitoring/:id", requireAuth, (req, res) => {
    if (!db.removeMonitoredTarget(getUserId(req), req.params.id)) {
      return res.status(404).json({ error: "Monitored target not found" });
    }
    res.json({ status: "ok" });
  });

  // --- Alert webhook (Slack-compatible) ---
  app.put("/api/user/webhook", requireAuth, async (req, res) => {
    const { url } = req.body || {};
    if (url) {
      if (typeof url !== "string") {
        return res.status(400).json({ status: "error", message: "Webhook must be an http(s) URL, or empty to disable." });
      }
      // Block internal/reserved destinations (SSRF) at set time; delivery is
      // re-validated as well in case DNS changes later.
      try {
        await assertScanTargetSafe(url.trim());
      } catch {
        return res.status(400).json({ status: "error", message: "Webhook must be a public http(s) URL (internal/reserved addresses are not allowed)." });
      }
    }
    const user = db.setUserWebhook(getUserId(req), url ? url.trim() : null);
    res.json({ status: "ok", notifyWebhook: user?.notifyWebhook ?? null });
  });

  // --- Personal DeepSeek API key (bring-your-own-key) ---
  // Lets a user supply their own DeepSeek key so their scans get full AI reports
  // even when the server has no global key (e.g. free mode). Send an empty/null
  // key to clear it. The raw key is never returned — only a set/preview status.
  app.put("/api/user/deepseek-key", requireAuth, (req, res) => {
    const { key } = req.body || {};
    if (key != null && typeof key !== "string") {
      return res.status(400).json({ status: "error", message: "key must be a string, or empty to remove." });
    }
    const trimmed = typeof key === "string" ? key.trim() : "";
    if (trimmed && (trimmed.length < 20 || /\s/.test(trimmed))) {
      return res.status(400).json({ status: "error", message: "That doesn't look like a valid DeepSeek API key (it should start with 'sk-' and contain no spaces)." });
    }
    const userId = getUserId(req);
    db.setUserDeepseekKey(userId, trimmed || null);
    res.json({ status: "ok", ...deepseekKeyStatus(db.getUserDeepseekKey(userId)) });
  });

  // --- Credits ---
  app.get("/api/credits", requireAuth, (req, res) => {
    const userId = getUserId(req);
    const user = db.getUser(userId);
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({ credits: user.credits, transactions: db.listTransactions(userId) });
  });

  // Real Stripe Checkout. Returns a hosted checkout URL; credits are granted by
  // the verified webhook after payment, never here.
  app.post("/api/credits/checkout", requireAuth, async (req, res) => {
    if (!isStripeConfigured()) {
      return res.status(503).json({ status: "error", message: "Payments are not currently available. Please contact support." });
    }
    const { pack } = req.body;
    // Trusted base only (APP_URL enforced in production); dev falls back to host.
    const base = config.appUrl || `${req.protocol}://${req.get("host")}`;
    try {
      const url = await createCheckoutSession(getUserId(req), pack, base);
      res.json({ status: "ok", url });
    } catch (err: any) {
      const msg = err?.message || "Could not start checkout.";
      const code = /invalid credit pack/i.test(msg) ? 400 : 502;
      res.status(code).json({ status: "error", message: msg });
    }
  });

  // API Key routes for developer MCP usecases
  app.get("/api/keys", requireAuth, (req, res) => {
    res.json({ keys: db.listApiKeys(getUserId(req)) });
  });

  // The raw key is returned ONLY in this response — it is never stored and
  // will never be shown again. The client must copy it now.
  app.post("/api/keys", requireAuth, (req, res) => {
    const { apiKey, rawKey } = db.generateApiKey(getUserId(req));
    res.json({ status: "ok", key: apiKey, rawKey });
  });

  app.delete("/api/keys/:id", requireAuth, (req, res) => {
    if (!db.revokeApiKey(getUserId(req), req.params.id)) {
      return res.status(404).json({ status: "error", message: "Key not found or could not be revoked" });
    }
    res.json({ status: "ok" });
  });
}
