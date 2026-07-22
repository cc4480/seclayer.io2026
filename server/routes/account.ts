// Account-scoped routes: continuous-monitoring targets, the Slack-compatible
// alert webhook, credit balance + Stripe checkout, and developer API keys.
import express from "express";
import { db, cleanUrl } from "../db.js";
import { config } from "../config.js";
import { assertScanTargetSafe } from "../scanner.js";
import { createCheckoutSession, isStripeConfigured } from "../stripe.js";
import type { RouteContext } from "./context.js";

export function registerAccountRoutes(app: express.Express, ctx: RouteContext) {
  const { requireAuth, getUserId } = ctx;

  // --- Continuous Monitoring ---
  app.get("/api/monitoring", requireAuth, (req, res) => {
    res.json({ monitoredTargets: db.listMonitoredTargets(getUserId(req)) });
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
