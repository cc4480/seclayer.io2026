// Network Reconnaissance (nmap) routes — a fully independent scan surface:
// own table, own worker, own gating order. Never touches the scans/findings
// tables or the AppSec posture score.
import express from "express";
import { db } from "../db.js";
import { config } from "../config.js";
import { rateLimit } from "../rateLimit.js";
import { assertScanTargetSafe } from "../ssrf.js";
import { activeProbesUnlocked } from "../activeProbeGate.js";
import { killNmapProcess } from "../nmap/run.js";
import * as scanEvents from "../scanEvents.js";
import type { RouteContext } from "./context.js";

export function registerNmapRoutes(app: express.Express, ctx: RouteContext) {
  const { requireAuth, getUserId, processNmapScanJob, nmapAvailable } = ctx;

  // Same window/max as the AppSec scanLimiter — a full nmap sweep is heavier
  // per launch, but the real backstop against abuse here is the one-in-flight
  // concurrency cap below plus the credit/ownership gates, not this limiter;
  // it only needs to stop a tight retry loop from hammering the route.
  const nmapLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 15,
    keyPrefix: "nmap",
    message: "Network reconnaissance rate limit reached. Please wait a moment before launching more scans.",
  });

  app.post("/api/nmap/scans", requireAuth, nmapLimiter, async (req, res) => {
    if (!nmapAvailable) {
      return res.status(503).json({
        status: "error",
        message: "Network reconnaissance is not available on this deployment.",
      });
    }

    const { url } = req.body;
    const userId = getUserId(req);
    if (!url) {
      return res.status(400).json({ status: "error", message: "Target URL is required" });
    }

    const user = db.getUser(userId);
    if (!user) {
      return res.status(404).json({ status: "error", message: "User profile not found" });
    }

    // SSRF / malformed-target safety, before anything else spends credit or
    // effort. (nmap/resolve.ts runs its own, IP-level equivalent check again
    // inside the worker, immediately before scanning — this early check just
    // fails fast with a friendly message for the common case.)
    try {
      await assertScanTargetSafe(url);
    } catch (e: any) {
      return res.status(400).json({ status: "error", message: e?.message || "Target URL cannot be scanned." });
    }

    // Hard authorization gate — no passive fallback exists for nmap (unlike
    // the AppSec scanner, which can run passive-only against an unverified
    // target), so this is a 403, matching the retest route's identical gate.
    if (!activeProbesUnlocked(userId, url)) {
      return res.status(403).json({
        status: "error",
        message: "Verify ownership of this domain first — network reconnaissance requires proven ownership.",
      });
    }

    // Resource-ceiling guard, not an authorization restriction: at most one
    // in-flight nmap scan per user (see db.hasInFlightNmapScan's doc comment).
    if (db.hasInFlightNmapScan(userId)) {
      return res.status(409).json({
        status: "error",
        message: "You already have a network reconnaissance scan in progress.",
      });
    }

    if (!config.freeMode && user.credits < 1) {
      return res.status(402).json({ status: "error", message: "No credits remaining. Please purchase scan credits to continue." });
    }
    if (!config.freeMode && !db.deductCredits(userId, 1)) {
      return res.status(402).json({ status: "error", message: "No credits remaining. Please purchase scan credits to continue." });
    }

    const scan = db.createNmapScan(userId, url);
    processNmapScanJob(scan.id); // fire-and-forget, mirrors processScanJob
    res.json({ status: "ok", scan });
  });

  app.get("/api/nmap/scans", requireAuth, (req, res) => {
    res.json({ scans: db.listNmapScans(getUserId(req)) });
  });

  app.get("/api/nmap/scans/:id", requireAuth, (req, res) => {
    const scan = db.getNmapScan(req.params.id);
    // 404 (not 403) so a scan id can't be probed for existence — matches
    // /api/scans/:id's identical ownership check.
    if (!scan || scan.userId !== getUserId(req)) {
      return res.status(404).json({ status: "error", message: "Scan not found" });
    }
    res.json({ scan });
  });

  // Live event feed for the progress ticker — identical contract to
  // GET /api/scans/:id/events, reusing the exact same in-memory stream module.
  app.get("/api/nmap/scans/:id/events", requireAuth, (req, res) => {
    const scan = db.getNmapScan(req.params.id);
    if (!scan || scan.userId !== getUserId(req)) {
      return res.status(404).json({ status: "error", message: "Scan not found" });
    }
    const since = Number.parseInt(String(req.query.since ?? "0"), 10);
    const cursor = Number.isFinite(since) && since >= 0 ? since : 0;
    const { events, cursor: nextCursor, found } = scanEvents.getSince(scan.id, cursor);
    res.json({ status: "ok", events, cursor: nextCursor, found, scanStatus: scan.status });
  });

  // User-initiated cancellation. Unlike /api/scans/:id/cancel, this also
  // kills the real OS process (nmap is exactly one killable process, unlike
  // the AppSec scanner's many small in-flight HTTP probes).
  app.post("/api/nmap/scans/:id/cancel", requireAuth, (req, res) => {
    const scan = db.cancelNmapScan(getUserId(req), req.params.id);
    if (!scan) {
      return res.status(409).json({ status: "error", message: "This scan can no longer be canceled — it may already be complete, failed, or not exist." });
    }
    killNmapProcess(scan.id);
    res.json({ status: "ok", scan });
  });
}
