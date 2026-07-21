// Scan lifecycle routes (launch, list, fetch, report) and false-positive
// suppression rules.
import express from "express";
import { db } from "../db.js";
import { rateLimit } from "../rateLimit.js";
import { assertScanTargetSafe } from "../scanner.js";
import { extractDomain } from "../domainVerify.js";
import type { BolaIdentity } from "../../src/types.js";
import type { RouteContext } from "./context.js";

// Validate + normalize a client-supplied two-identity BOLA payload. Returns a
// clean [A, B] tuple, or undefined when the shape is invalid (in which case the
// scan simply runs without the cross-tenant probe). Credentials here are used for
// this run only and never persisted on the scan record.
function sanitizeBolaIdentities(raw: any): [BolaIdentity, BolaIdentity] | undefined {
  if (!Array.isArray(raw) || raw.length !== 2) return undefined;
  const one = (x: any, fallbackLabel: string): BolaIdentity | null => {
    if (!x || typeof x !== "object") return null;
    const authHeader = typeof x.authHeader === "string" ? x.authHeader.trim() : "";
    const ownResource = typeof x.ownResource === "string" ? x.ownResource.trim() : "";
    if (!authHeader || !ownResource) return null;
    const label = typeof x.label === "string" && x.label.trim() ? x.label.trim().slice(0, 40) : fallbackLabel;
    const ownMarker = typeof x.ownMarker === "string" && x.ownMarker.trim() ? x.ownMarker.trim().slice(0, 200) : undefined;
    return { label, authHeader, ownResource, ownMarker };
  };
  const a = one(raw[0], "tenant-A");
  const b = one(raw[1], "tenant-B");
  return a && b ? [a, b] : undefined;
}

export function registerScanRoutes(app: express.Express, ctx: RouteContext) {
  const { requireAuth, getUserId, processScanJob } = ctx;

  const scanLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    keyPrefix: "scan",
    message: "Scan rate limit reached. Please wait a moment before launching more scans.",
  });
  app.post("/api/scans", requireAuth, scanLimiter, async (req, res) => {
    const { url, authHeader } = req.body;
    const userId = getUserId(req);
    if (!url) {
      return res.status(400).json({ status: "error", message: "Target URL is required" });
    }

    // Optional two-identity BOLA/IDOR test. Only meaningful on a verified target
    // (active probes gated below); when the shape is invalid it is simply dropped.
    const bolaIdentities = sanitizeBolaIdentities(req.body.bolaIdentities);

    const user = db.getUser(userId);
    if (!user) {
      return res.status(404).json({ status: "error", message: "User profile not found" });
    }

    if (user.credits < 1) {
      return res.status(402).json({
        status: "error",
        message: "No credits remaining. Please purchase scan credits to continue.",
      });
    }

    // Reject SSRF / malformed targets before spending a credit.
    try {
      await assertScanTargetSafe(url);
    } catch (e: any) {
      return res.status(400).json({ status: "error", message: e?.message || "Target URL cannot be scanned." });
    }

    // Deduct 1 credit. This re-checks the balance at the moment of deduction
    // (deductCredits is a single synchronous read-then-write, so it can't be
    // interleaved by a concurrent request) rather than trusting the earlier
    // check, which ran before the `await` above and so could be stale —
    // without this, two concurrent launches sharing 1 credit could both pass
    // the early check and both get a free scan.
    if (!db.deductCredits(userId, 1)) {
      return res.status(402).json({
        status: "error",
        message: "No credits remaining. Please purchase scan credits to continue.",
      });
    }

    // Create the scan entry in queued state
    const scan = db.createScan(userId, url, authHeader);

    // Active exploit probing runs only when BOTH hold: the caller asked for it
    // (per-scan choice — omitted defaults to true for back-compat), AND this user
    // has verified ownership of the target's domain (see /api/domains/verify/*).
    // Either false → passive recon only. This lets an owner run a passive-only
    // sweep of a domain they've already verified.
    const requestedActive = req.body.activeProbes !== false;
    const allowActiveProbes = requestedActive && db.isDomainVerified(userId, extractDomain(url));

    // Trigger asynchronous background worker flow mimicking the pg-boss worker pipeline
    processScanJob(scan.id, allowActiveProbes, bolaIdentities);

    res.json({ status: "ok", scan });
  });

  app.get("/api/scans", requireAuth, (req, res) => {
    const scansList = db.listScans(getUserId(req)).map((s) => db.getScanWithSuppressedFindings(s));
    res.json({ scans: scansList });
  });

  // User-initiated cancellation. Only valid while the scan is still in
  // flight; the credit is refunded (see db.cancelScan). Does not abort
  // in-flight network probes — see the doc comment on db.cancelScan.
  app.post("/api/scans/:id/cancel", requireAuth, (req, res) => {
    const scan = db.cancelScan(getUserId(req), req.params.id);
    if (!scan) {
      return res.status(409).json({ status: "error", message: "This scan can no longer be canceled — it may already be complete, failed, or not exist." });
    }
    res.json({ status: "ok", scan });
  });

  app.get("/api/scans/:id", requireAuth, (req, res) => {
    let scan = db.getScan(req.params.id);
    // Enforce ownership: a scan ID alone must not grant access to another
    // user's results. Return 404 (not 403) to avoid leaking scan existence.
    if (!scan || scan.userId !== getUserId(req)) {
      return res.status(404).json({ status: "error", message: "Scan not found" });
    }
    scan = db.getScanWithSuppressedFindings(scan);
    res.json({ scan });
  });

  app.get("/api/scans/:id/report", requireAuth, (req, res) => {
    let scan = db.getScan(req.params.id);
    if (!scan || scan.userId !== getUserId(req)) {
      return res.status(404).json({ status: "error", message: "Scan not found" });
    }
    if (scan.status !== "complete") {
      return res.status(400).json({ status: "error", message: "Scan report is not complete yet" });
    }
    scan = db.getScanWithSuppressedFindings(scan);
    res.json({
      scanId: scan.id,
      url: scan.url,
      score: scan.score,
      severity: scan.severity,
      aiSummary: scan.aiSummary,
      aiReasoning: scan.aiReasoning,
      executiveBreakdown: scan.executiveBreakdown,
      evidence: scan.evidence,
      findings: scan.findings,
      createdAt: scan.createdAt,
      completedAt: scan.completedAt,
    });
  });

  // --- False Positive & Suppression Rules ---
  app.get("/api/suppressions", requireAuth, (req, res) => {
    res.json({ suppressions: db.listSuppressions(getUserId(req)) });
  });

  app.post("/api/suppressions", requireAuth, (req, res) => {
    const { targetUrl, findingTitle, reason } = req.body;
    if (!targetUrl || !findingTitle) {
      return res.status(400).json({ error: "targetUrl and findingTitle are required" });
    }
    const rule = db.addSuppression(getUserId(req), targetUrl, findingTitle, reason || "False positive confirmation");
    res.json({ status: "ok", rule });
  });

  app.delete("/api/suppressions/:id", requireAuth, (req, res) => {
    if (!db.removeSuppression(getUserId(req), req.params.id)) {
      return res.status(404).json({ error: "Suppression exclusion rule not found" });
    }
    res.json({ status: "ok" });
  });

  app.post("/api/scans/:scanId/findings/:findingId/suppress", requireAuth, (req, res) => {
    const { scanId, findingId } = req.params;
    const { reason = "Manual enterprise validation" } = req.body;
    const userId = getUserId(req);

    const scan = db.getScan(scanId);
    if (!scan || scan.userId !== userId) {
      return res.status(404).json({ error: "Scan job not resolved" });
    }

    const finding = scan.findings?.find((f) => f.id === findingId);
    if (!finding) {
      return res.status(404).json({ error: "Finding payload not found" });
    }

    const rule = db.addSuppression(userId, scan.url, finding.title, reason);
    res.json({ status: "ok", rule, message: "Finding successfully suppressed and marked as False Positive." });
  });
}
