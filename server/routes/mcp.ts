// MCP endpoint: any external agent can call this with an API key to run the full
// diagnostic-and-AI pipeline synchronously and get back the same report quality
// as the dashboard. Active exploit probing only runs once the key's owner has
// verified ownership of the target's domain; otherwise passive recon only.
import express from "express";
import { db } from "../db.js";
import { config } from "../config.js";
import { rateLimit } from "../rateLimit.js";
import { runDiagnostics, compileStaticFindings, compileScanEvidence, assertScanTargetSafe } from "../scanner.js";
import { generateAiReport } from "../deepseek.js";
import { extractDomain } from "../domainVerify.js";
import type { RouteContext } from "./context.js";

export function registerMcpRoutes(app: express.Express, ctx: RouteContext) {
  // Unlike /api/scans (fire-and-forget, backed by the same limiter), this
  // endpoint runs the full diagnostic-and-AI pipeline synchronously in-process
  // per call — with no limit here, a caller could burst enough concurrent
  // heavy scans to exhaust the single Node process and starve every other
  // user's scans, a real availability risk the credit cost alone doesn't stop.
  const mcpLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    keyPrefix: "mcp-scan",
    message: "MCP scan rate limit reached. Please wait a moment before the next call.",
  });
  app.post("/api/mcp/scan", mcpLimiter, async (req, res) => {
    const { url, apiKey, authHeader } = req.body;
    if (!url || !apiKey) {
      return res.status(400).json({ error: "Missing parameters. required: url, apiKey" });
    }

    // Reject SSRF / malformed targets before validating the key or spending a credit.
    try {
      await assertScanTargetSafe(url);
    } catch (e: any) {
      return res.status(400).json({ error: e?.message || "Target URL cannot be scanned." });
    }

    // Verify the key. In free mode scans cost nothing, so we validate the key
    // without deducting; otherwise we deduct 1 credit as part of validation.
    const user = config.freeMode ? db.validateApiKey(apiKey) : db.validateApiKeyAndDeduct(apiKey, 1);
    if (!user) {
      return res.status(401).json({
        error: config.freeMode
          ? "Invalid API Key — an active key is required."
          : "Invalid API Key, active key required, or insufficient credits. Get credits at seclayer.io.",
      });
    }

    // Create the scan record now, before running the pipeline — not just
    // after success. This mirrors the dashboard flow so an MCP scan is (a)
    // visible in scan history immediately, (b) covered by db.recoverStuckScans
    // if the process crashes mid-pipeline, and (c) refundable below if the
    // pipeline throws, rather than the credit silently vanishing with no
    // record of what happened to it.
    const scan = db.createScan(user.id, url, authHeader);
    db.updateScan(scan.id, { status: "scanning" });

    try {
      // Active exploit probing only runs once this key's owner has verified
      // ownership of the target's domain; otherwise passive recon only.
      const allowActiveProbes = db.isDomainVerified(user.id, extractDomain(url));

      // Runs scan diagnostic synchronously for MCP tools context
      const diagnostics = await runDiagnostics(url, authHeader, { allowActiveProbes, oob: ctx.oobCollaborator, scanId: scan.id });
      const staticCompiled = compileStaticFindings(diagnostics);
      // Use the key owner's personal DeepSeek key (BYOK) when set.
      const aiReport = await generateAiReport(url, diagnostics, staticCompiled, db.getUserDeepseekKey(user.id));

      const evidence = compileScanEvidence(diagnostics);
      db.updateScan(scan.id, {
        status: "complete",
        score: aiReport.score,
        severity: aiReport.severity,
        findings: aiReport.findings,
        aiSummary: aiReport.aiSummary,
        aiReasoning: aiReport.aiReasoning,
        executiveBreakdown: aiReport.executiveBreakdown,
        evidence,
        completedAt: new Date().toISOString(),
      });

      res.json({
        success: true,
        targetUrl: url,
        postureScore: aiReport.score,
        vulnerabilityLevel: aiReport.severity,
        analysisSummary: aiReport.aiSummary,
        executiveBreakdown: aiReport.executiveBreakdown,
        securityFindings: aiReport.findings,
        evidence,
        creditsRemaining: user.credits,
      });
    } catch (err: any) {
      // Refund the credit spent on a failed scan — except in free mode, where
      // none was spent, so the balance is reported unchanged.
      const creditsRemaining = config.freeMode ? user.credits : db.addCredits(user.id, 1, "purchase").credits;
      db.updateScan(scan.id, {
        status: "failed",
        error: err?.message || "The scan could not be completed.",
      });
      res.status(500).json({ error: "Internal audit scanning failed", details: err.message, creditsRemaining });
    }
  });

  // --- Read access for agents (no credit cost) ---
  // Retrieval is READ-ONLY: it never runs the pipeline and never spends a
  // credit, so an agent can review results it already paid for (and check scan
  // status/history) without launching a new scan. Authenticated by the same API
  // key as the scan endpoint, accepted in the X-API-Key header or an apiKey
  // query param. Its own lighter limiter (distinct keyPrefix) so cheap reads
  // don't share the heavy scan budget.
  const mcpReadLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    keyPrefix: "mcp-read",
    message: "MCP read rate limit reached. Please wait a moment before the next call.",
  });

  const keyOwner = (req: express.Request) => {
    const key = (req.header("x-api-key") || req.query.apiKey || "").toString().trim();
    return key ? db.validateApiKey(key) : null;
  };

  // List this key owner's recent scans (compact: no findings bodies), newest
  // first — so an agent can find the id of a scan to fetch in full below.
  app.get("/api/mcp/scans", mcpReadLimiter, (req, res) => {
    const user = keyOwner(req);
    if (!user) {
      return res.status(401).json({ error: "Invalid or missing API key. Pass it in the X-API-Key header or the apiKey query parameter." });
    }
    const limit = Math.min(Math.max(Number(req.query.limit) || 20, 1), 100);
    const scans = db.listScans(user.id).slice(0, limit).map((s) => ({
      id: s.id,
      url: s.url,
      status: s.status,
      score: s.score ?? null,
      severity: s.severity ?? null,
      createdAt: s.createdAt,
      completedAt: s.completedAt ?? null,
    }));
    res.json({ success: true, scans });
  });

  // Fetch one completed scan's full report by id — the SAME shape POST
  // /api/mcp/scan returns, so an agent (and the MCP formatter) can consume a
  // retrieved report identically to a freshly-run one. Suppression is applied
  // and the score recalculated via the shared read-model.
  app.get("/api/mcp/scans/:id", mcpReadLimiter, (req, res) => {
    const user = keyOwner(req);
    if (!user) {
      return res.status(401).json({ error: "Invalid or missing API key. Pass it in the X-API-Key header or the apiKey query parameter." });
    }
    const raw = db.getScan(req.params.id);
    // 404 (not 403) when the scan isn't this owner's, so an id can't probe existence.
    if (!raw || raw.userId !== user.id) {
      return res.status(404).json({ error: "Scan not found." });
    }
    if (raw.status !== "complete") {
      return res.status(409).json({ error: `Scan is not complete (status: ${raw.status}). Only completed scans have a report.`, status: raw.status });
    }
    const scan = db.getScanWithSuppressedFindings(raw);
    res.json({
      success: true,
      targetUrl: scan.url,
      postureScore: scan.score,
      vulnerabilityLevel: scan.severity,
      analysisSummary: scan.aiSummary,
      executiveBreakdown: scan.executiveBreakdown,
      securityFindings: scan.findings,
      evidence: scan.evidence,
      createdAt: scan.createdAt,
      completedAt: scan.completedAt,
    });
  });
}
