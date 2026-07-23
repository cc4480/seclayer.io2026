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
}
