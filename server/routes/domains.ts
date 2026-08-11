// Domain-ownership verification routes. These gate the scanner's active exploit
// probes (SQLi/XSS/cmd-injection/SSRF/GraphQL/BOLA fuzzing) so the platform
// cannot be used as an anonymous attack proxy against arbitrary third-party
// sites: only a verified owner (DNS TXT / well-known file) unlocks them.
// Passive recon still runs on any target.
import express from "express";
import { db } from "../db.js";
import { assertScanTargetSafe } from "../scanner.js";
import {
  extractDomain, generateVerificationToken, txtRecordName, WELL_KNOWN_PATH,
  checkTxtRecord, checkWellKnownFile,
} from "../domainVerify.js";
import type { RouteContext } from "./context.js";

export function registerDomainRoutes(app: express.Express, ctx: RouteContext) {
  const { requireAuth, getUserId } = ctx;

  app.get("/api/domains", requireAuth, async (req, res) => {
    res.json({ domains: (await db.listDomainVerifications(getUserId(req))) });
  });

  app.post("/api/domains/verify/start", requireAuth, async (req, res) => {
    const { url } = req.body || {};
    if (!url || typeof url !== "string") {
      return res.status(400).json({ status: "error", message: "url is required" });
    }
    try {
      await assertScanTargetSafe(url);
    } catch (e: any) {
      return res.status(400).json({ status: "error", message: e?.message || "Target URL cannot be verified." });
    }
    const domain = extractDomain(url);
    const userId = getUserId(req);
    const existing = (await db.getDomainVerification(userId, domain));
    if (existing?.verified) {
      return res.json({ status: "ok", domain, verified: true });
    }
    const record = (await db.startDomainVerification(userId, domain, existing?.token || generateVerificationToken()));
    res.json({
      status: "ok",
      domain,
      verified: false,
      txtRecord: { name: txtRecordName(domain), value: record.token },
      wellKnownFile: { path: WELL_KNOWN_PATH, content: record.token },
    });
  });

  app.post("/api/domains/verify/check", requireAuth, async (req, res) => {
    const { url } = req.body || {};
    if (!url || typeof url !== "string") {
      return res.status(400).json({ status: "error", message: "url is required" });
    }
    try {
      await assertScanTargetSafe(url);
    } catch (e: any) {
      return res.status(400).json({ status: "error", message: e?.message || "Target URL cannot be verified." });
    }
    const domain = extractDomain(url);
    const userId = getUserId(req);
    const record = (await db.getDomainVerification(userId, domain));
    if (!record) {
      return res.status(400).json({ status: "error", message: "Start verification for this domain first." });
    }
    if (record.verified) {
      return res.json({ status: "ok", domain, verified: true });
    }
    const [txtOk, fileOk] = await Promise.all([
      checkTxtRecord(domain, record.token),
      checkWellKnownFile(domain, record.token),
    ]);
    if (txtOk || fileOk) {
      (await db.markDomainVerified(userId, domain, txtOk ? "dns" : "file"));
      return res.json({ status: "ok", domain, verified: true });
    }
    res.json({ status: "ok", domain, verified: false, message: "Verification not found yet — DNS/file changes can take a few minutes to propagate." });
  });
}
