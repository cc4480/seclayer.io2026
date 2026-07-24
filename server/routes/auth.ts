// Public entry routes: health check, the out-of-band collaborator listener, and
// the passwordless magic-link auth flow.
import express from "express";
import { db } from "../db.js";
import { config } from "../config.js";
import { deepseekKeyStatus } from "./deepseekKeyStatus.js";
import { rateLimit } from "../rateLimit.js";
import { sendEmail, buildMagicLinkEmail, isEmailConfigured } from "../email.js";
import type { RouteContext } from "./context.js";

export function registerAuthRoutes(app: express.Express, ctx: RouteContext) {
  const { requireAuth, getUserId, cookieOptions, sessionCookie } = ctx;

  app.get("/api/system/health", (req, res) => {
    res.json({ status: "Online", version: "v2.1.2-stable", timestamp: new Date().toISOString() });
  });

  // --- Out-of-band collaborator listener ---
  // Public and unauthenticated by necessity: the SCANNED TARGET (not the user)
  // calls this back when a blind-SSRF/RCE payload we injected fires. Any HTTP
  // method is accepted. recordOobEvent stores a hit only for a token WE issued
  // recently, so this can't be used as an open write-anything store; the token
  // is 48 hex chars of CSPRNG output, so callbacks can't be forged or enumerated.
  // Always returns a flat 200 so it reveals nothing about which tokens are valid.
  app.all("/api/oob/:token", (req, res) => {
    const token = req.params.token || "";
    if (/^[a-f0-9]{16,96}$/i.test(token)) {
      try {
        db.recordOobEvent(token, {
          method: req.method,
          sourceIp: req.ip || req.socket?.remoteAddress || "unknown",
          path: req.originalUrl,
          userAgent: req.get("user-agent") || undefined,
        });
      } catch { /* never let a callback error affect anything */ }
    }
    res.status(200).type("text/plain").send("ok");
  });

  // --- Auth (passwordless magic link) ---
  const requestLinkLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    keyPrefix: "auth",
    message: "Too many sign-in attempts. Please wait a few minutes and try again.",
  });
  app.post("/api/auth/request-link", requestLinkLimiter, async (req, res) => {
    const { email } = req.body || {};
    if (!email || typeof email !== "string" || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      return res.status(400).json({ status: "error", message: "A valid email address is required." });
    }
    const normEmail = email.toLowerCase().trim();
    const token = db.createLoginToken(normEmail);
    // Build the link from a TRUSTED base only. In production APP_URL is required
    // (enforced at boot), so the attacker-controllable Host header is never used
    // for auth links. The request-host fallback is dev-only.
    const base = config.appUrl || `${req.protocol}://${req.get("host")}`;
    const link = `${base}/api/auth/verify?token=${token}`;
    try {
      const mail = buildMagicLinkEmail(link);
      await sendEmail({ to: normEmail, subject: mail.subject, html: mail.html, text: mail.text });
    } catch (err: any) {
      console.error("Failed to send magic link email:", err?.message || err);
      return res.status(502).json({ status: "error", message: "Could not send the sign-in email. Please try again shortly." });
    }
    // The login link contains a live session-granting token, so it is ONLY ever
    // returned in the response for local development (no email provider). In
    // production it is never exposed — it is delivered by email exclusively.
    const devLink = (!config.isProd && !isEmailConfigured()) ? link : undefined;
    res.json({ status: "ok", message: "If that email is valid, a sign-in link is on its way.", devLink });
  });

  app.get("/api/auth/verify", (req, res) => {
    const token = req.query.token as string | undefined;
    const email = token ? db.consumeLoginToken(token) : null;
    if (!email) {
      return res.status(400).send("<h1>Sign-in link invalid or expired</h1><p>Please request a new link from the Seclayer app.</p>");
    }
    const user = db.getOrCreateUser(email);
    const session = db.createSession(user.id);
    res.cookie(sessionCookie, session, cookieOptions);
    res.redirect("/");
  });

  app.post("/api/auth/logout", (req, res) => {
    const token = req.cookies?.[sessionCookie];
    if (token) db.deleteSession(token);
    res.clearCookie(sessionCookie, { ...cookieOptions, maxAge: undefined });
    res.json({ status: "ok", message: "Logged out successfully" });
  });

  app.get("/api/auth/me", requireAuth, (req, res) => {
    const user = db.getUser(getUserId(req));
    if (!user) {
      return res.status(404).json({ status: "error", message: "User profile not found" });
    }
    // freeMode lets the client hide the paywall and credit gating when scans
    // are free (payments not configured / FREE_MODE on). The DeepSeek status
    // lets the client render the bring-your-own-key card without ever seeing
    // the raw key.
    // devSkipDomainVerification (dev-only) lets the launcher unlock the active
    // red-team scan without the DNS/file ownership step; always false in prod.
    res.json({ user, freeMode: config.freeMode, devSkipDomainVerification: config.devSkipDomainVerification, ...deepseekKeyStatus(db.getUserDeepseekKey(user.id)) });
  });
}
