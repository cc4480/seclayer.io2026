// Public entry routes: health check, the out-of-band collaborator listener, and
// the passwordless magic-link auth flow.
import express from "express";
import { db } from "../db.js";
import { config } from "../config.js";
import { deepseekKeyStatus } from "./deepseekKeyStatus.js";
import { rateLimit } from "../rateLimit.js";
import { sendEmail, buildMagicLinkEmail, isEmailConfigured } from "../email.js";
import type { RouteContext } from "./context.js";

// Minimal server-rendered pages for the magic-link confirmation step. Plain
// HTML on purpose: this runs before any session exists, so it must not depend
// on the SPA bundle loading or on client-side routing.
const PAGE_STYLE =
  "font-family:system-ui,-apple-system,sans-serif;background:#0c0c0e;color:#e4e4e7;" +
  "display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0";

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
}

function expiredLinkPage(): string {
  return (
    '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<meta name="robots" content="noindex"><title>Sign-in link invalid or expired</title></head>' +
    `<body style="${PAGE_STYLE}"><main style="text-align:center;padding:2rem;max-width:26rem">` +
    '<h1 style="font-size:1.25rem;margin:0 0 .5rem">Sign-in link invalid or expired</h1>' +
    '<p style="color:#a1a1aa;font-size:.875rem;margin:0 0 1.25rem">Sign-in links can be used once and expire after 15 minutes. Please request a new one.</p>' +
    '<a href="/" style="color:#22c55e;font-size:.875rem">Back to Seclayer</a>' +
    "</main></body></html>"
  );
}

// The token rides in a hidden field and is spent only when this form is
// submitted, so a scanner's GET leaves it unused.
function confirmSignInPage(token: string, email: string): string {
  return (
    '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<meta name="robots" content="noindex"><title>Confirm sign-in</title></head>' +
    `<body style="${PAGE_STYLE}"><main style="text-align:center;padding:2rem;max-width:26rem">` +
    '<h1 style="font-size:1.25rem;margin:0 0 .5rem">Confirm sign-in</h1>' +
    `<p style="color:#a1a1aa;font-size:.875rem;margin:0 0 1.5rem">Continue as <strong style="color:#e4e4e7">${escapeHtml(email)}</strong>.</p>` +
    '<form method="POST" action="/api/auth/verify">' +
    `<input type="hidden" name="token" value="${escapeHtml(token)}">` +
    '<button type="submit" style="background:#22c55e;color:#000;border:0;border-radius:.375rem;' +
    'padding:.75rem 1.75rem;font-size:.875rem;font-weight:600;cursor:pointer">Sign in to Seclayer</button>' +
    "</form>" +
    '<p style="color:#52525b;font-size:.75rem;margin:1.5rem 0 0">This link can be used once and expires 15 minutes after it was sent.</p>' +
    "</main></body></html>"
  );
}

export function registerAuthRoutes(app: express.Express, ctx: RouteContext) {
  const { requireAuth, getUserId, cookieOptions, sessionCookie, nmapAvailable } = ctx;

  // Liveness + readiness probe. Actually pings the datastore rather than
  // reporting a hardcoded "Online", so an orchestrator (or the Docker
  // HEALTHCHECK) can detect a process that is up but has lost its database and
  // pull it out of rotation. Returns 503 when the DB is unreachable.
  app.get("/api/system/health", async (req, res) => {
    const dbOk = (await db.healthy());
    res.status(dbOk ? 200 : 503).json({
      status: dbOk ? "Online" : "Degraded",
      version: config.appVersion,
      checks: { database: dbOk ? "ok" : "error" },
      uptimeSeconds: Math.round(process.uptime()),
      timestamp: new Date().toISOString(),
    });
  });

  // --- Out-of-band collaborator listener ---
  // Public and unauthenticated by necessity: the SCANNED TARGET (not the user)
  // calls this back when a blind-SSRF/RCE payload we injected fires. Any HTTP
  // method is accepted. recordOobEvent stores a hit only for a token WE issued
  // recently, so this can't be used as an open write-anything store; the token
  // is 48 hex chars of CSPRNG output, so callbacks can't be forged or enumerated.
  // Always returns a flat 200 so it reveals nothing about which tokens are valid.
  app.all("/api/oob/:token", async (req, res) => {
    const token = req.params.token || "";
    if (/^[a-f0-9]{16,96}$/i.test(token)) {
      try {
        (await db.recordOobEvent(token, {
          method: req.method,
          sourceIp: req.ip || req.socket?.remoteAddress || "unknown",
          path: req.originalUrl,
          userAgent: req.get("user-agent") || undefined,
        }));
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
    const token = (await db.createLoginToken(normEmail));
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
    // returned in the response when there's no real email provider configured
    // AND either we're not in production, or the operator has explicitly opted
    // into running without one (ALLOW_MISSING_EMAIL_PROVIDER — private,
    // single-operator instances only, e.g. local Docker testing; see
    // config.ts). Any real deployment with an email provider configured never
    // exposes it — it is delivered by email exclusively.
    const devLink = !isEmailConfigured() && (!config.isProd || config.allowMissingEmailProvider) ? link : undefined;
    res.json({ status: "ok", message: "If that email is valid, a sign-in link is on its way.", devLink });
  });

  // Opening the emailed link only CHECKS the token — it never spends it. Mail
  // security scanners and link prefetchers fetch every URL in a message
  // automatically (production logs showed ~8 datacenter IPs hitting this within
  // milliseconds of delivery), so burning the single use here meant a scanner
  // always redeemed the token first and the human's click failed as "invalid or
  // expired". The redemption is the POST below, which automated fetchers don't
  // issue. Same token, same 15-minute single-use guarantee — only the step that
  // spends it moved.
  app.get("/api/auth/verify", async (req, res) => {
    const token = req.query.token as string | undefined;
    const email = token ? (await db.peekLoginToken(token)) : null;
    if (!email) {
      return res.status(400).send(expiredLinkPage());
    }
    res.type("html").send(confirmSignInPage(token!, email));
  });

  // Redeems the token. Only reached by submitting the confirmation form above.
  app.post("/api/auth/verify", async (req, res) => {
    const token = (req.body?.token ?? req.query.token) as string | undefined;
    const email = token ? (await db.consumeLoginToken(token)) : null;
    if (!email) {
      return res.status(400).send(expiredLinkPage());
    }
    const user = (await db.getOrCreateUser(email));
    const session = (await db.createSession(user.id));
    res.cookie(sessionCookie, session, cookieOptions);
    res.redirect("/");
  });

  app.post("/api/auth/logout", async (req, res) => {
    const token = req.cookies?.[sessionCookie];
    if (token) (await db.deleteSession(token));
    res.clearCookie(sessionCookie, { ...cookieOptions, maxAge: undefined });
    res.json({ status: "ok", message: "Logged out successfully" });
  });

  app.get("/api/auth/me", requireAuth, async (req, res) => {
    const user = (await db.getUser(getUserId(req)));
    if (!user) {
      return res.status(404).json({ status: "error", message: "User profile not found" });
    }
    // freeMode lets the client hide the paywall and credit gating when scans
    // are free (payments not configured / FREE_MODE on). The DeepSeek status
    // lets the client render the bring-your-own-key card without ever seeing
    // the raw key.
    // Whether active probes are unlocked on THIS instance without per-domain
    // verification — either the dev flag (non-prod) or the operator flag
    // (ALLOW_UNVERIFIED_ACTIVE_PROBES, any env). The client uses this one signal
    // to enable the active-scan UI; kept under the existing field name so nothing
    // downstream has to change.
    const activeProbesUnlocked = config.devSkipDomainVerification || config.allowUnverifiedActiveProbes;
    res.json({
      user,
      freeMode: config.freeMode,
      devSkipDomainVerification: activeProbesUnlocked,
      // Network Reconnaissance (nmap) is only ever present in the self-hosted
      // Docker image — this tells the client whether to render the feature at
      // all, so it stays cleanly absent (not erroring) everywhere else.
      nmapAvailable,
      ...deepseekKeyStatus((await db.getUserDeepseekKey(user.id))),
    });
  });
}
