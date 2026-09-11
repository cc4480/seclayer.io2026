// Public entry routes: health check, the out-of-band collaborator listener, and
// the passwordless one-time-code auth flow.
import express from "express";
import { db } from "../db.js";
import { config } from "../config.js";
import { deepseekKeyStatus } from "./deepseekKeyStatus.js";
import { rateLimit } from "../rateLimit.js";
import { sendEmail, buildLoginCodeEmail, isEmailConfigured } from "../email.js";
import { LOGIN_CODE_TTL_MS, normalizeLoginCode, normalizeLoginEmail } from "../loginCode.js";
import crypto from "node:crypto";
import { INSTANCE_ID } from "../instance.js";
import { verifyGoogleIdToken } from "../googleAuth.js";
import type { RouteContext } from "./context.js";

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
      // Opaque per-process id, regenerated on every boot. Without it there is no
      // way to tell from outside whether one replica is serving or five: uptime
      // cannot separate replicas that started together. Deliberately random
      // rather than RAILWAY_REPLICA_ID so this leaks no platform detail — it only
      // has to differ between processes.
      instance: INSTANCE_ID,
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

  // --- Auth (one-time emailed code) ---
  //
  // This replaced the magic link outright rather than running alongside it. Two
  // live sign-in paths is twice the surface to keep correct, and the link had
  // two problems codes do not: mail security scanners and prefetchers follow
  // every URL in a message (which forced the check/spend split this file used
  // to carry), and a link only works if the mail is opened on the same device
  // as the browser waiting to sign in.
  //
  // A code is a much weaker secret than the 32-byte token a link carried — a
  // million values, not 2^256. What makes it safe is enforced in
  // server/loginCode.ts and db.verifyLoginCode: lookup scoped to the address,
  // five attempts per code, one live code per address. The limiters below are
  // the outer bound on how fast an attacker can cycle fresh codes to get more
  // guesses.
  const requestLinkLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    keyPrefix: "auth",
    message: "Too many sign-in attempts. Please wait a few minutes and try again.",
  });
  // Second gate on the MAILBOX, not the sender. The IP limiter above stops one
  // client hammering the endpoint, but IP is a weak identity: a caller on CGNAT
  // or mobile egresses from several addresses and gets a fresh allowance from
  // each, so mailbombing one inbox only costs them a few extra source IPs.
  // Bucketing on the normalised address caps how often ANY sender can have a
  // code sent to a given mailbox.
  //
  // It is also what bounds brute force. Each code dies after five wrong
  // guesses, so the only way to get more is to request another one: five codes
  // an hour x five attempts = at most 25 guesses per hour against a
  // million-value keyspace, no matter how many source IPs an attacker has.
  const requestLinkEmailLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    keyPrefix: "auth-email",
    keyFrom: (req) => {
      const raw = (req.body || {}).email;
      return typeof raw === "string" && raw.trim() ? raw.toLowerCase().trim() : undefined;
    },
    message: "Too many sign-in codes have been requested for that address. Please wait a while and try again.",
  });
  // Guess limiter. The per-code attempt cap is the real defence; this stops an
  // attacker spending someone else's five attempts as fast as the network
  // allows, and keeps a scripted client from hammering the endpoint.
  const verifyCodeLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    keyPrefix: "auth-verify",
    message: "Too many code attempts. Please wait a few minutes and try again.",
  });

  app.post("/api/auth/request-code", requestLinkLimiter, requestLinkEmailLimiter, async (req, res) => {
    const { email } = req.body || {};
    if (!email || typeof email !== "string" || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      return res.status(400).json({ status: "error", message: "A valid email address is required." });
    }
    const normEmail = normalizeLoginEmail(email);
    const code = (await db.createLoginCode(normEmail));
    try {
      const mail = buildLoginCodeEmail(code, Math.round(LOGIN_CODE_TTL_MS / 60000));
      await sendEmail({ to: normEmail, subject: mail.subject, html: mail.html, text: mail.text });
    } catch (err: any) {
      console.error("Failed to send sign-in code email:", err?.message || err);
      return res.status(502).json({ status: "error", message: "Could not send the sign-in email. Please try again shortly." });
    }
    // The code is a live credential, so it is ONLY ever returned in the response
    // when there is no real email provider configured AND either we are not in
    // production, or the operator has explicitly opted into running without one
    // (ALLOW_MISSING_EMAIL_PROVIDER — private, single-operator instances only;
    // see config.ts). Any real deployment never exposes it.
    const devCode = !isEmailConfigured() && (!config.isProd || config.allowMissingEmailProvider) ? code : undefined;
    res.json({ status: "ok", message: "If that email is valid, a sign-in code is on its way.", devCode });
  });

  app.post("/api/auth/verify-code", verifyCodeLimiter, async (req, res) => {
    const rawEmail = (req.body || {}).email;
    const code = normalizeLoginCode((req.body || {}).code);
    if (!rawEmail || typeof rawEmail !== "string" || !code) {
      return res.status(400).json({ status: "error", message: "Enter the email address and the 6-digit code." });
    }
    const result = (await db.verifyLoginCode(rawEmail, code));
    if (!result.ok) {
      // ONE message for every failure. Separating "wrong code" from "no code was
      // issued for that address" would turn this into an account-existence
      // oracle, and separating "expired" from "wrong" would tell an attacker
      // whether a guessed value was ever real. The reason is logged, not sent.
      if (result.reason === "too_many_attempts") {
        console.warn("[auth] Sign-in code exhausted its attempts — possible brute force.");
      }
      return res.status(401).json({
        status: "error",
        message: "That code is not valid. Request a new one and try again.",
      });
    }
    const user = (await db.getOrCreateUser(result.email));
    const session = (await db.createSession(user.id));
    res.cookie(sessionCookie, session, cookieOptions);
    res.json({ status: "ok" });
  });

  // Public, pre-auth: the login form has no session yet, so it can't learn the
  // client id from /api/auth/me. Returns null when Google sign-in isn't
  // configured, which is how the client decides not to render the button.
  // The client id is public by design — it ships in every GIS page.
  app.get("/api/auth/providers", (_req, res) => {
    res.json({ googleClientId: config.googleClientId ?? null });
  });

  // "Sign in with Google". Verifies the ID token, then joins the SAME path the
  // magic link ends in — getOrCreateUser + createSession + the session cookie —
  // so both methods produce identical sessions and identity stays keyed on the
  // email address. A Google sign-in with an address that already has a
  // magic-link account therefore lands in that same account rather than
  // creating a duplicate.
  app.post("/api/auth/google", requestLinkLimiter, async (req, res) => {
    if (!config.googleClientId) {
      return res.status(503).json({ status: "error", message: "Google sign-in is not configured on this deployment." });
    }
    const credential = typeof req.body?.credential === "string" ? req.body.credential : "";
    const identity = await verifyGoogleIdToken(credential);
    if (!identity) {
      return res.status(401).json({ status: "error", message: "That Google sign-in could not be verified. Please try again." });
    }
    const user = (await db.getOrCreateUser(identity.email));
    const session = (await db.createSession(user.id));
    res.cookie(sessionCookie, session, cookieOptions);
    res.json({ status: "ok" });
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
