import './server/env.js'; // must run first: loads .env before any module reads process.env
import express from 'express';
import path from 'path';
import cookieParser from 'cookie-parser';
import { createServer as createViteServer } from 'vite';
import { db, recalculateScore } from './server/db.js';
import { runDiagnostics, compileStaticFindings, compileScanEvidence, assertScanTargetSafe, parseAuthHeader } from './server/scanner.js';
import { captureScreenshot } from './server/render.js';
import { generateAiReport } from './server/deepseek.js';
import { narrateScanning, narrateAnalysis } from './server/narrate.js';
import { sendEmail, buildMagicLinkEmail, isEmailConfigured } from './server/email.js';
import { config, validateConfigOnBoot } from './server/config.js';
import { rateLimit } from './server/rateLimit.js';
import { createCheckoutSession, parseWebhookEvent, isStripeConfigured } from './server/stripe.js';
import { notifyScanComplete } from './server/notify.js';
import { extractDomain, generateVerificationToken, txtRecordName, WELL_KNOWN_PATH, checkTxtRecord, checkWellKnownFile } from './server/domainVerify.js';

async function startServer() {
  if (!validateConfigOnBoot() && config.isProd) {
    console.error('[config] Refusing to start: production-critical configuration is missing (see warnings above).');
    process.exit(1);
  }

  const app = express();
  const PORT = config.port;

  // Behind a proxy/load balancer in production so req.protocol, req.ip and
  // Secure cookies are derived from the X-Forwarded-* headers.
  if (config.isProd) app.set('trust proxy', 1);

  // Baseline security headers on every response (including API + errors).
  app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    if (config.isProd) {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    }
    next();
  });

  // Stripe webhook MUST receive the raw body for signature verification, so it
  // is registered before the JSON body parser. Credits are granted only here,
  // on a verified, paid checkout.session.completed event.
  app.post('/api/webhooks/stripe', express.raw({ type: 'application/json' }), (req, res) => {
    let completion;
    try {
      completion = parseWebhookEvent(req.body as Buffer, req.headers['stripe-signature'] as string | undefined);
    } catch (err: any) {
      console.warn('[stripe] Webhook verification failed:', err?.message || err);
      return res.status(400).json({ error: `Webhook Error: ${err?.message || 'invalid signature'}` });
    }
    if (completion && !db.hasTransactionForSession(completion.sessionId)) {
      const user = db.getUser(completion.userId);
      if (user) {
        db.addCredits(user.id, completion.credits, 'purchase', completion.sessionId);
        console.log(`[stripe] Granted ${completion.credits} credits to ${user.id} (session ${completion.sessionId}).`);
      }
    }
    res.json({ received: true });
  });

  // Body parsers + cookies (explicit body size cap)
  app.use(express.json({ limit: '256kb' }));
  app.use(express.urlencoded({ extended: true, limit: '256kb' }));
  app.use(cookieParser());

  const SESSION_COOKIE = 'sl_session';
  const isProd = process.env.NODE_ENV === 'production';
  const cookieOptions = {
    httpOnly: true,
    secure: isProd,
    sameSite: 'lax' as const,
    path: '/',
    maxAge: 30 * 24 * 60 * 60 * 1000,
  };

  // Resolve the session cookie to a userId for every request. Identity is
  // derived server-side from the signed session — never from client input.
  app.use((req, res, next) => {
    const token = req.cookies?.[SESSION_COOKIE];
    if (token) {
      const userId = db.getSessionUserId(token);
      if (userId) (req as any).userId = userId;
    }
    // Dev convenience (config.devSkipAuth, never true in production): skip the
    // magic-link flow entirely by treating every unauthenticated request as a
    // fixed local dev account, so the app is usable immediately while building.
    if (!(req as any).userId && config.devSkipAuth) {
      (req as any).userId = db.getOrCreateUser('dev@localhost').id;
    }
    next();
  });

  function requireAuth(req: express.Request, res: express.Response, next: express.NextFunction) {
    if (!(req as any).userId) {
      return res.status(401).json({ status: 'error', message: 'Authentication required' });
    }
    next();
  }
  const getUserId = (req: express.Request): string => (req as any).userId;

  // --- API ROUTES ---

  app.get('/api/system/health', (req, res) => {
    res.json({
      status: 'Online',
      version: 'v2.1.2-stable',
      timestamp: new Date().toISOString()
    });
  });

  // --- Auth (passwordless magic link) ---
  const requestLinkLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    keyPrefix: 'auth',
    message: 'Too many sign-in attempts. Please wait a few minutes and try again.',
  });
  app.post('/api/auth/request-link', requestLinkLimiter, async (req, res) => {
    const { email } = req.body || {};
    if (!email || typeof email !== 'string' || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      return res.status(400).json({ status: 'error', message: 'A valid email address is required.' });
    }
    const normEmail = email.toLowerCase().trim();
    const token = db.createLoginToken(normEmail);
    // Build the link from a TRUSTED base only. In production APP_URL is required
    // (enforced at boot), so the attacker-controllable Host header is never used
    // for auth links. The request-host fallback is dev-only.
    const base = config.appUrl || `${req.protocol}://${req.get('host')}`;
    const link = `${base}/api/auth/verify?token=${token}`;
    try {
      const mail = buildMagicLinkEmail(link);
      await sendEmail({ to: normEmail, subject: mail.subject, html: mail.html, text: mail.text });
    } catch (err: any) {
      console.error('Failed to send magic link email:', err?.message || err);
      return res.status(502).json({ status: 'error', message: 'Could not send the sign-in email. Please try again shortly.' });
    }
    // The login link contains a live session-granting token, so it is ONLY ever
    // returned in the response for local development (no email provider). In
    // production it is never exposed — it is delivered by email exclusively.
    const devLink = (!config.isProd && !isEmailConfigured()) ? link : undefined;
    res.json({ status: 'ok', message: 'If that email is valid, a sign-in link is on its way.', devLink });
  });

  app.get('/api/auth/verify', (req, res) => {
    const token = req.query.token as string | undefined;
    const email = token ? db.consumeLoginToken(token) : null;
    if (!email) {
      return res.status(400).send('<h1>Sign-in link invalid or expired</h1><p>Please request a new link from the Seclayer app.</p>');
    }
    const user = db.getOrCreateUser(email);
    const session = db.createSession(user.id);
    res.cookie(SESSION_COOKIE, session, cookieOptions);
    res.redirect('/');
  });

  app.post('/api/auth/logout', (req, res) => {
    const token = req.cookies?.[SESSION_COOKIE];
    if (token) db.deleteSession(token);
    res.clearCookie(SESSION_COOKIE, { ...cookieOptions, maxAge: undefined });
    res.json({ status: 'ok', message: 'Logged out successfully' });
  });

  app.get('/api/auth/me', requireAuth, (req, res) => {
    const user = db.getUser(getUserId(req));
    if (!user) {
      return res.status(404).json({ status: 'error', message: 'User profile not found' });
    }
    res.json({ user });
  });

  // Scan Routes
  const scanLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    keyPrefix: 'scan',
    message: 'Scan rate limit reached. Please wait a moment before launching more scans.',
  });
  app.post('/api/scans', requireAuth, scanLimiter, async (req, res) => {
    const { url, authHeader } = req.body;
    const userId = getUserId(req);
    if (!url) {
      return res.status(400).json({ status: 'error', message: 'Target URL is required' });
    }

    const user = db.getUser(userId);
    if (!user) {
      return res.status(404).json({ status: 'error', message: 'User profile not found' });
    }

    if (user.credits < 1) {
      return res.status(402).json({
        status: 'error',
        message: 'No credits remaining. Please purchase scan credits to continue.'
      });
    }

    // Reject SSRF / malformed targets before spending a credit.
    try {
      await assertScanTargetSafe(url);
    } catch (e: any) {
      return res.status(400).json({ status: 'error', message: e?.message || 'Target URL cannot be scanned.' });
    }

    // Deduct 1 credit
    db.deductCredits(userId, 1);

    // Create the scan entry in queued state
    const scan = db.createScan(userId, url, authHeader);

    // Active exploit probing only runs once this user has verified ownership
    // of the target's domain (see /api/domains/verify/*); otherwise the scan
    // still runs, but with passive recon only.
    const allowActiveProbes = db.isDomainVerified(userId, extractDomain(url));

    // Trigger asynchronous background worker flow mimicking the pg-boss worker pipeline
    processScanJob(scan.id, allowActiveProbes);

    res.json({ status: 'ok', scan });
  });

  app.get('/api/scans', requireAuth, (req, res) => {
    const scansList = db.listScans(getUserId(req)).map(s => db.getScanWithSuppressedFindings(s));
    res.json({ scans: scansList });
  });

  app.get('/api/scans/:id', requireAuth, (req, res) => {
    let scan = db.getScan(req.params.id);
    // Enforce ownership: a scan ID alone must not grant access to another
    // user's results. Return 404 (not 403) to avoid leaking scan existence.
    if (!scan || scan.userId !== getUserId(req)) {
      return res.status(404).json({ status: 'error', message: 'Scan not found' });
    }
    scan = db.getScanWithSuppressedFindings(scan);
    res.json({ scan });
  });

  app.get('/api/scans/:id/report', requireAuth, (req, res) => {
    let scan = db.getScan(req.params.id);
    if (!scan || scan.userId !== getUserId(req)) {
      return res.status(404).json({ status: 'error', message: 'Scan not found' });
    }
    if (scan.status !== 'complete') {
      return res.status(400).json({ status: 'error', message: 'Scan report is not complete yet' });
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
      completedAt: scan.completedAt
    });
  });

  // --- False Positive & Suppression Rules ---
  app.get('/api/suppressions', requireAuth, (req, res) => {
    res.json({ suppressions: db.listSuppressions(getUserId(req)) });
  });

  app.post('/api/suppressions', requireAuth, (req, res) => {
    const { targetUrl, findingTitle, reason } = req.body;
    if (!targetUrl || !findingTitle) {
      return res.status(400).json({ error: 'targetUrl and findingTitle are required' });
    }
    const rule = db.addSuppression(getUserId(req), targetUrl, findingTitle, reason || 'False positive confirmation');
    res.json({ status: 'ok', rule });
  });

  app.delete('/api/suppressions/:id', requireAuth, (req, res) => {
    if (!db.removeSuppression(getUserId(req), req.params.id)) {
      return res.status(404).json({ error: 'Suppression exclusion rule not found' });
    }
    res.json({ status: 'ok' });
  });

  app.post('/api/scans/:scanId/findings/:findingId/suppress', requireAuth, (req, res) => {
    const { scanId, findingId } = req.params;
    const { reason = 'Manual enterprise validation' } = req.body;
    const userId = getUserId(req);

    const scan = db.getScan(scanId);
    if (!scan || scan.userId !== userId) {
      return res.status(404).json({ error: 'Scan job not resolved' });
    }

    const finding = scan.findings?.find(f => f.id === findingId);
    if (!finding) {
      return res.status(404).json({ error: 'Finding payload not found' });
    }

    const rule = db.addSuppression(userId, scan.url, finding.title, reason);
    res.json({ status: 'ok', rule, message: 'Finding successfully suppressed and marked as False Positive.' });
  });

  // --- Continuous Monitoring ---
  app.get('/api/monitoring', requireAuth, (req, res) => {
    res.json({ monitoredTargets: db.listMonitoredTargets(getUserId(req)) });
  });

  app.post('/api/monitoring', requireAuth, (req, res) => {
    const { url, frequencyDays = 7, scheduleString } = req.body;
    if (!url) {
      return res.status(400).json({ error: 'url is required' });
    }
    const target = db.addMonitoredTarget(getUserId(req), url, frequencyDays, scheduleString);
    res.json({ status: 'ok', target });
  });

  app.delete('/api/monitoring/:id', requireAuth, (req, res) => {
    if (!db.removeMonitoredTarget(getUserId(req), req.params.id)) {
      return res.status(404).json({ error: 'Monitored target not found' });
    }
    res.json({ status: 'ok' });
  });

  // --- Alert webhook (Slack-compatible) ---
  app.put('/api/user/webhook', requireAuth, async (req, res) => {
    const { url } = req.body || {};
    if (url) {
      if (typeof url !== 'string') {
        return res.status(400).json({ status: 'error', message: 'Webhook must be an http(s) URL, or empty to disable.' });
      }
      // Block internal/reserved destinations (SSRF) at set time; delivery is
      // re-validated as well in case DNS changes later.
      try {
        await assertScanTargetSafe(url.trim());
      } catch {
        return res.status(400).json({ status: 'error', message: 'Webhook must be a public http(s) URL (internal/reserved addresses are not allowed).' });
      }
    }
    const user = db.setUserWebhook(getUserId(req), url ? url.trim() : null);
    res.json({ status: 'ok', notifyWebhook: user?.notifyWebhook ?? null });
  });

  // --- Credits ---
  app.get('/api/credits', requireAuth, (req, res) => {
    const userId = getUserId(req);
    const user = db.getUser(userId);
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({
      credits: user.credits,
      transactions: db.listTransactions(userId)
    });
  });

  // Real Stripe Checkout. Returns a hosted checkout URL; credits are granted by
  // the verified webhook after payment, never here.
  app.post('/api/credits/checkout', requireAuth, async (req, res) => {
    if (!isStripeConfigured()) {
      return res.status(503).json({ status: 'error', message: 'Payments are not currently available. Please contact support.' });
    }
    const { pack } = req.body;
    // Trusted base only (APP_URL enforced in production); dev falls back to host.
    const base = config.appUrl || `${req.protocol}://${req.get('host')}`;
    try {
      const url = await createCheckoutSession(getUserId(req), pack, base);
      res.json({ status: 'ok', url });
    } catch (err: any) {
      const msg = err?.message || 'Could not start checkout.';
      const code = /invalid credit pack/i.test(msg) ? 400 : 502;
      res.status(code).json({ status: 'error', message: msg });
    }
  });

  // API Key routes for developer MCP usecases
  app.get('/api/keys', requireAuth, (req, res) => {
    res.json({ keys: db.listApiKeys(getUserId(req)) });
  });

  // The raw key is returned ONLY in this response — it is never stored and
  // will never be shown again. The client must copy it now.
  app.post('/api/keys', requireAuth, (req, res) => {
    const { apiKey, rawKey } = db.generateApiKey(getUserId(req));
    res.json({ status: 'ok', key: apiKey, rawKey });
  });

  app.delete('/api/keys/:id', requireAuth, (req, res) => {
    if (!db.revokeApiKey(getUserId(req), req.params.id)) {
      return res.status(404).json({ status: 'error', message: 'Key not found or could not be revoked' });
    }
    res.json({ status: 'ok' });
  });

  // --- Domain Ownership Verification ---
  // Gates the scanner's active exploit probes (SQLi/XSS/cmd-injection/SSRF/
  // GraphQL/BOLA fuzzing) so the platform cannot be used as an anonymous
  // attack proxy against arbitrary third-party sites: only a verified owner
  // unlocks them. Passive black-box recon still runs on any target.
  app.get('/api/domains', requireAuth, (req, res) => {
    res.json({ domains: db.listDomainVerifications(getUserId(req)) });
  });

  app.post('/api/domains/verify/start', requireAuth, async (req, res) => {
    const { url } = req.body || {};
    if (!url || typeof url !== 'string') {
      return res.status(400).json({ status: 'error', message: 'url is required' });
    }
    try {
      await assertScanTargetSafe(url);
    } catch (e: any) {
      return res.status(400).json({ status: 'error', message: e?.message || 'Target URL cannot be verified.' });
    }
    const domain = extractDomain(url);
    const userId = getUserId(req);
    const existing = db.getDomainVerification(userId, domain);
    if (existing?.verified) {
      return res.json({ status: 'ok', domain, verified: true });
    }
    const record = db.startDomainVerification(userId, domain, existing?.token || generateVerificationToken());
    res.json({
      status: 'ok',
      domain,
      verified: false,
      txtRecord: { name: txtRecordName(domain), value: record.token },
      wellKnownFile: { path: WELL_KNOWN_PATH, content: record.token },
    });
  });

  app.post('/api/domains/verify/check', requireAuth, async (req, res) => {
    const { url } = req.body || {};
    if (!url || typeof url !== 'string') {
      return res.status(400).json({ status: 'error', message: 'url is required' });
    }
    try {
      await assertScanTargetSafe(url);
    } catch (e: any) {
      return res.status(400).json({ status: 'error', message: e?.message || 'Target URL cannot be verified.' });
    }
    const domain = extractDomain(url);
    const userId = getUserId(req);
    const record = db.getDomainVerification(userId, domain);
    if (!record) {
      return res.status(400).json({ status: 'error', message: 'Start verification for this domain first.' });
    }
    if (record.verified) {
      return res.json({ status: 'ok', domain, verified: true });
    }
    const [txtOk, fileOk] = await Promise.all([
      checkTxtRecord(domain, record.token),
      checkWellKnownFile(domain, record.token),
    ]);
    if (txtOk || fileOk) {
      db.markDomainVerified(userId, domain);
      return res.json({ status: 'ok', domain, verified: true });
    }
    res.json({ status: 'ok', domain, verified: false, message: 'Verification not found yet — DNS/file changes can take a few minutes to propagate.' });
  });

  // --- MCP Endpoints ---
  // Any external agent can call this with an API key
  app.post('/api/mcp/scan', async (req, res) => {
    const { url, apiKey, authHeader } = req.body;
    if (!url || !apiKey) {
      return res.status(400).json({ error: 'Missing parameters. required: url, apiKey' });
    }

    // Reject SSRF / malformed targets before validating the key or spending a credit.
    try {
      await assertScanTargetSafe(url);
    } catch (e: any) {
      return res.status(400).json({ error: e?.message || 'Target URL cannot be scanned.' });
    }

    // Verify key and deduct 1 credit
    const user = db.validateApiKeyAndDeduct(apiKey, 1);
    if (!user) {
      return res.status(401).json({ error: 'Invalid API Key, active key required, or insufficient credits. Get credits at seclayer.io.' });
    }

    try {
      // Active exploit probing only runs once this key's owner has verified
      // ownership of the target's domain; otherwise passive recon only.
      const allowActiveProbes = db.isDomainVerified(user.id, extractDomain(url));

      // Runs scan diagnostic synchronously for MCP tools context
      const diagnostics = await runDiagnostics(url, authHeader, { allowActiveProbes });
      const staticCompiled = compileStaticFindings(diagnostics);
      const aiReport = await generateAiReport(url, diagnostics, staticCompiled);
      
      // Save completed scan in background for dashboard history as well
      const completedScan = db.createScan(user.id, url, authHeader);
      const evidence = compileScanEvidence(diagnostics);
      db.updateScan(completedScan.id, {
        status: 'complete',
        score: aiReport.score,
        severity: aiReport.severity,
        findings: aiReport.findings,
        aiSummary: aiReport.aiSummary,
        aiReasoning: aiReport.aiReasoning,
        executiveBreakdown: aiReport.executiveBreakdown,
        evidence,
        completedAt: new Date().toISOString()
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
        creditsRemaining: user.credits
      });
    } catch (err: any) {
      res.status(500).json({ error: 'Internal audit scanning failed', details: err.message });
    }
  });


  // --- Background scan worker ---
  // Drives a scan through its real lifecycle: status reflects actual work
  // boundaries (diagnostics, then AI analysis), with no artificial delays.
  async function processScanJob(scanId: string, allowActiveProbes: boolean) {
    try {
      console.log(`[Job Worker] Starting scan ${scanId}`);

      const scan = db.getScan(scanId);
      if (!scan) return;

      let narration: string[] = [];

      // Active diagnostics (HTTP probing, header/secret/SCA/path checks, fuzzing).
      db.updateScan(scanId, { status: 'scanning' });
      const diagnostics = await runDiagnostics(scan.url, scan.authHeader, { allowActiveProbes });

      // Fast (flash), cheap narration of what the sweep actually found — read
      // by the progress UI in place of scripted filler text.
      narration = narration.concat(await narrateScanning(diagnostics, scan.url));
      db.updateScan(scanId, { status: 'analyzing', narrationLog: narration });

      // Compile findings and generate the analysis report.
      const staticCompiled = compileStaticFindings(diagnostics);
      const outputReport = await generateAiReport(scan.url, diagnostics, staticCompiled);

      // Narrate the score the UI will actually display: every read path
      // (getScanWithSuppressedFindings) recalculates it deterministically
      // from finding severities, which can differ from the AI's own
      // subjective adjustedScore stored below — narrating the raw AI figure
      // would show the user a number that contradicts the report they open next.
      const { score: displayScore, severity: displaySeverity } = recalculateScore(outputReport.findings);
      narration = narration.concat(await narrateAnalysis({ score: displayScore, severity: displaySeverity, findings: outputReport.findings }, scan.url));

      // Best-effort visual capture of the target's landing page (opt-in via
      // ENABLE_TARGET_SCREENSHOT). Returns null — never throws — when disabled,
      // unavailable, or blocked, so it can never fail the scan. Reuses the same
      // auth headers the diagnostics used.
      const evidence = compileScanEvidence(diagnostics);
      const shot = await captureScreenshot(scan.url, {
        'User-Agent': 'Seclayer-Security-Scanner/2.0 (+https://seclayer.io)',
        ...parseAuthHeader(scan.authHeader),
      });
      if (shot) evidence.screenshot = shot;

      const completed = db.updateScan(scanId, {
        status: 'complete',
        score: outputReport.score,
        severity: outputReport.severity,
        findings: outputReport.findings,
        aiSummary: outputReport.aiSummary,
        aiReasoning: outputReport.aiReasoning,
        narrationLog: narration,
        executiveBreakdown: outputReport.executiveBreakdown,
        evidence,
        completedAt: new Date().toISOString()
      });
      console.log(`[Job Worker] Completed scan ${scanId}`);

      // Fire the user's alert webhook for actionable results (non-blocking).
      const owner = db.getUser(completed.userId);
      notifyScanComplete(owner?.notifyWebhook, db.getScanWithSuppressedFindings(completed));

    } catch (err: any) {
      console.error(`[Job Worker] FAILED scan ${scanId}:`, err?.message || err);
      db.updateScan(scanId, {
        status: 'failed',
        error: err?.message || 'The scan could not be completed.'
      });
    }
  }

  // --- Continuous monitoring worker ---
  // Runs real scheduled scans for due monitored targets: validates the target,
  // spends a credit, and launches the same scan pipeline as a manual scan.
  let monitorTickRunning = false;
  async function runDueMonitoredScans() {
    if (monitorTickRunning) return;
    monitorTickRunning = true;
    try {
      const due = db.listDueMonitoredTargets(new Date().toISOString());
      for (const target of due) {
        const next = new Date(Date.now() + (target.frequencyDays || 7) * 24 * 60 * 60 * 1000).toISOString();
        try {
          const user = db.getUser(target.userId);
          if (!user || user.credits < 1) continue; // retry next tick once credits exist
          await assertScanTargetSafe(target.url);
          db.deductCredits(target.userId, 1);
          const scan = db.createScan(target.userId, target.url);
          db.markMonitoredScanned(target.id, new Date().toISOString(), next);
          const allowActiveProbes = db.isDomainVerified(target.userId, extractDomain(target.url));
          processScanJob(scan.id, allowActiveProbes);
        } catch (err: any) {
          // Invalid/unsafe target: defer instead of retrying every tick.
          db.markMonitoredScanned(target.id, target.lastScannedAt || new Date().toISOString(), next);
          console.warn(`[monitor] Skipped ${target.url}: ${err?.message || err}`);
        }
      }
    } finally {
      monitorTickRunning = false;
    }
  }
  const monitorInterval = setInterval(() => {
    runDueMonitoredScans().catch((e) => console.error('[monitor] tick error:', e));
  }, 60 * 1000);
  monitorInterval.unref();

  // Unknown API routes return JSON 404 (not the SPA shell).
  app.use('/api', (req, res) => {
    res.status(404).json({ status: 'error', message: `Unknown API endpoint: ${req.method} ${req.path}` });
  });

  // --- Express serving of static client files ---
  if (!config.isProd) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  // JSON error handler — keeps thrown route errors from leaking stack traces
  // or crashing the process; always responds with structured JSON.
  app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    console.error('[server] Unhandled route error:', err?.message || err);
    if (res.headersSent) return next(err);
    res.status(500).json({ status: 'error', message: 'An unexpected server error occurred.' });
  });

  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Seclayer Engine] Listening on http://0.0.0.0:${PORT} (${config.isProd ? 'production' : 'development'})`);
  });

  // Graceful shutdown for containerized deployments.
  const shutdown = (signal: string) => {
    console.log(`[server] ${signal} received — shutting down gracefully.`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

// Process-level safety nets: log instead of crashing silently.
process.on('unhandledRejection', (reason) => {
  console.error('[server] Unhandled promise rejection:', reason);
});
process.on('uncaughtException', (err) => {
  console.error('[server] Uncaught exception:', err);
});

// Global safety catch
startServer().catch((err) => {
  console.error("Critical server bootstrap error:", err);
  process.exit(1);
});
