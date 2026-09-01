import './server/env.js'; // must run first: loads .env before any module reads process.env
import express from 'express';
import path from 'path';
import cookieParser from 'cookie-parser';
import { db } from './server/db.js';
import { config, validateConfigOnBoot } from './server/config.js';
import { parseWebhookEvent } from './server/stripe.js';
import { createOobCollaborator } from './server/oob.js';
import { makeProcessScanJob } from './server/scanWorker.js';
import { processNmapScanJob } from './server/nmapWorker.js';
import { detectNmap } from './server/nmap/detect.js';
import { startMonitorWorker } from './server/monitorWorker.js';
import { startDigestWorker } from './server/digestWorker.js';
import { startBackupWorker } from './server/backupWorker.js';
import { registerAuthRoutes } from './server/routes/auth.js';
import { registerScanRoutes } from './server/routes/scans.js';
import { registerNmapRoutes } from './server/routes/nmap.js';
import { registerAccountRoutes } from './server/routes/account.js';
import { registerDomainRoutes } from './server/routes/domains.js';
import { registerMcpRoutes } from './server/routes/mcp.js';
import { registerAutofixRoutes } from './server/routes/autofix.js';
import { registerWellKnownRoutes } from './server/routes/wellKnown.js';
import { accessLog } from './server/accessLog.js';
import { securityHeaders } from './server/securityHeaders.js';
import type { RouteContext } from './server/routes/context.js';

async function startServer() {
  if (!validateConfigOnBoot() && config.isProd) {
    console.error('[config] Refusing to start: production-critical configuration is missing (see warnings above).');
    process.exit(1);
  }

  const app = express();
  app.disable('x-powered-by');
  const PORT = config.port;

  // Resilience: fail (and refund) any scan orphaned by a prior process's
  // crash/redeploy before it can ever be found stuck by a user. Only the
  // worker-bearing roles do this — a 'web' instance booting must NOT sweep
  // scans a worker instance is actively running and mark them failed. On a
  // single-node deployment (role 'all', the default) this runs exactly as before.
  const runsWorkers = config.role !== 'web';
  if (runsWorkers) {
    const recovered = (await db.recoverStuckScans());
    if (recovered > 0) {
      console.log(`[server] Recovered ${recovered} scan(s) left mid-flight by a prior process — marked failed and refunded.`);
    }
    const recoveredNmap = (await db.recoverStuckNmapScans());
    if (recoveredNmap > 0) {
      console.log(`[server] Recovered ${recoveredNmap} network reconnaissance scan(s) left mid-flight by a prior process — marked failed and refunded.`);
    }
  }

  // Network Reconnaissance (nmap) feature detection — probed once at boot and
  // memoized; the feature stays cleanly absent (not erroring) whenever the
  // binary isn't present, e.g. the Vercel-hosted deployment or a bare local
  // checkout without nmap installed. Only ever present in the self-hosted
  // Docker image (see Dockerfile).
  const nmapDetection = await detectNmap();
  console.log(
    nmapDetection.available
      ? `[config] nmap ${nmapDetection.version} detected — Network Reconnaissance is available (${nmapDetection.privileged ? 'privileged: SYN + OS detection' : 'unprivileged: TCP connect scan, no OS detection — this container has no raw-socket capability'}).`
      : `[config] nmap not available (${nmapDetection.error}) — Network Reconnaissance is disabled on this deployment.`
  );

  // Out-of-band collaborator for blind-vuln proofs. Needs a base URL the SCANNED
  // TARGET can reach back on — APP_URL in production (OOB_BASE_URL overrides it,
  // e.g. to a loopback base in local testing). When neither is set the OOB probe
  // is skipped and the rest of the scan is unaffected.
  const oobBase = process.env.OOB_BASE_URL || config.appUrl;
  const oobCollaborator = oobBase ? createOobCollaborator(db, oobBase) : undefined;

  // Behind a proxy/load balancer in production so req.protocol, req.ip and
  // Secure cookies are derived from the X-Forwarded-* headers.
  if (config.isProd) app.set('trust proxy', 1);

  // Per-request access log (skips the health probe so orchestrator polling
  // doesn't flood the log). One structured line per finished response.
  app.use(accessLog());

  // Baseline security headers on every response (including API + errors). HSTS
  // and the strict Content-Security-Policy are production-only — see
  // server/securityHeaders.ts for the per-directive rationale.
  app.use(securityHeaders({ isProd: config.isProd }));

  // Stripe webhook MUST receive the raw body for signature verification, so it
  // is registered before the JSON body parser. Credits are granted only here,
  // on a verified, paid checkout.session.completed event.
  app.post('/api/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
    let completion;
    try {
      completion = parseWebhookEvent(req.body as Buffer, req.headers['stripe-signature'] as string | undefined);
    } catch (err: any) {
      console.warn('[stripe] Webhook verification failed:', err?.message || err);
      return res.status(400).json({ error: `Webhook Error: ${err?.message || 'invalid signature'}` });
    }
    if (completion && !(await db.hasTransactionForSession(completion.sessionId))) {
      const user = (await db.getUser(completion.userId));
      if (user) {
        (await db.addCredits(user.id, completion.credits, 'purchase', completion.sessionId));
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
  const cookieOptions: express.CookieOptions = {
    httpOnly: true,
    secure: isProd,
    sameSite: 'lax',
    path: '/',
    maxAge: 30 * 24 * 60 * 60 * 1000,
  };

  // Resolve the session cookie to a userId for every request. Identity is
  // derived server-side from the signed session — never from client input.
  app.use(async (req, res, next) => {
    const token = req.cookies?.[SESSION_COOKIE];
    if (token) {
      const userId = (await db.getSessionUserId(token));
      if (userId) (req as any).userId = userId;
    }
    // Dev convenience (config.devSkipAuth, never true in production): skip the
    // magic-link flow entirely by treating every unauthenticated request as a
    // fixed local dev account, so the app is usable immediately while building.
    if (!(req as any).userId && config.devSkipAuth) {
      (req as any).userId = (await db.getOrCreateUser('dev@localhost')).id;
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

  // Background scan worker, shared by the HTTP routes and the monitoring worker.
  const processScanJob = makeProcessScanJob(oobCollaborator);

  // --- API ROUTES ---
  const ctx: RouteContext = {
    requireAuth, getUserId, processScanJob, processNmapScanJob,
    nmapAvailable: nmapDetection.available,
    oobCollaborator, cookieOptions, sessionCookie: SESSION_COOKIE,
  };
  registerAuthRoutes(app, ctx);
  registerScanRoutes(app, ctx);
  registerNmapRoutes(app, ctx);
  registerAccountRoutes(app, ctx);
  registerDomainRoutes(app, ctx);
  registerMcpRoutes(app, ctx);
  registerAutofixRoutes(app);

  // Public site-policy files: robots.txt + RFC 9116 security.txt.
  registerWellKnownRoutes(app);

  // In-process background workers (continuous monitoring 60s tick, daily digest,
  // periodic DB backup). Gated by role so that when scaling horizontally, only
  // the 'worker'/'all' instances run them — otherwise EVERY web instance would
  // run its own timers and duplicate the monitoring scans, digest emails, and
  // backups N times over. Single-node ('all', the default) is unchanged.
  if (runsWorkers) {
    startMonitorWorker(processScanJob);
    startDigestWorker();
    startBackupWorker();
  } else {
    console.log('[server] role=web — background workers (monitoring, digest, backups) disabled on this instance.');
  }

  // Unknown API routes return JSON 404 (not the SPA shell).
  app.use('/api', (req, res) => {
    res.status(404).json({ status: 'error', message: `Unknown API endpoint: ${req.method} ${req.path}` });
  });

  // --- Express serving of static client files ---
  if (!config.isProd) {
    // Dynamic, not a top-level import: vite is a devDependency only (see
    // package.json) so it — and its own esbuild/transitive deps — can be
    // pruned out of the production image entirely (npm prune --omit=dev). A
    // static top-level import would force node to resolve 'vite' on every
    // boot, dev or prod, defeating that.
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));

    // The SPA shell is served ONLY for paths the client router actually has a
    // view for; everything else gets a real 404.
    //
    // This is a security-reputation fix, not just tidiness. The previous
    // catch-all answered 200 + the full app shell for EVERY path, so
    // /wp-login.php, /admin/login, /verify-account and /secure/signin all
    // returned a page with a sign-in form. That is indistinguishable from a
    // credential-harvesting kit — unlimited distinct URLs, all 200, all showing
    // a login UI — and Google Safe Browsing flagged the whole domain as
    // "Deceptive pages" (no sample URLs: the pattern itself was the finding),
    // which made Chrome block every visitor.
    //
    // Keep this list in sync with the client router (src/hooks/useSeclayer.ts's
    // initial view + src/App.tsx's /r/:token share route).
    const SPA_ROUTES = [/^\/$/, /^\/docs\/?$/, /^\/privacy\/?$/, /^\/terms\/?$/, /^\/r\/[A-Za-z0-9_-]+\/?$/];
    app.get('*', (req, res) => {
      if (SPA_ROUTES.some((re) => re.test(req.path))) {
        return res.sendFile(path.join(distPath, 'index.html'));
      }
      // Deliberately a minimal page with no sign-in affordance — a 404 that
      // still rendered the app shell would keep the same phishing fingerprint.
      res.status(404).type('html').send(
        '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
          '<meta name="viewport" content="width=device-width,initial-scale=1">' +
          '<meta name="robots" content="noindex">' +
          '<title>404 — Page not found</title></head>' +
          '<body style="font-family:system-ui,-apple-system,sans-serif;background:#0c0c0e;color:#e4e4e7;' +
          'display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0">' +
          '<main style="text-align:center;padding:2rem">' +
          '<h1 style="font-size:1.25rem;margin:0 0 .5rem">404 — Page not found</h1>' +
          '<p style="color:#a1a1aa;font-size:.875rem;margin:0 0 1.25rem">That page does not exist on Seclayer.</p>' +
          '<a href="/" style="color:#22c55e;font-size:.875rem">Go to seclayer.app</a>' +
          '</main></body></html>',
      );
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
  let shuttingDown = false;
  const shutdown = (signal: string) => {
    if (shuttingDown) return; // ignore a second signal while already draining
    shuttingDown = true;
    console.log(`[server] ${signal} received — shutting down gracefully.`);
    server.close(async () => {
      // Checkpoint the WAL and release the SQLite file lock so a container
      // redeploy leaves a clean database behind, then exit.
      (await db.close());
      process.exit(0);
    });
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
