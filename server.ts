import './server/env.js'; // must run first: loads .env before any module reads process.env
import express from 'express';
import path from 'path';
import cookieParser from 'cookie-parser';
import { createServer as createViteServer } from 'vite';
import { db } from './server/db.js';
import { config, validateConfigOnBoot } from './server/config.js';
import { parseWebhookEvent } from './server/stripe.js';
import { createOobCollaborator } from './server/oob.js';
import { makeProcessScanJob } from './server/scanWorker.js';
import { startMonitorWorker } from './server/monitorWorker.js';
import { startDigestWorker } from './server/digestWorker.js';
import { registerAuthRoutes } from './server/routes/auth.js';
import { registerScanRoutes } from './server/routes/scans.js';
import { registerAccountRoutes } from './server/routes/account.js';
import { registerDomainRoutes } from './server/routes/domains.js';
import { registerMcpRoutes } from './server/routes/mcp.js';
import { registerWellKnownRoutes } from './server/routes/wellKnown.js';
import { accessLog } from './server/accessLog.js';
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
  // crash/redeploy before it can ever be found stuck by a user.
  const recovered = db.recoverStuckScans();
  if (recovered > 0) {
    console.log(`[server] Recovered ${recovered} scan(s) left mid-flight by a prior process — marked failed and refunded.`);
  }

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
  const cookieOptions: express.CookieOptions = {
    httpOnly: true,
    secure: isProd,
    sameSite: 'lax',
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

  // Background scan worker, shared by the HTTP routes and the monitoring worker.
  const processScanJob = makeProcessScanJob(oobCollaborator);

  // --- API ROUTES ---
  const ctx: RouteContext = {
    requireAuth, getUserId, processScanJob, oobCollaborator, cookieOptions, sessionCookie: SESSION_COOKIE,
  };
  registerAuthRoutes(app, ctx);
  registerScanRoutes(app, ctx);
  registerAccountRoutes(app, ctx);
  registerDomainRoutes(app, ctx);
  registerMcpRoutes(app, ctx);

  // Public site-policy files: robots.txt + RFC 9116 security.txt.
  registerWellKnownRoutes(app);

  // Continuous-monitoring worker (60s tick).
  startMonitorWorker(processScanJob);
  startDigestWorker();

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
  let shuttingDown = false;
  const shutdown = (signal: string) => {
    if (shuttingDown) return; // ignore a second signal while already draining
    shuttingDown = true;
    console.log(`[server] ${signal} received — shutting down gracefully.`);
    server.close(() => {
      // Checkpoint the WAL and release the SQLite file lock so a container
      // redeploy leaves a clean database behind, then exit.
      db.close();
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
