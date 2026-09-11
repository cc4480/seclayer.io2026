// Centralized runtime configuration + boot-time validation. Keeps environment
// handling in one place and surfaces misconfiguration as clear startup warnings
// instead of silent degradation in production.

/**
 * The scanner's outbound User-Agent — one string, used by every fetch path.
 *
 * The `Mozilla/5.0 (compatible; <bot>; +<url>)` form is the convention every
 * legitimate crawler uses (Googlebot, Bingbot). It still identifies honestly as
 * the Seclayer scanner and is NOT browser-spoofing — it does not claim to be
 * Chrome or any real browser. It replaced a bare `Seclayer-Security-Scanner/2.0`
 * token that Cloudflare's bot management scored as an obvious non-browser bot
 * and 403'd from a cloud egress IP, blocking scans of sites (e.g. lovable.dev)
 * that return 200 to any conventional request. The `SCANNER_USER_AGENT` env var
 * overrides it for self-hosted operators.
 *
 * Eight call sites had drifted to slightly different literals; they now share
 * this one, so the identity a target sees is consistent everywhere.
 */
export const SCANNER_USER_AGENT: string =
  process.env.SCANNER_USER_AGENT?.trim() ||
  "Mozilla/5.0 (compatible; Seclayer-Security-Scanner/2.0; +https://seclayer.app/bot)";

function clean(v: string | undefined, placeholder?: string): string | undefined {
  if (!v) return undefined;
  const t = v.trim();
  if (!t || (placeholder && t === placeholder)) return undefined;
  return t;
}

const stripeConfigured = !!clean(process.env.STRIPE_SECRET_KEY) && !!clean(process.env.STRIPE_WEBHOOK_SECRET);

// Free testing mode: scans require no credits and no purchase. FREE_MODE=true|false
// overrides; otherwise it defaults ON whenever payments aren't configured, so the
// app is usable for free out of the box and automatically switches to paid once
// Stripe is wired up.
const freeModeEnv = clean(process.env.FREE_MODE);
const freeMode = freeModeEnv === 'true' ? true : freeModeEnv === 'false' ? false : !stripeConfigured;

// Deployment role for THIS instance. Controls which in-process background
// workers run here and whether this instance performs boot-time scan recovery.
//   'all'    (default) — single-node: serve HTTP AND run monitoring/digest/backup
//            workers + boot recovery. Backwards-compatible with every existing
//            single-instance deployment.
//   'web'    — serve HTTP only. NO background workers, NO boot-time scan recovery.
//            Run many of these behind the load balancer when scaling out, so the
//            monitoring scans, digest emails, and backups are NOT duplicated on
//            every instance (they would be, otherwise — each ran its own timers).
//   'worker' — run the background workers + boot recovery, no public HTTP surface
//            needed (still binds a port for health checks).
// NOTE: a real multi-instance ('web' × N + 'worker') deployment ALSO requires a
// shared/networked database — the current local SQLite file can't be shared
// across machines. See the scale-out readiness notes.
export function parseRole(raw: string | undefined = process.env.SECLAYER_ROLE): 'web' | 'worker' | 'all' {
  const r = clean(raw)?.toLowerCase();
  return r === 'web' || r === 'worker' ? r : 'all';
}

/**
 * The exact build running in this process, for OPERATORS ONLY.
 *
 * Deliberately separate from config.appVersion, which is public (see there).
 * This is logged once at boot, so it reaches the platform's log stream — which
 * requires project access to read — and never an HTTP response body.
 *
 * It exists because "is my change actually live?" had no answer from inside the
 * app: the public health endpoint reported `dev`, and the only way to tell was
 * to query the deploy platform's API from a developer machine.
 *
 * The git SHA is supplied by the platform on a deploy (Railway and Vercel both
 * inject their own name for it); `local` is the honest answer when none is —
 * a developer run, or a `docker build` that passed no build metadata.
 */
export function buildId(env: NodeJS.ProcessEnv = process.env): string {
  const sha = clean(env.APP_BUILD_SHA)
    || clean(env.RAILWAY_GIT_COMMIT_SHA)
    || clean(env.VERCEL_GIT_COMMIT_SHA)
    || clean(env.SOURCE_COMMIT)
    || clean(env.GIT_COMMIT);
  if (!sha) return 'local';
  // Short form: enough to identify a commit, and it is what `git log --oneline`
  // prints, so it can be pasted straight into a git command.
  return /^[0-9a-f]{40}$/i.test(sha) ? sha.slice(0, 7) : sha;
}

export const config = {
  port: Number(process.env.PORT) || 3000,
  isProd: process.env.NODE_ENV === 'production',
  role: parseRole(process.env.SECLAYER_ROLE),
  // Max scans allowed to run concurrently IN THIS PROCESS. Each scan is heavy
  // (minutes of CPU + hundreds of network calls + an nmap subprocess), so an
  // unbounded burst of scan requests could exhaust the instance's memory,
  // sockets, and event loop. Excess scans wait (their row stays 'queued', which
  // recoverStuckScans already sweeps on a crash) until a slot frees. Also the
  // natural per-worker concurrency cap once scans move to a worker fleet.
  // MAX_CONCURRENT_SCANS overrides; default 4.
  maxConcurrentScans: Math.max(1, Number(process.env.MAX_CONCURRENT_SCANS) || 4),
  // PUBLIC. This string is served by the unauthenticated /api/system/health
  // probe AND rendered to every visitor in the navbar's engine tooltip
  // (src/components/Navbar.tsx) — it is product surface, not operator surface.
  //
  // So do NOT set APP_VERSION to a git SHA. This repository is public, so a
  // live commit hash lets anyone diff it against main and read off exactly
  // which security fixes are not yet deployed. (The comment here used to
  // recommend precisely that.) Use a release tag people are meant to see, e.g.
  // "v2.1.0". Operators who need the exact build read buildId() from the boot
  // log, which only someone with platform access can see.
  appVersion: clean(process.env.APP_VERSION) || 'dev',
  appUrl: clean(process.env.APP_URL, 'MY_APP_URL')?.replace(/\/+$/, ''),
  deepseekConfigured: !!clean(process.env.DEEPSEEK_API_KEY, 'MY_DEEPSEEK_API_KEY'),
  // "Sign in with Google" (Google Identity Services). Public value — it ships in
  // the client bundle by design, so it is served to the login form rather than
  // kept secret. Absent = the button is simply not offered and the magic-link
  // flow is unchanged, so deploying this code with the var unset is a no-op.
  googleClientId: clean(process.env.GOOGLE_CLIENT_ID, 'MY_GOOGLE_CLIENT_ID'),
  emailConfigured: !!clean(process.env.RESEND_API_KEY, 'MY_RESEND_API_KEY'),
  stripeConfigured,
  freeMode,
  // Dev convenience: auto-authenticate every request as a fixed local user, so
  // the magic-link sign-in flow can be skipped while building locally. The
  // `process.env.NODE_ENV !== 'production'` half of this check is redundant
  // with isProd by construction, but is spelled out explicitly (rather than
  // just referencing isProd) so this can never accidentally evaluate true in
  // a production build regardless of how the flag is later refactored.
  devSkipAuth: process.env.NODE_ENV !== 'production' && process.env.DEV_SKIP_AUTH !== 'false',
  // Dev-only: unlock the ACTIVE red-team exploit probes (SQLi/XSS/cmd-injection/
  // SSRF/GraphQL/BOLA) WITHOUT the usual DNS/well-known domain-ownership proof, so
  // the probes can be exercised locally (e.g. against test-targets/vulnerable-app).
  // Opt-in and HARD-disabled in production — the ownership gate exists so the
  // platform can't be used as an anonymous attack proxy, so it can never be
  // bypassed on a real deployment regardless of this env var. Pair with
  // SCAN_DEV_ALLOW_HOSTS to also let the SSRF guard reach a loopback target.
  devSkipDomainVerification:
    process.env.NODE_ENV !== 'production' && process.env.DEV_SKIP_DOMAIN_VERIFICATION === 'true',
  // OPERATOR opt-in (works in production too, unlike the dev flag above): unlock
  // the active red-team/aggressive probes on THIS instance without per-domain
  // ownership proof. Off by default. Intended for a private, single-tenant
  // instance you run to test targets you own — set it once and every scan path
  // (dashboard, scan-now, monitors, MCP) runs active probes. Do NOT enable it on
  // an instance other people can reach or sign into: it re-opens the "aim active
  // exploits at any domain" surface the ownership gate exists to close.
  allowUnverifiedActiveProbes: process.env.ALLOW_UNVERIFIED_ACTIVE_PROBES === 'true',
  // OPERATOR opt-in (works in production too): permit boot without a real email
  // provider. This does NOT weaken auth - the magic-link token, its single-use
  // redemption and 15-minute expiry are unchanged (see routes/auth.ts); it only
  // changes delivery: server/email.ts already logs the link to the console
  // whenever RESEND_API_KEY is unset, this just lets that fallback run on a
  // production boot instead of being treated as fatal misconfiguration. Intended
  // for a private, single-operator instance (e.g. local Docker) where you read
  // your own sign-in link from `docker logs`/console instead of an inbox. Do NOT
  // enable it on an instance other people might try to sign into - they would
  // have no way to receive their link.
  allowMissingEmailProvider: process.env.ALLOW_MISSING_EMAIL_PROVIDER === 'true',
};

// Logs configuration warnings; returns false if a production-critical setting is
// missing so the caller can decide whether to refuse to boot.
export function validateConfigOnBoot(): boolean {
  const warnings: string[] = [];
  let prodCriticalMissing = false;

  if (!config.deepseekConfigured) {
    warnings.push('DEEPSEEK_API_KEY not set — AI reports will use built-in local summaries.');
  }
  if (!config.emailConfigured) {
    warnings.push('RESEND_API_KEY not set — magic-link emails are written to the console (dev/demo mode).');
  }
  if (!config.stripeConfigured) {
    warnings.push('STRIPE_SECRET_KEY / STRIPE_WEBHOOK_SECRET not set — credit purchases are disabled.');
  }
  if (config.freeMode) {
    warnings.push('FREE_MODE is on — scans require no credits (free public testing). Set FREE_MODE=false once payments are configured.');
  }
  if (config.devSkipDomainVerification) {
    warnings.push('DEV_SKIP_DOMAIN_VERIFICATION is on — active red-team probes run WITHOUT domain-ownership proof. DEV ONLY: only scan targets you own (this is hard-disabled in production). Unset it to restore the verification gate.');
  }
  if (config.allowUnverifiedActiveProbes) {
    warnings.push('ALLOW_UNVERIFIED_ACTIVE_PROBES is on — active red-team probes run WITHOUT domain-ownership proof on EVERY scan path, including in production. Only safe on a PRIVATE instance you control, testing targets you own. Anyone who can use this instance can now aim active exploits at any domain. Unset it to restore the ownership gate.');
  }

  if (config.isProd) {
    if (!config.appUrl) {
      warnings.push('APP_URL is required in production (used to build magic-link and checkout URLs from a trusted host, not the request Host header).');
      prodCriticalMissing = true;
    }
    if (!config.emailConfigured) {
      if (config.allowMissingEmailProvider) {
        warnings.push('ALLOW_MISSING_EMAIL_PROVIDER is on — running in production without an email provider; sign-in links are written to the console instead of emailed. Only safe on a private, single-operator instance.');
      } else {
        warnings.push('Running in production without an email provider: users will NOT receive sign-in links.');
        prodCriticalMissing = true;
      }
    }
  }

  if (config.role !== 'all') {
    warnings.push(
      config.role === 'web'
        ? "SECLAYER_ROLE=web — this instance serves HTTP only; background workers (monitoring, digest, backups) and boot-time scan recovery are DISABLED here. Ensure exactly one 'worker'/'all' instance runs them, and that all instances share a networked database (SQLite cannot be shared across instances)."
        : "SECLAYER_ROLE=worker — this instance runs background workers + boot recovery. Make sure a networked database is shared with the web instances (SQLite cannot be shared across instances)."
    );
  }

  for (const w of warnings) console.warn(`[config] ${w}`);
  return !prodCriticalMissing;
}
