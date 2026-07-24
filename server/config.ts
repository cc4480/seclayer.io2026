// Centralized runtime configuration + boot-time validation. Keeps environment
// handling in one place and surfaces misconfiguration as clear startup warnings
// instead of silent degradation in production.

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

export const config = {
  port: Number(process.env.PORT) || 3000,
  isProd: process.env.NODE_ENV === 'production',
  appUrl: clean(process.env.APP_URL, 'MY_APP_URL')?.replace(/\/+$/, ''),
  deepseekConfigured: !!clean(process.env.DEEPSEEK_API_KEY, 'MY_DEEPSEEK_API_KEY'),
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

  if (config.isProd) {
    if (!config.appUrl) {
      warnings.push('APP_URL is required in production (used to build magic-link and checkout URLs from a trusted host, not the request Host header).');
      prodCriticalMissing = true;
    }
    if (!config.emailConfigured) {
      warnings.push('Running in production without an email provider: users will NOT receive sign-in links.');
      prodCriticalMissing = true;
    }
  }

  for (const w of warnings) console.warn(`[config] ${w}`);
  return !prodCriticalMissing;
}
