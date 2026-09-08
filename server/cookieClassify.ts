// Classify a cookie by name so cookie-flag findings can be scored by what the
// cookie actually IS. A missing HttpOnly/Secure flag only carries real
// session-hijack risk on a cookie that holds session/auth state. On third-party
// analytics cookies and non-secret UX preference cookies the same "gap" is a
// false positive: those cookies MUST be readable by client-side JavaScript, hold
// no secret, and (for analytics) are set by an embedded SDK, not the app. Flagging
// every cookie at "medium" regardless is what let six locale/analytics cookies
// crater an otherwise-clean site to the score floor.
//
// Pure and dependency-free so it's unit-tested directly.

export type CookieClass = "session" | "analytics" | "preference" | "infra" | "unknown";

// Cookies set by a CDN, WAF or bot-management layer in front of the site — not
// by the application, and not something the operator can add flags to. Flagging
// a missing HttpOnly on Cloudflare's or DataDome's own cookie is unactionable:
// the fix would require the vendor, not the site owner. Checked first, like
// analytics, because some carry "session"/"sid" substrings.
const INFRA_PATTERNS: RegExp[] = [
  /^datadome$/i,                         // DataDome bot management
  /^bm_/i, /^ak_bmsc$/i, /^_abck$/i,     // Akamai Bot Manager
  /^__cf_bm$/i, /^cf_clearance$/i, /^_cfuvid$/i, /^__cflb$/i, // Cloudflare
  /^incap_ses/i, /^visid_incap/i, /^nlbi_/i, // Imperva/Incapsula
  /^__cfruid$/i,
];

// Double-submit CSRF tokens are read by the page and echoed in a request header,
// so they MUST be JS-readable — HttpOnly would break the defence. They still
// need Secure and SameSite, so they stay classified "session"; this predicate
// only exempts them from the HttpOnly finding specifically.
export function isCsrfToken(name: string): boolean {
  const n = (name || "").trim();
  if (!/csrf|xsrf/i.test(n)) return false;
  // A name carrying both a CSRF and a stronger session marker is ambiguous;
  // keep it locked down rather than exempt it.
  return !/sess|jwt|login|remember|credential|(^|[._-])sid([._-]|$)/i.test(n);
}

// Third-party analytics / marketing / product-telemetry cookies, set by embedded
// SDKs and required to be JS-readable. Checked FIRST because some carry "session"
// or "id" substrings (e.g. rs_session_id) that would otherwise trip the session
// matcher.
const ANALYTICS_PATTERNS: RegExp[] = [
  /^rs_/i,                 // RudderStack (rs_visitor_id, rs_session_id, …)
  /^_ga(_|$)/i, /^_gid$/i, /^_gat/i, /^_gcl_/i, // Google Analytics / Ads
  /^_fb[pc]$/i,            // Meta / Facebook pixel
  /^ajs_/i,                // Segment
  /^(amplitude|amp_)/i,    // Amplitude
  /^mp_/i, /mixpanel/i,    // Mixpanel
  /^_hj/i,                 // Hotjar
  /^__hs|hubspotutk/i,     // HubSpot
  /^intercom-/i,           // Intercom
  /^_pk_/i,                // Matomo
  /optimizely/i,           // Optimizely
  /^_clck$|^_clsk$/i,      // Microsoft Clarity
];

// Non-secret UX preference cookies: they exist to be read by client-side JS to
// render the right locale/currency/theme, so HttpOnly is inappropriate by design
// and their interception risk is negligible (no secret to steal).
const PREFERENCE_PATTERNS: RegExp[] = [
  /locale/i,
  /(^|[._-])lang(uage)?([._-]|$)/i,
  /currency/i,
  /country/i,
  /region/i,
  /timezone/i,
  /(^|[._-])tz([._-]|$)/i,
  /theme/i,
  /color[._-]?scheme/i,
];

// Session / authentication cookies — where HttpOnly and Secure genuinely matter
// because the cookie carries credentials or session state.
const SESSION_PATTERNS: RegExp[] = [
  /sess/i,                       // session, sess, phpsessid, jsessionid
  /(^|[._-])sid([._-]|$)/i,      // connect.sid, foo_sid
  /auth/i, /token/i, /jwt/i,
  /csrf/i, /xsrf/i,
  /login/i, /remember/i,
  /credential/i, /identity/i,
];

export function classifyCookie(name: string): CookieClass {
  const n = (name || "").trim();
  if (!n) return "unknown";
  if (INFRA_PATTERNS.some((re) => re.test(n))) return "infra";
  if (ANALYTICS_PATTERNS.some((re) => re.test(n))) return "analytics";
  if (SESSION_PATTERNS.some((re) => re.test(n))) return "session";
  if (PREFERENCE_PATTERNS.some((re) => re.test(n))) return "preference";
  return "unknown";
}
