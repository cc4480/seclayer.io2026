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

export type CookieClass = "session" | "analytics" | "preference" | "unknown";

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
  if (ANALYTICS_PATTERNS.some((re) => re.test(n))) return "analytics";
  if (SESSION_PATTERNS.some((re) => re.test(n))) return "session";
  if (PREFERENCE_PATTERNS.some((re) => re.test(n))) return "preference";
  return "unknown";
}
