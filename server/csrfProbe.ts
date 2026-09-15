// CSRF posture check — high-precision, non-destructive.
//
// passiveScan.ts once omitted CSRF inference entirely, because the naive version
// ("a form has no anti-CSRF token → vulnerable") fires on almost every site and
// is hopelessly false-positive-prone: modern browsers default a cookie with NO
// SameSite attribute to SameSite=Lax, which already blocks the cross-site POST a
// classic CSRF relies on, so a tokenless form is usually NOT exploitable.
//
// This probe fires only on the case where that default has been explicitly
// waived: a SESSION cookie set with `SameSite=None`. That cookie IS sent on
// cross-site requests, so if the app also authenticates with it and exposes a
// state-changing form with no anti-CSRF token, an attacker's page can forge that
// request in a victim's authenticated session — textbook CSRF. Two precise
// preconditions (SameSite=None session cookie AND a tokenless POST form), not an
// inference, so it stays clear of the false positives that got inference dropped.
//
// It does not send a forged request — proving CSRF end-to-end would require a
// cross-site state-changing write, which breaks the scanner's non-destructive
// rule. It is reported as a needs-verification (medium-confidence) observation,
// never PROVEN.
import { buildObservationEvidence } from "./evidence.js";

// Anti-CSRF hidden-field names across the common frameworks: generic csrf/xsrf,
// Rails (authenticity_token), Laravel (_token), Django (csrfmiddlewaretoken),
// ASP.NET (__RequestVerificationToken).
const CSRF_FIELD_RE = /csrf|xsrf|authenticity_token|requestverificationtoken|csrfmiddlewaretoken|^_token$/i;

export function formHasAntiCsrfToken(fieldNames: string[]): boolean {
  return (fieldNames || []).some((n) => CSRF_FIELD_RE.test((n || "").trim()));
}

// Strip a cookie's VALUE, keeping its name and attributes — cookie values are
// session secrets and must never be stored or shown.
export function redactCookieValue(setCookieLine: string): string {
  return (setCookieLine || "").replace(/^(\s*[^=;\s]+=)[^;]*/, "$1***");
}

const SESSION_NAME_RE = /sess|token|auth|sid|jwt|login|sso|connect\.sid|phpsessid|jsessionid|asp\.net_sessionid|_session/i;

// The name of a session cookie that has explicitly set SameSite=None (waiving the
// browser's Lax default), or null if none. Analytics/preference cookies are
// ignored — only a cookie that looks like it carries authentication matters for
// CSRF.
export function sessionCookieSameSiteNone(setCookieLines: string[]): string | null {
  for (const raw of setCookieLines || []) {
    const line = raw || "";
    if (!/;\s*samesite\s*=\s*none/i.test(line)) continue;
    const nameMatch = line.match(/^\s*([^=;\s]+)=/);
    const name = nameMatch ? nameMatch[1] : "";
    if (name && SESSION_NAME_RE.test(name)) return name;
  }
  return null;
}

export interface CsrfForm {
  url: string;
  method: string;
  params: string[];
  discoveredOnPage?: string;
}

// Returns an apiSec-shaped finding when a SameSite=None session cookie coexists
// with a state-changing (POST) form that carries no anti-CSRF token, else null.
export function assessCsrf(setCookieLines: string[], forms: CsrfForm[]): any | null {
  const sessionCookie = sessionCookieSameSiteNone(setCookieLines);
  if (!sessionCookie) return null;

  const exposed = (forms || []).find(
    (f) => (f.method || "").toUpperCase() === "POST" && !formHasAntiCsrfToken(f.params),
  );
  if (!exposed) return null;

  const where = exposed.discoveredOnPage && exposed.discoveredOnPage !== exposed.url
    ? `${exposed.url} (form on ${exposed.discoveredOnPage})`
    : exposed.url;
  const redactedCookie = redactCookieValue(
    (setCookieLines || []).find((l) => new RegExp(`^\\s*${sessionCookie}=`).test(l || "")) || `${sessionCookie}=***; SameSite=None`,
  );

  const evidence = buildObservationEvidence({
    url: exposed.url,
    reqMethod: "POST",
    requestHeaders: {},
    responseStatus: 200,
    responseHeaders: { "set-cookie": redactedCookie },
    extraResponseLine: `(form fields: ${exposed.params.join(", ") || "none"} — no anti-CSRF token among them)`,
    why: `The session cookie "${sessionCookie}" is set with SameSite=None, so browsers send it on cross-site requests; the state-changing form at ${where} carries no anti-CSRF token, so a cross-site POST would be accepted in the victim's authenticated session.`,
    demonstration: `An attacker page could auto-submit a POST to ${exposed.url}; because "${sessionCookie}" is SameSite=None it rides along, and with no CSRF token to check, the forged state-changing request succeeds.`,
  });

  return {
    testName: "Cross-Site Request Forgery (CSRF) Exposure — SameSite=None session, tokenless form",
    severity: "medium",
    confidence: "medium", // inferred from posture; not exploited end-to-end
    description: `The session cookie "${sessionCookie}" is set with SameSite=None (waiving the browser's default cross-site protection) and the state-changing form at ${where} has no anti-CSRF token. Together these leave the endpoint open to Cross-Site Request Forgery: a page the victim visits could forge this request in their authenticated session. This is a posture inference (the SameSite=None cookie plus a tokenless POST form), not an executed exploit — confirm by attempting a cross-site submission.`,
    fix: `Either restore SameSite protection on the "${sessionCookie}" cookie (set SameSite=Lax or Strict unless a genuine cross-site need requires None) OR add a per-session anti-CSRF token to state-changing forms and verify it server-side. Defense in depth applies both.`,
    endpoint: exposed.url,
    evidence,
  };
}
