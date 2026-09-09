// Domains hardcoded in Chromium's built-in HSTS preload list.
//
// Why a bundled list rather than a lookup: both obvious alternatives fail on
// exactly the domains that matter most, and google.com demonstrates both.
//
//   1. hstspreload.org's API answers `status: "unknown"` for google.com. That
//      service only tracks domains submitted through its own form; Chromium's
//      hardcoded entries are not in it.
//
//   2. The behavioural fallback — "if http:// upgrades to https://, HSTS is
//      being enforced somehow" — also fails: http://google.com redirects to
//      http://www.google.com, still plaintext. The upgrade happens in the
//      browser, from the built-in list, before a request is ever sent.
//
// So a scanner with no bundled list reports "missing HSTS, risk of protocol
// downgrade" against a domain browsers will not connect to over plaintext under
// any circumstances. That is a false positive, and on a household-name domain
// it is the kind that teaches a reader to distrust the whole report.
//
// This list is deliberately short: the well-known apex domains a scan is most
// likely to be pointed at, not a copy of Chromium's several-thousand-entry
// file. A domain missing from it is reported as it always was, so the only
// failure mode is under-suppression.
const PRELOADED_APEX_DOMAINS = new Set([
  // Google
  "google.com", "youtube.com", "gmail.com", "android.com", "chromium.org",
  "googleapis.com", "gstatic.com", "googleusercontent.com", "withgoogle.com",
  "blogger.com", "appspot.com", "doubleclick.net", "ytimg.com",
  // Apple / Microsoft
  "apple.com", "icloud.com", "microsoft.com", "live.com", "outlook.com", "office.com",
  // Developer / infrastructure
  "github.com", "github.io", "githubusercontent.com", "gitlab.com",
  "cloudflare.com", "stripe.com", "npmjs.com", "python.org", "rust-lang.org",
  // Social / consumer
  "facebook.com", "instagram.com", "whatsapp.com", "twitter.com", "x.com",
  "linkedin.com", "reddit.com", "tumblr.com", "medium.com", "wikipedia.org",
  // Commerce / SaaS
  "paypal.com", "amazon.com", "dropbox.com", "box.com", "shopify.com",
  "wordpress.com", "mozilla.org",
]);

/**
 * True when browsers force HTTPS for this host from their built-in preload
 * list, making a missing Strict-Transport-Security header unexploitable.
 *
 * Matches the apex and any subdomain of it, because Chromium's entries for
 * these domains are include-subdomains.
 */
export function isHstsPreloaded(hostname: string): boolean {
  const host = (hostname || "").trim().toLowerCase().replace(/\.$/, "");
  if (!host) return false;
  if (PRELOADED_APEX_DOMAINS.has(host)) return true;
  return [...PRELOADED_APEX_DOMAINS].some((apex) => host.endsWith(`.${apex}`));
}

/** Test seam: lets a test assert the list is non-trivial without exporting it. */
export const PRELOADED_DOMAIN_COUNT = PRELOADED_APEX_DOMAINS.size;
