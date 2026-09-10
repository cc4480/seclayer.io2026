# Scan results

Passive scans of 37 sites, captured 2026-09-10. That the engine still detects real vulnerabilities is shown separately by `scripts/detection-check.ts`, because an engine that reports nothing would also produce a clean-looking page like this one.

Passive means HTTP GETs and DNS lookups against publicly served pages. No authentication was attempted, no parameters were manipulated, and no state was altered on any site. Every finding below can be reproduced with `curl` or `dig`.

**186 findings across 37 sites, 92 of them above Info.** 0 critical, 0 high, 79 medium, 13 low, 94 info.

Not reached, and therefore not included:

- `https://letsencrypt.org` — Unable to connect to https://letsencrypt.org: fetch failed

## Read this before comparing sites

4 of these sites answered with a bot-protection interstitial rather than their own page: `ebay.com`, `etsy.com`, `reuters.com`, `stackoverflow.com`. Every check that reads the response would have described that challenge page rather than the site, so those findings are withheld. **That is suppressed coverage, not a clean result** — it means their page was never seen, and their scores reflect only what could still be observed. Their counts are not comparable with the rest.

## Every site

| Site | Score | Grade | Findings | Actionable | Critical | High | Medium | Low | Info | Detail |
|---|---:|:--:|---:|---:|---:|---:|---:|---:|---:|---|
| amazon.co.uk | 40 | F | 9 | 6 | 0 | 0 | 6 | 0 | 3 | [detail](scans/amazon.co.uk.md) |
| apnews.com | 78 | C | 6 | 3 | 0 | 0 | 3 | 0 | 3 | [detail](scans/apnews.com.md) |
| apple.com | 85 | B | 5 | 2 | 0 | 0 | 2 | 0 | 3 | [detail](scans/apple.com.md) |
| archive.org | 80 | B | 5 | 3 | 0 | 0 | 2 | 1 | 2 | [detail](scans/archive.org.md) |
| bbc.co.uk | 100 | A | 3 | 0 | 0 | 0 | 0 | 0 | 3 | [detail](scans/bbc.co.uk.md) |
| cloudflare.com | 65 | D | 7 | 5 | 0 | 0 | 1 | 4 | 2 | [detail](scans/cloudflare.com.md) |
| digitalocean.com | 85 | B | 5 | 2 | 0 | 0 | 2 | 0 | 3 | [detail](scans/digitalocean.com.md) |
| dropbox.com | 100 | A | 3 | 0 | 0 | 0 | 0 | 0 | 3 | [detail](scans/dropbox.com.md) |
| ebay.com * | 100 | A | 2 | 0 | 0 | 0 | 0 | 0 | 2 | [detail](scans/ebay.com.md) |
| etsy.com * | 100 | A | 2 | 0 | 0 | 0 | 0 | 0 | 2 | [detail](scans/etsy.com.md) |
| european-union.europa.eu | 93 | A | 3 | 1 | 0 | 0 | 1 | 0 | 2 | [detail](scans/european-union.europa.eu.md) |
| fastly.com | 73 | C | 7 | 4 | 0 | 0 | 3 | 1 | 3 | [detail](scans/fastly.com.md) |
| figma.com | 100 | A | 2 | 0 | 0 | 0 | 0 | 0 | 2 | [detail](scans/figma.com.md) |
| github.com | 73 | C | 6 | 3 | 0 | 0 | 2 | 1 | 3 | [detail](scans/github.com.md) |
| gitlab.com | 78 | C | 5 | 3 | 0 | 0 | 3 | 0 | 2 | [detail](scans/gitlab.com.md) |
| google.com | 80 | B | 6 | 3 | 0 | 0 | 2 | 1 | 3 | [detail](scans/google.com.md) |
| gov.uk | 100 | A | 3 | 0 | 0 | 0 | 0 | 0 | 3 | [detail](scans/gov.uk.md) |
| linkedin.com | 85 | B | 3 | 1 | 0 | 0 | 1 | 0 | 2 | [detail](scans/linkedin.com.md) |
| mapbox.com | 100 | A | 2 | 0 | 0 | 0 | 0 | 0 | 2 | [detail](scans/mapbox.com.md) |
| microsoft.com | 60 | D | 8 | 6 | 0 | 0 | 6 | 0 | 2 | [detail](scans/microsoft.com.md) |
| mozilla.org | 100 | A | 3 | 0 | 0 | 0 | 0 | 0 | 3 | [detail](scans/mozilla.org.md) |
| nasa.gov | 85 | B | 5 | 2 | 0 | 0 | 2 | 0 | 3 | [detail](scans/nasa.gov.md) |
| netlify.com | 73 | C | 7 | 4 | 0 | 0 | 3 | 1 | 3 | [detail](scans/netlify.com.md) |
| notion.so | 63 | D | 8 | 5 | 0 | 0 | 5 | 0 | 3 | [detail](scans/notion.so.md) |
| npmjs.com | 100 | A | 2 | 0 | 0 | 0 | 0 | 0 | 2 | [detail](scans/npmjs.com.md) |
| nytimes.com | 48 | F | 9 | 6 | 0 | 0 | 6 | 0 | 3 | [detail](scans/nytimes.com.md) |
| paypal.com | 93 | A | 3 | 1 | 0 | 0 | 1 | 0 | 2 | [detail](scans/paypal.com.md) |
| reddit.com | 68 | D | 7 | 4 | 0 | 0 | 2 | 2 | 3 | [detail](scans/reddit.com.md) |
| reuters.com * | 100 | A | 2 | 0 | 0 | 0 | 0 | 0 | 2 | [detail](scans/reuters.com.md) |
| shopify.com | 78 | C | 5 | 3 | 0 | 0 | 3 | 0 | 2 | [detail](scans/shopify.com.md) |
| slack.com | 63 | D | 8 | 5 | 0 | 0 | 5 | 0 | 3 | [detail](scans/slack.com.md) |
| stackoverflow.com * | 100 | A | 2 | 0 | 0 | 0 | 0 | 0 | 2 | [detail](scans/stackoverflow.com.md) |
| stripe.com | 93 | A | 4 | 1 | 0 | 0 | 1 | 0 | 3 | [detail](scans/stripe.com.md) |
| theguardian.com | 70 | C | 6 | 4 | 0 | 0 | 4 | 0 | 2 | [detail](scans/theguardian.com.md) |
| vercel.com | 75 | C | 7 | 4 | 0 | 0 | 2 | 2 | 3 | [detail](scans/vercel.com.md) |
| wikipedia.org | 63 | D | 8 | 5 | 0 | 0 | 5 | 0 | 3 | [detail](scans/wikipedia.org.md) |
| zoom.us | 60 | D | 8 | 6 | 0 | 0 | 6 | 0 | 2 | [detail](scans/zoom.us.md) |

`*` answered with a bot-protection interstitial; see above.

**Grades, over the 33 sites actually reached:** A 10 · B 6 · C 8 · D 7 · F 2 — mean score 79.0.

**Higher is better.** 100 is clean; only critical/high/medium/low deduct, so a site whose findings are all info notices scores a true 100. Grade is `gradeForScore`: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F below.

> SecScan runs the opposite scale (0 = clean, A ≤ 10). The two numbers are not comparable in either direction.

## What came up most often

Across the 33 sites whose own pages were seen.

| Finding | Severity | Sites | OWASP |
|---|---|---:|---|
| Active Exploit Probing Skipped (Unverified Target) | Info | 33/33 | A05:2021 – Security Misconfiguration |
| Verbose Server Framework Signature Leaked | Info | 21/33 | A05:2021 – Security Misconfiguration |
| Missing X-Content-Type-Options (MIME Sniffing) | Medium | 12/33 | A05:2021 – Security Misconfiguration |
| Missing Content-Security-Policy (CSP) | Medium | 10/33 | A05:2021 – Security Misconfiguration |
| Missing X-Frame-Options / Clickjacking Immunity | Medium | 7/33 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 3 endpoints) | Info | 4/33 | A05:2021 – Security Misconfiguration |
| OpenAPI/Swagger Spec Exposed | Low | 3/33 | A05:2021 – Security Misconfiguration |
| GraphiQL / GraphQL Playground Exposed | Low | 3/33 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 2 endpoints) | Info | 3/33 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 1 endpoints) | Info | 3/33 | A05:2021 – Security Misconfiguration |
| Kibana Instance Exposed | Medium | 2/33 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 9 endpoints) | Info | 2/33 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 28 endpoints) | Info | 2/33 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 5 endpoints) | Info | 2/33 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 6 endpoints) | Info | 2/33 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (1 pages, 1 endpoints) | Info | 2/33 | A05:2021 – Security Misconfiguration |
| Cookie "i18n-prefs" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "i18n-prefs" is set without the Secure attribute over HTTPS | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "lc-acbuk" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "lc-acbuk" is set without the Secure attribute over HTTPS | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "session-id-time" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "session-id" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "kameleoonVisitorCode" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "kameleoonVisitorCode" is set without the Secure attribute over HTTPS | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "geo" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "geo" is set without the Secure attribute over HTTPS | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "kndctr_8AD56F28618A50850A495FB6_AdobeOrg_identity" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Missing Strict-Transport-Security (HSTS) Policy | Medium | 1/33 | A02:2021 – Cryptographic Failures |
| Cookie "_fs_ch_st_FSBmUei20MqUiJb9" is set without the Secure attribute over HTTPS | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "ff_revamp" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "_octo" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| phpMyAdmin Panel Exposed | Medium | 1/33 | A01:2021 – Broken Access Control |
| Cookie "__Secure-STRP" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "JSESSIONID" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "bStore" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "bStore" is set without the Secure attribute over HTTPS | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "CAS_PROGRAM" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "notion_browser_id" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "notion_browser_id" is set without the Secure attribute over HTTPS | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "notion_check_cookie_consent" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "notion_check_cookie_consent" is set without the Secure attribute over HTTPS | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "nyt-a" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "nyt-gdpr" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "nyt-gdpr" is set without the Secure attribute over HTTPS | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "nyt-geo" is set without the Secure attribute over HTTPS | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "nyt-purr" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "ts_c" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "edgebucket" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "_shopify_essential_" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "b" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "utm" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "x" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "cid" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "gu_client_ab_tests" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "gu_client_ab_tests" is set without the Secure attribute over HTTPS | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "gu_v2_mvt_id" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "gu_v2_mvt_id" is set without the Secure attribute over HTTPS | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "_v-anonymous-id-renewed" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "_v-anonymous-id" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "GeoIP" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "NetworkProbeLimit" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "_zm_billing_visitor_guid" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "_zm_mtk_guid" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Cookie "_zm_visitor_guid" is set without the HttpOnly attribute | Medium | 1/33 | A05:2021 – Security Misconfiguration |
| Exposed JavaScript source map (/offshoot_assets/vendor/lit/polyfill-support.js.map) | Low | 1/33 | A05:2021 – Security Misconfiguration |
| Exposed JavaScript source map (/_connect/Globe.astro_astro_type_script_index_0_lang.C9vJTI-3.js.map) | Low | 1/33 | A05:2021 – Security Misconfiguration |
| Exposed JavaScript source map (/_connect/Hero.astro_astro_type_script_index_0_lang.BBNztvks.js.map) | Low | 1/33 | A05:2021 – Security Misconfiguration |
| Exposed JavaScript source map (/_connect/page.V2R8AmkL.js.map) | Low | 1/33 | A05:2021 – Security Misconfiguration |
| Exposed JavaScript source map (/_astro/page.sxlF4EnU.js.map) | Low | 1/33 | A05:2021 – Security Misconfiguration |
| Content-Security-Policy is report-only (not enforced) | Low | 1/33 | A05:2021 – Security Misconfiguration |
| Swagger UI Exposed | Low | 1/33 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 231 endpoints) | Info | 1/33 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 0 endpoints) | Info | 1/33 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 47 endpoints) | Info | 1/33 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (9 pages, 131 endpoints) | Info | 1/33 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 246 endpoints) | Info | 1/33 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (4 pages, 40 endpoints) | Info | 1/33 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 11 endpoints) | Info | 1/33 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 12 endpoints) | Info | 1/33 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 94 endpoints) | Info | 1/33 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 633 endpoints) | Info | 1/33 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 7 endpoints) | Info | 1/33 | A05:2021 – Security Misconfiguration |
| Application Surface Mapped (10 pages, 4 endpoints) | Info | 1/33 | A05:2021 – Security Misconfiguration |

