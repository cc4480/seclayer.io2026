// Curated common-parameter wordlist for parameter MINING. Modern SPAs/JSON APIs
// ship an almost-empty HTML shell and load data via bundled-JS fetch() calls, so
// the static crawler discovers few or no query parameters — leaving the injection
// probes with nothing to aim at. When that happens we guess these high-signal
// parameter names and keep the ones the target actually processes (see
// server/paramMiner.ts), so injection testing reaches a real surface anyway.
//
// Kept deliberately focused (not a 2000-word brute list): every name here is one
// commonly bound to a database lookup, a filesystem path, a redirect target, or a
// reflected search — i.e. the parameters most likely to be injectable — so mining
// stays cheap and high-yield.

// Names always injection-tested against a candidate endpoint even if mining did
// not observe them reflected — the highest-probability injection sinks, where a
// blind (non-reflecting) vulnerability is common enough to justify the probes.
export const ALWAYS_TEST_PARAMS: string[] = [
  "id", "q", "search", "page", "file", "url", "user", "name", "category", "sort",
];

// The broader mining candidate set (includes ALWAYS_TEST_PARAMS). Reflected hits
// among these are promoted to full injection targets.
export const COMMON_PARAMS: string[] = [
  // Object identifiers → SQLi / IDOR
  "id", "uid", "user_id", "userid", "pid", "oid", "item", "item_id", "product",
  "product_id", "order", "order_id", "account", "record", "row", "num", "no", "ref",
  // Search / free text → reflected XSS / SQLi
  "q", "s", "search", "query", "term", "keyword", "name", "title", "comment",
  "message", "msg", "text", "content", "body", "description", "desc", "subject",
  "label", "note", "tag",
  // Listing controls → SQLi (ORDER BY / LIMIT)
  "sort", "order", "orderby", "order_by", "filter", "category", "cat", "type",
  "field", "column", "page", "offset", "limit",
  // Filesystem → LFI / path traversal
  "file", "path", "dir", "folder", "doc", "document", "template", "view",
  "include", "download", "load", "read", "img", "image",
  // URL sinks → SSRF / open redirect
  "url", "uri", "link", "redirect", "redirect_uri", "return", "returnurl",
  "return_url", "next", "dest", "destination", "continue", "callback", "goto",
  "out", "target", "domain", "host", "site", "feed", "data",
  // Misc
  "lang", "locale", "debug", "action", "mode", "format", "email", "user", "username",
];
