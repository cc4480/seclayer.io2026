// Maps a finding to its OWASP Top 10 (2021) category. Enables compliance-style
// reporting and lets the UI group/badge findings by the industry-standard
// taxonomy. Heuristic over category + title; order matters (most specific first).

export function mapOwasp(category: string, title: string): string {
  const t = (title || "").toLowerCase();
  const c = (category || "").toUpperCase();

  // A03 — Injection (SQLi, XSS, command injection)
  if (/\b(sql injection|sqli|xss|cross-site scripting|command injection|code injection|template injection|ldap injection)\b/.test(t)) {
    return "A03:2021 – Injection";
  }
  // A10 — Server-Side Request Forgery
  if (/\bssrf\b|server-side request forgery/.test(t)) {
    return "A10:2021 – Server-Side Request Forgery (SSRF)";
  }
  // A01 — Broken Access Control (IDOR/BOLA, directory listing, exposed admin/db panels)
  if (/\b(idor|bola)\b|broken object level|broken access|directory listing|access control|phpmyadmin|adminer|admin panel|unauthorized/.test(t)) {
    return "A01:2021 – Broken Access Control";
  }
  // A08 — Software and Data Integrity Failures (e.g. missing SRI). Checked
  // before A06 so SRI findings (often tagged SCA) aren't swallowed by it.
  if (/subresource integrity|\bsri\b|integrity hash/.test(t)) {
    return "A08:2021 – Software and Data Integrity Failures";
  }
  // A06 — Vulnerable and Outdated Components
  if (c === "SCA" || /outdated library|vulnerable (library|component|dependency)|end-of-life|package\.json/.test(t)) {
    return "A06:2021 – Vulnerable and Outdated Components";
  }
  // A02 — Cryptographic Failures (plaintext transport, exposed secrets/credentials, weak cookies)
  if (
    /plaintext http|insecure connection|cleartext|\bhsts\b|strict-transport|\btls\b|\bssl\b|lacks secure|secure directive|credential|secret|api key|private key|\.env|wp-config|password/.test(t)
  ) {
    return "A02:2021 – Cryptographic Failures";
  }
  // A05 — Security Misconfiguration (missing headers, exposed config/panels/actuators,
  // verbose server banners, clickjacking, debug tooling) — the sensible default.
  return "A05:2021 – Security Misconfiguration";
}
