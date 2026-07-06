// Lightweight tech-stack fingerprinting from the root response (headers, cookies,
// HTML). Drives template gating so framework-specific checks only run on the
// relevant stack. Detection deliberately leans toward over-detecting (recall):
// running a few extra templates is cheaper than missing a real exposure.

export function detectTechTags(headers: Record<string, string>, html: string): Set<string> {
  const tags = new Set<string>();
  const h = Object.entries(headers || {})
    .map(([k, v]) => `${k}: ${v}`)
    .join("\n")
    .toLowerCase();
  const cookie = (headers?.["set-cookie"] || "").toLowerCase();
  const body = (html || "").toLowerCase();
  const hay = h + "\n" + body;
  const add = (...t: string[]) => t.forEach((x) => tags.add(x));

  // PHP
  if (/x-powered-by:\s*php|phpsessid/.test(h) || cookie.includes("phpsessid") || /\.php(["'?\s/]|$)/.test(body)) {
    add("php");
  }
  // WordPress (implies PHP)
  if (/wp-content|wp-includes|wp-json|wp-emoji|content=["']wordpress/.test(body)) add("wordpress", "php");
  // Laravel (implies PHP)
  if (cookie.includes("laravel_session") || cookie.includes("xsrf-token") || /laravel/.test(body)) add("laravel", "php");
  // Symfony (implies PHP)
  if (h.includes("x-debug-token") || /\bsf_redirect\b|symfony/.test(hay)) add("symfony", "php");
  // Joomla (implies PHP)
  if (/joomla|\/media\/jui\/|com_content|\/media\/system\/js/.test(body)) add("joomla", "php");
  // Drupal (implies PHP)
  if (/drupal|sites\/default\/files|x-generator:\s*drupal/.test(hay)) add("drupal", "php");
  // Ruby on Rails
  if (cookie.includes("_session_id") || /csrf-param|x-powered-by:\s*phusion/.test(hay)) add("rails");
  // Java / servlet containers
  if (cookie.includes("jsessionid") || /server:.*(tomcat|coyote|jetty|wildfly|glassfish)/.test(h)) add("java");
  if (/server:.*(coyote|tomcat)/.test(h)) add("tomcat", "java");
  // Spring (implies Java)
  if (/x-application-context|spring/.test(hay)) add("spring", "java");
  // ASP.NET / IIS
  if (/x-aspnet-version|x-powered-by:\s*asp\.net|server:.*microsoft-iis/.test(h)) add("aspnet");
  // Node / Express
  if (/x-powered-by:\s*express/.test(h)) add("node");

  return tags;
}
