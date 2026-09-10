/**
 * Renders SCAN-RESULTS.md and scans/<host>.md from a live-scan --json capture.
 * Everything in the output comes from the capture; nothing is transcribed.
 *
 *   node scripts/render-scan-report.mjs run.json out/
 *
 * The score in the capture is the engine's own — scoring.ts produced it during
 * the scan, and this script never recomputes it. The grade thresholds are
 * gradeForScore's, restated here because this is a plain .mjs with no TS loader;
 * if they move there and not here, the tables are wrong.
 *
 * Seclayer's scale is INVERTED relative to SecScan's: 100 is clean here, 0 is
 * clean there. The output says so, because the two products get read together.
 *
 * A scan answered by a bot-protection interstitial keeps its score — the engine
 * already floors it to what could still be observed — but the page says plainly
 * that it is partial coverage rather than a clean result.
 */
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";

const [, , src, outDir] = process.argv;
if (!src || !outDir) {
  console.error("usage: node scripts/render-scan-report.mjs <run.json> <outDir>");
  process.exit(2);
}
const raw = JSON.parse(readFileSync(src, "utf8"));
const SEV = ["critical", "high", "medium", "low", "info"];
const rank = Object.fromEntries(SEV.map((s, i) => [s, i]));

// server/scoring.ts:gradeForScore — higher is better.
const gradeFor = (score) =>
  score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";

const INTERCEPTED = /intercepted by a bot-protection/i;

const host = (u) => {
  try { return new URL(u).hostname.replace(/^www\./, ""); } catch { return u; }
};
const sev = (s) => s[0].toUpperCase() + s.slice(1);
const esc = (s) => String(s).replace(/\|/g, "\\|").replace(/\n/g, " ");
const slug = (h) => h.replace(/[^a-z0-9.-]/gi, "_");

const sites = raw.results
  .filter((r) => !r.failed)
  .map((r) => {
    const findings = r.findings ?? [];
    return {
      host: host(r.url),
      url: r.url,
      finalUrl: r.finalUrl,
      status: r.responseStatus,
      elapsedMs: r.elapsedMs,
      intercepted: findings.some((f) => INTERCEPTED.test(f.title)),
      score: r.score,
      grade: gradeFor(r.score),
      findings: [...findings].sort(
        (a, b) => rank[a.severity] - rank[b.severity] || a.title.localeCompare(b.title),
      ),
      counts: Object.fromEntries(SEV.map((s) => [s, findings.filter((f) => f.severity === s).length])),
      actionable: findings.filter((f) => f.severity !== "info").length,
    };
  })
  .sort((a, b) => a.host.localeCompare(b.host));

const failed = raw.results.filter((r) => r.failed);
const total = sites.reduce((a, s) => a + s.findings.length, 0);
const actionable = sites.reduce((a, s) => a + s.actionable, 0);
const bySev = Object.fromEntries(SEV.map((s) => [s, sites.reduce((a, x) => a + x.counts[s], 0)]));

mkdirSync(join(outDir, "scans"), { recursive: true });

const out = [];
out.push("# Scan results");
out.push("");
out.push(
  `Passive scans of ${sites.length} sites, captured ${new Date(raw.scannedAt).toISOString().slice(0, 10)}. ` +
  "That the engine still detects real vulnerabilities is shown separately by " +
  "`scripts/detection-check.ts`, because an engine that reports nothing would " +
  "also produce a clean-looking page like this one.",
);
out.push("");
out.push(
  "Passive means HTTP GETs and DNS lookups against publicly served pages. No " +
  "authentication was attempted, no parameters were manipulated, and no state " +
  "was altered on any site. Every finding below can be reproduced with `curl` " +
  "or `dig`.",
);
out.push("");
out.push(
  `**${total} findings across ${sites.length} sites, ${actionable} of them above Info.** ` +
  SEV.map((s) => `${bySev[s]} ${s}`).join(", ") + ".",
);
out.push("");

if (failed.length) {
  out.push("Not reached, and therefore not included:");
  out.push("");
  for (const f of failed) out.push(`- \`${f.url}\` — ${f.failed}`);
  out.push("");
}

const interceptedSites = sites.filter((s) => s.intercepted);
if (interceptedSites.length) {
  out.push("## Read this before comparing sites");
  out.push("");
  out.push(
    `${interceptedSites.length} of these sites answered with a bot-protection interstitial rather than ` +
    "their own page: " + interceptedSites.map((s) => `\`${s.host}\``).join(", ") + ". " +
    "Every check that reads the response would have described that challenge " +
    "page rather than the site, so those findings are withheld. " +
    "**That is suppressed coverage, not a clean result** — it means their page " +
    "was never seen, and their scores reflect only what could still be observed. " +
    "Their counts are not comparable with the rest.",
  );
  out.push("");
}

out.push("## Every site");
out.push("");
out.push("| Site | Score | Grade | Findings | Actionable | Critical | High | Medium | Low | Info | Detail |");
out.push("|---|---:|:--:|---:|---:|---:|---:|---:|---:|---:|---|");
for (const s of sites) {
  const note = s.intercepted ? " *" : "";
  out.push(
    `| ${s.host}${note} | ${s.score} | ${s.grade} | ${s.findings.length} | ${s.actionable} | ` +
    `${s.counts.critical} | ${s.counts.high} | ${s.counts.medium} | ${s.counts.low} | ` +
    `${s.counts.info} | [detail](scans/${slug(s.host)}.md) |`,
  );
}
out.push("");
if (interceptedSites.length) out.push("`*` answered with a bot-protection interstitial; see above.");
out.push("");
{
  const seen = sites.filter((s) => !s.intercepted);
  const dist = {};
  for (const s of seen) dist[s.grade] = (dist[s.grade] ?? 0) + 1;
  const mean = seen.length ? (seen.reduce((n, s) => n + s.score, 0) / seen.length).toFixed(1) : "—";
  out.push(
    `**Grades, over the ${seen.length} sites actually reached:** ` +
    ["A", "B", "C", "D", "F"].map((g) => `${g} ${dist[g] ?? 0}`).join(" · ") +
    ` — mean score ${mean}.`,
  );
  out.push("");
  out.push(
    "**Higher is better.** 100 is clean; only critical/high/medium/low deduct, " +
    "so a site whose findings are all info notices scores a true 100. Grade is " +
    "`gradeForScore`: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F below.",
  );
  out.push("");
  out.push(
    "> SecScan runs the opposite scale (0 = clean, A ≤ 10). The two numbers are " +
    "not comparable in either direction.",
  );
}
out.push("");

// ── findings by prevalence ───────────────────────────────────────────────────
const prev = {};
for (const s of sites) {
  if (s.intercepted) continue;
  for (const title of new Set(s.findings.map((f) => f.title))) {
    const f = s.findings.find((x) => x.title === title);
    prev[title] ??= { title, severity: f.severity, owasp: f.owasp, sites: [] };
    prev[title].sites.push(s.host);
  }
}
const fully = sites.filter((s) => !s.intercepted).length;
out.push("## What came up most often");
out.push("");
out.push(`Across the ${fully} sites whose own pages were seen.`);
out.push("");
out.push("| Finding | Severity | Sites | OWASP |");
out.push("|---|---|---:|---|");
for (const p of Object.values(prev).sort(
  (a, b) => b.sites.length - a.sites.length || rank[a.severity] - rank[b.severity],
)) {
  out.push(`| ${esc(p.title)} | ${sev(p.severity)} | ${p.sites.length}/${fully} | ${p.owasp ? esc(p.owasp) : "—"} |`);
}
out.push("");

writeFileSync(join(outDir, "SCAN-RESULTS.md"), out.join("\n") + "\n");

// ── per-site detail ──────────────────────────────────────────────────────────
for (const s of sites) {
  const d = [];
  d.push(`# ${s.host}`);
  d.push("");
  d.push(`- Requested: \`${s.url}\``);
  if (s.finalUrl && s.finalUrl.replace(/\/$/, "") !== s.url.replace(/\/$/, "")) {
    d.push(`- Final URL: \`${s.finalUrl}\``);
  }
  d.push(`- HTTP ${s.status}, ${(s.elapsedMs / 1000).toFixed(1)}s`);
  d.push(`- Score ${s.score}/100 — grade ${s.grade}`);
  d.push(`- ${s.findings.length} findings, ${s.actionable} above Info`);
  if (s.intercepted) {
    d.push("");
    d.push(
      "> This scan was answered by a bot-protection interstitial. Findings read " +
      "from that response are withheld, so this is a partial view — not a clean " +
      "result, and the score reflects only what could still be observed.",
    );
  }
  d.push("");
  if (!s.findings.length) {
    d.push("No findings.");
  } else {
    for (const f of s.findings) {
      d.push(`### ${f.title}`);
      d.push("");
      d.push(
        `**${sev(f.severity)}**` +
        (f.confidence ? ` · ${f.confidence} confidence` : "") +
        (f.owasp ? ` · ${f.owasp}` : "") +
        ` · ${f.category}`,
      );
      d.push("");
      if (f.endpoint) {
        d.push(`\`${f.endpoint}\``);
        d.push("");
      }
      if (f.verification) {
        d.push("```");
        d.push(String(f.verification).trim());
        d.push("```");
        d.push("");
      }
    }
  }
  writeFileSync(join(outDir, "scans", `${slug(s.host)}.md`), d.join("\n") + "\n");
}

console.log(`SCAN-RESULTS.md + ${sites.length} per-site files`);
console.log(`  ${total} findings, ${actionable} actionable, ${bySev.critical} critical, ${bySev.high} high`);
console.log(`  intercepted (partial): ${interceptedSites.map((s) => s.host).join(", ") || "none"}`);
if (failed.length) console.log(`  failed: ${failed.map((f) => f.url).join(", ")}`);
