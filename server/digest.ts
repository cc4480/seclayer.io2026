// Weekly monitoring digest email. Pure builder: given each monitored target's
// latest (and previous) completed scan, it produces the subject + text/html
// bodies summarizing current posture and what changed. Kept separate from the
// worker that fetches the data and sends the mail, so the formatting is unit
// tested without a database or an email transport. Isomorphic-style: imports
// only shared scoring/diff modules, exactly like scanDiff.ts.
import { Scan } from "../src/types.js";
import { deriveSecurityPosture } from "./scoring.js";
import { diffFindings } from "./scanDiff.js";

export interface DigestInput {
  url: string;
  latest?: Scan;   // most recent completed scan of this target
  previous?: Scan; // the one before it (for the change counts)
}

export interface DigestRow {
  url: string;
  hasData: boolean;
  score?: number;
  grade?: string;
  severity?: string;
  newCount: number;
  fixedCount: number;
  scannedAt?: string;
}

export interface Digest {
  subject: string;
  text: string;
  html: string;
  rows: DigestRow[];
}

function rowFor({ url, latest, previous }: DigestInput): DigestRow {
  if (!latest || latest.status !== "complete") {
    return { url, hasData: false, newCount: 0, fixedCount: 0 };
  }
  const posture = deriveSecurityPosture(latest.findings || []);
  const diff = previous ? diffFindings(latest.findings, previous.findings) : null;
  return {
    url,
    hasData: true,
    score: posture.score,
    grade: posture.grade,
    severity: posture.severity,
    newCount: diff?.newFindings.length ?? 0,
    fixedCount: diff?.fixedFindings.length ?? 0,
    scannedAt: latest.completedAt,
  };
}

// Builds the digest, or null when there are no targets to report on.
export function buildDigest(inputs: DigestInput[], appUrl = "https://seclayerio.ai"): Digest | null {
  if (!inputs.length) return null;

  const rows = inputs.map(rowFor);
  const withData = rows.filter((r) => r.hasData);
  const totalNew = withData.reduce((n, r) => n + r.newCount, 0);
  const totalFixed = withData.reduce((n, r) => n + r.fixedCount, 0);

  const subject =
    `Seclayer monitoring digest — ${inputs.length} target${inputs.length === 1 ? "" : "s"}` +
    (totalNew > 0 ? `, ${totalNew} new finding${totalNew === 1 ? "" : "s"}` : "");

  // --- plain text ---
  const textLines: string[] = [];
  textLines.push(`Seclayer monitoring digest`);
  textLines.push(`${inputs.length} monitored target(s) · ${totalNew} new · ${totalFixed} resolved since last scan`);
  textLines.push("");
  for (const r of rows) {
    if (!r.hasData) {
      textLines.push(`• ${r.url} — no completed scan yet`);
      continue;
    }
    const change = r.newCount || r.fixedCount ? ` (${r.newCount} new, ${r.fixedCount} resolved)` : "";
    textLines.push(`• ${r.url} — score ${r.score}/100 (${r.grade}, ${String(r.severity).toUpperCase()})${change}`);
  }
  textLines.push("");
  textLines.push(`Manage your monitors: ${appUrl}`);
  const text = textLines.join("\n");

  // --- html ---
  const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const rowsHtml = rows
    .map((r) => {
      if (!r.hasData) {
        return `<tr><td style="padding:8px;border-bottom:1px solid #27272a;color:#a1a1aa">${esc(r.url)}</td><td colspan="2" style="padding:8px;border-bottom:1px solid #27272a;color:#71717a">No completed scan yet</td></tr>`;
      }
      const change = r.newCount || r.fixedCount
        ? `<span style="color:#f87171">${r.newCount} new</span> · <span style="color:#22c55e">${r.fixedCount} resolved</span>`
        : `<span style="color:#71717a">no change</span>`;
      return `<tr><td style="padding:8px;border-bottom:1px solid #27272a;color:#fff">${esc(r.url)}</td><td style="padding:8px;border-bottom:1px solid #27272a;color:#fff"><strong>${r.score}/100</strong> ${r.grade} · ${String(r.severity).toUpperCase()}</td><td style="padding:8px;border-bottom:1px solid #27272a">${change}</td></tr>`;
    })
    .join("");
  const html = `<div style="font-family:system-ui,sans-serif;background:#09090b;color:#e4e4e7;padding:24px">
  <h2 style="color:#fff;margin:0 0 4px">Seclayer monitoring digest</h2>
  <p style="color:#a1a1aa;margin:0 0 16px">${inputs.length} monitored target(s) · ${totalNew} new · ${totalFixed} resolved since last scan</p>
  <table style="width:100%;border-collapse:collapse;font-size:14px"><tbody>${rowsHtml}</tbody></table>
  <p style="margin:16px 0 0"><a href="${appUrl}" style="color:#22c55e">Manage your monitors →</a></p>
</div>`;

  return { subject, text, html, rows };
}
