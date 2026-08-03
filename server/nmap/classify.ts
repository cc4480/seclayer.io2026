// Classifies a single NSE `--script vuln` result's raw output text. nmap
// includes a <script> element for every script that ran against a port/host
// regardless of what it found — a script that explicitly reports "not
// vulnerable", or one that failed to execute or timed out, produces output
// exactly like a real hit structurally. Treating every element as a finding
// (the previous behavior) mislabeled negative results and tooling failures as
// DETECTED security findings — the exact class of false positive this
// product exists not to produce. This reads the script's own conventional
// output text (nmap's XML has no separate structured verdict field to rely
// on instead — see parseXml.ts) to sort each result into what actually
// happened.
import type { NmapScriptOutcome } from "../../src/types.js";

// nmap's own wrapper when an NSE script raises a Lua error, verbatim and
// script-independent — and the two explicit no-response/timeout phrasings
// used by scripts like ssl-ccs-injection when they can't get a probe answer.
const ERROR_PATTERNS = [/^ERROR: Script execution failed/i, /^No reply from server/i, /\(TIMEOUT\)/i];

// vulns.lua's own "couldn't determine" state, used by scripts that share that
// library — a script ran to completion but couldn't establish either verdict.
const INCONCLUSIVE_PATTERNS = [/State:\s*UNKNOWN/i];

// Explicit negative determinations. Checked before the generic "VULNERABLE"
// substring test below so a "State: NOT VULNERABLE" line (vulns.lua) is never
// mistaken for a hit just because it contains the word "VULNERABLE".
const NEGATIVE_PATTERNS = [
  /couldn'?t find any/i,
  /\bnot vulnerable\b/i,
  /no vulnerabilities found/i,
  /appears to be (not vulnerable|patched)/i,
  /^likely not vulnerable/i,
];

export function classifyNmapScriptOutput(output: string): NmapScriptOutcome {
  const text = (output || "").trim();
  if (!text) return "negative";
  if (ERROR_PATTERNS.some((re) => re.test(text))) return "error";
  if (INCONCLUSIVE_PATTERNS.some((re) => re.test(text))) return "inconclusive";
  if (NEGATIVE_PATTERNS.some((re) => re.test(text))) return "negative";
  return "finding";
}
