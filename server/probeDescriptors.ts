// Human-readable metadata for each active probe, used to narrate the live scan
// ticker. Keyed by the probe function's name (Function.prototype.name), so the
// orchestrators (redTeamProbes.ts, aggressiveProbes.ts) can emit a "firing" line
// naming the technique + the real payload it sends and a one-line "why", without
// every probe module having to know about the event bus. This built-in "why" is
// also what keeps the ticker fully explanatory when DeepSeek Flash is
// unavailable — the AI prose is layered on top of these, never required.
import type { EmitFn } from "./scanEvents.js";
import type { RedTeamFinding } from "./scanTypes.js";

export interface ProbeDescriptor {
  label: string; // e.g. "SQL injection"
  payload: string; // a representative payload, matching what the probe actually fires
  why: string; // one line: what this test is checking for
}

export const PROBE_DESCRIPTORS: Record<string, ProbeDescriptor> = {
  // --- Red-team tier ---
  probeSqlInjection: {
    label: "SQL injection",
    payload: "?id=' OR 1=1--",
    why: "checking whether input reaches the SQL engine unescaped (raw DB error = injectable)",
  },
  probeReflectedXss: {
    label: "Reflected XSS",
    payload: "?q=<script>…</script>",
    why: "checking whether input is reflected into the page unescaped and would execute",
  },
  probeCommandInjection: {
    label: "OS command injection",
    payload: "?ping=127.0.0.1; id",
    why: "checking whether input is passed to a shell (arithmetic/`id` oracle)",
  },
  probeSsrf: {
    label: "SSRF",
    payload: "?url=http://127.0.0.1:22",
    why: "checking whether the server fetches attacker-supplied URLs to internal hosts",
  },
  probeBlindSsrf: {
    label: "Blind SSRF (out-of-band)",
    payload: "?url=http://<collaborator>/<token>",
    why: "injecting an out-of-band callback URL to catch blind server-side fetches",
  },
  // --- Aggressive tier ---
  probeSsti: {
    label: "Server-side template injection",
    payload: "?name={{7*7}}",
    why: "checking whether a template engine evaluates injected expressions (arithmetic oracle)",
  },
  probePathTraversal: {
    label: "Path traversal / LFI",
    payload: "?file=../../../../etc/passwd",
    why: "checking whether path input escapes the web root to read local files",
  },
  probeOpenRedirect: {
    label: "Open redirect",
    payload: "?next=//evil.example/",
    why: "checking whether a redirect target is taken from user input without validation",
  },
  probeCrlf: {
    label: "CRLF / header injection",
    payload: "?lang=en%0d%0aSet-Cookie:x",
    why: "checking whether CR/LF in input injects new HTTP response headers",
  },
  probeCors: {
    label: "CORS misconfiguration",
    payload: "Origin: https://evil.example",
    why: "checking whether the app reflects any Origin with credentials allowed",
  },
  probeXxe: {
    label: "XML external entity (out-of-band)",
    payload: "<!ENTITY x SYSTEM \"http://<collaborator>\">",
    why: "checking whether the XML parser resolves external entities to our collaborator",
  },
  probeNoSql: {
    label: "NoSQL injection",
    payload: '{"username":{"$ne":null}}',
    why: "checking whether an operator object bypasses authentication",
  },
  probeHostHeaderInjection: {
    label: "Host-header injection",
    payload: "Host: evil.example",
    why: "checking whether a spoofed Host header is reflected into links/redirects",
  },
};

// Emit the "firing" line for a probe about to run.
export function emitProbeFiring(emit: EmitFn | undefined, desc?: ProbeDescriptor): void {
  if (!emit || !desc) return;
  emit("probe", `→ ${desc.label}: firing ${desc.payload} — ${desc.why}`);
}

// Emit the outcome line once a probe resolves: a confirmed exploit (with the
// real payload from the receipt) or a clean "resisted" line.
export function emitProbeResult(
  emit: EmitFn | undefined,
  desc: ProbeDescriptor | undefined,
  finding: RedTeamFinding | null,
): void {
  if (!emit) return;
  if (finding) {
    emit(
      "result",
      `✓ CONFIRMED: ${finding.testName} [${finding.severity.toUpperCase()}] — payload: ${finding.payload}`,
    );
  } else if (desc) {
    emit("probe", `· ${desc.label}: no signal — target resisted`);
  }
}
