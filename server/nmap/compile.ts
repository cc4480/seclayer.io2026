// Maps the internal NmapParsedResult (raw off the XML parser) to the
// persisted NmapResult (src/types.ts) — mirrors how scanner.ts's
// compileScanEvidence/compileStaticFindings turn DiagnosticResult into the
// persisted ScanEvidence/Finding[].
import type { NmapParsedResult } from "../nmapTypes.js";
import type { NmapResult, NmapPort, NmapVulnFinding } from "../../src/types.js";
import { classifyNmapScriptOutput } from "./classify.js";

export interface CompileNmapResultContext {
  targetHost: string;
  resolvedIp: string;
  nmapVersion: string;
  durationMs: number;
  scanArgs: string[];
}

const VALID_PROTOCOLS = new Set(["tcp", "udp"]);

export function compileNmapResult(parsed: NmapParsedResult, ctx: CompileNmapResultContext): NmapResult {
  const ports: NmapPort[] = parsed.ports.map((p) => ({
    port: p.portid,
    protocol: VALID_PROTOCOLS.has(p.protocol) ? (p.protocol as "tcp" | "udp") : "tcp",
    state: p.state,
    service: p.service?.name,
    product: p.service?.product,
    version: p.service?.version,
    extraInfo: p.service?.extrainfo,
    scripts: p.scripts,
  }));

  // Every entry here is a `--script vuln` result (that's the only NSE category
  // this scan ever requests — see nmap/args.ts), but that only means the
  // script RAN — not that it found anything. classifyNmapScriptOutput reads
  // each script's own output text to tell a real hit apart from an explicit
  // negative result or a script error/timeout (see its doc comment). A
  // 'finding' outcome is always DETECTED, never PROVEN (banner/version-
  // matched, not a replayable exploit receipt). Never synthesized into an
  // ExploitEvidence or Finding — this type has no path into the AppSec
  // posture score.
  const vulnFindings: NmapVulnFinding[] = [];
  for (const p of parsed.ports) {
    for (const s of p.scripts) {
      vulnFindings.push({ port: p.portid, scriptId: s.id, output: s.output, outcome: classifyNmapScriptOutput(s.output) });
    }
  }
  for (const s of parsed.hostScripts) {
    vulnFindings.push({ scriptId: s.id, output: s.output, outcome: classifyNmapScriptOutput(s.output) });
  }

  return {
    scannedAt: new Date().toISOString(),
    targetHost: ctx.targetHost,
    resolvedIp: ctx.resolvedIp,
    state: parsed.state,
    ports,
    osMatches: parsed.osMatches,
    vulnFindings,
    nmapVersion: ctx.nmapVersion,
    scanArgs: ctx.scanArgs,
    durationMs: ctx.durationMs,
  };
}
