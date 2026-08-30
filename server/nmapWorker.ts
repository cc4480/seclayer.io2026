// Background worker for one nmap scan's lifecycle — mirrors scanWorker.ts's
// conventions (status guards before every write, live event stream, refund
// handled at the DB layer) adapted for a single long-running process instead
// of many small probes. Unlike scanWorker.ts this needs no injected
// dependency (no OOB collaborator equivalent), so it's a plain exported async
// function rather than a closure factory — a deliberate simplification.
import { db } from "./db.js";
import * as scanEvents from "./scanEvents.js";
import { resolveNmapTarget } from "./nmap/resolve.js";
import { runNmap } from "./nmap/run.js";
import { parseNmapXml } from "./nmap/parseXml.js";
import { compileNmapResult } from "./nmap/compile.js";
import { nmapVersionString } from "./nmap/detect.js";

async function isCanceled(scanId: string): Promise<boolean> {
  return (await db.getNmapScan(scanId))?.status === "canceled";
}

export async function processNmapScanJob(scanId: string): Promise<void> {
  let stream: ReturnType<typeof scanEvents.openStream> | undefined;
  try {
    const scan = (await db.getNmapScan(scanId));
    if (!scan || await isCanceled(scanId)) return;

    stream = scanEvents.openStream(scanId);
    const emit = stream.emit;
    emit("system", `Resolving ${scan.url}…`);

    (await db.updateNmapScan(scanId, { status: "scanning", startedAt: new Date().toISOString() }));

    // Resolved fresh here (not reused from launch time) so a DNS answer that
    // changed between "user clicked launch" and "the worker actually runs"
    // is re-validated — see nmap/resolve.ts's doc comment.
    const { hostname, ip } = await resolveNmapTarget(scan.url);
    if (await isCanceled(scanId)) return;
    (await db.updateNmapScan(scanId, { resolvedIp: ip }));
    emit(
      "system",
      scan.deep
        ? `Resolved ${hostname} → ${ip}. Launching deep nmap scan (all 65535 ports, -sV, -O, --script vuln)…`
        : `Resolved ${hostname} → ${ip}. Launching nmap scan (top 1000 ports, -sV, -O, --script vuln)…`,
    );

    const { xml, durationMs, args } = await runNmap(scanId, ip, emit, undefined, scan.deep);
    if (await isCanceled(scanId)) return; // discard a result that arrived after cancellation

    emit("system", "Scan complete — parsing results…");
    const parsed = parseNmapXml(xml);
    const result = compileNmapResult(parsed, {
      targetHost: hostname,
      resolvedIp: ip,
      nmapVersion: nmapVersionString() || "unknown",
      durationMs,
      scanArgs: args,
    });

    if (await isCanceled(scanId)) return;
    (await db.updateNmapScan(scanId, {
      status: "complete",
      nmapVersion: result.nmapVersion,
      result,
      rawXml: xml,
      completedAt: new Date().toISOString(),
    }));
    const openPorts = result.ports.filter((p) => p.state === "open").length;
    const detected = result.vulnFindings.filter((f) => f.outcome === "finding").length;
    emit(
      "result",
      `Found ${openPorts} open port(s), ${detected} DETECTED vuln-script hit(s) (${result.vulnFindings.length} scripts ran).`,
    );
  } catch (err: any) {
    if (await isCanceled(scanId)) return; // already canceled — don't overwrite with a failure
    const message = err?.message || "The network reconnaissance scan could not be completed.";
    if (stream) stream.emit("system", `Scan failed: ${message}`);
    (await db.updateNmapScan(scanId, { status: "failed", error: message, completedAt: new Date().toISOString() }));
  } finally {
    if (stream) stream.close();
  }
}
