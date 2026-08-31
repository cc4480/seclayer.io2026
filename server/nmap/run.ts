// Runs the actual nmap process. Uses spawn (not execFile) so stderr can be
// streamed live as it arrives — execFile only resolves after the process
// exits and buffers everything, which would mean no progress ticker.
import { spawn, type ChildProcess } from "node:child_process";
import { buildNmapArgs, nmapProcessTimeoutMs } from "./args.js";
import { isNmapPrivileged } from "./detect.js";
import type { EmitFn } from "../scanEvents.js";

// Hard backstop above --host-timeout, in case nmap itself hangs — this has been
// observed with some NSE `vuln` scripts independent of --host-timeout. Resource
// safety, not a scan-scope restriction. Derived per-profile by
// nmapProcessTimeoutMs (see args.ts) so it can never fall below the
// host-timeout it is supposed to backstop.
// Ceiling on buffered XML stdout — prevents unbounded memory growth from a
// pathological target. A full 65535-port scan's XML is well under 1MB in
// practice; this is a generous multiple, not a realistic limit.
const MAX_STDOUT_BYTES = 64 * 1024 * 1024;

const liveProcesses = new Map<string, ChildProcess>();

// Real process termination, keyed by scan id — called by the cancel route.
// Unlike the AppSec scanner (which has no cancellation token and can only
// stop itself from writing stale results after the fact), nmap is exactly
// one killable OS process, so this actually stops the work, not just the write.
export function killNmapProcess(scanId: string): boolean {
  const child = liveProcesses.get(scanId);
  if (!child) return false;
  child.kill("SIGTERM");
  const t = setTimeout(() => {
    if (!child.killed) child.kill("SIGKILL");
  }, 5000);
  t.unref();
  return true;
}

export interface NmapRunResult {
  xml: string;
  durationMs: number;
  args: string[];
}

export function runNmap(
  scanId: string,
  targetIp: string,
  emit: EmitFn,
  timeoutMs?: number,
  deep = false,
): Promise<NmapRunResult> {
  // Falls back to the profile-derived backstop when the caller doesn't pin one,
  // so a deep scan always gets a process budget larger than its host-timeout.
  const effectiveTimeoutMs = timeoutMs ?? nmapProcessTimeoutMs(deep);
  // Pick SYN+OS vs. TCP-connect based on the boot-time raw-socket probe, so the
  // scan adapts to platforms (e.g. Railway) that can't open raw sockets. `deep`
  // selects all-ports (-p-) over the fast top-1000 default (see buildNmapArgs).
  const args = buildNmapArgs(targetIp, undefined, isNmapPrivileged(), deep);
  const start = Date.now();

  return new Promise((resolve, reject) => {
    const child = spawn("nmap", args, { stdio: ["ignore", "pipe", "pipe"] });
    liveProcesses.set(scanId, child);

    let stdout = "";
    let stdoutBytes = 0;
    let stderrBuf = "";
    let killedForSize = false;

    const hardTimer = setTimeout(() => {
      child.kill("SIGTERM");
      const t = setTimeout(() => {
        if (!child.killed) child.kill("SIGKILL");
      }, 5000);
      t.unref();
    }, effectiveTimeoutMs);
    hardTimer.unref();

    child.stdout!.on("data", (chunk: Buffer) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > MAX_STDOUT_BYTES) {
        killedForSize = true;
        child.kill("SIGKILL");
        return;
      }
      stdout += chunk.toString("utf8");
    });

    // nmap's `--stats-every 10s` lines (e.g. "Stats: 0:02:14 elapsed; ...% done;
    // ETC: ...") arrive here, line-buffered, and are forwarded verbatim to the
    // live scan console on the 'recon' channel.
    child.stderr!.on("data", (chunk: Buffer) => {
      stderrBuf += chunk.toString("utf8");
      let idx: number;
      while ((idx = stderrBuf.indexOf("\n")) >= 0) {
        const line = stderrBuf.slice(0, idx).trim();
        stderrBuf = stderrBuf.slice(idx + 1);
        if (line) emit("recon", line);
      }
    });

    child.on("error", (err) => {
      clearTimeout(hardTimer);
      liveProcesses.delete(scanId);
      reject(err); // e.g. ENOENT if nmap vanished after boot detection
    });

    child.on("close", (code) => {
      clearTimeout(hardTimer);
      liveProcesses.delete(scanId);
      if (killedForSize) {
        reject(new Error("nmap output exceeded the size ceiling and was terminated."));
        return;
      }
      if (code !== 0 && !stdout.trim()) {
        reject(new Error(`nmap exited with code ${code}: ${stderrBuf.slice(-500)}`));
        return;
      }
      resolve({ xml: stdout, durationMs: Date.now() - start, args });
    });
  });
}
