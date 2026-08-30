// Feature detection for the optional nmap-backed Network Reconnaissance
// capability. Nmap only ships in the self-hosted Docker image (see
// Dockerfile) — it is never available on the Vercel-hosted deployment, and
// may be absent in a bare local `npm run dev` too. The whole feature must
// stay ABSENT (not erroring) whenever the binary isn't present or runnable,
// so this is probed once at boot and memoized for the process lifetime —
// nmap's presence can't change without a redeploy.
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export interface NmapDetection {
  available: boolean;
  version?: string;
  // Whether raw sockets are actually usable in THIS container. SYN scan (-sS,
  // the default when privileged) and OS detection (-O) need them; a TCP connect
  // scan (-sT) does not. Managed platforms (e.g. Railway) run the container
  // without CAP_NET_RAW in the bounding set, so even as root nmap must fall back
  // to connect scans — buildNmapArgs() adapts on this flag.
  privileged?: boolean;
  error?: string;
}

let cached: NmapDetection | null = null;

// Budget for `nmap --version`. Deliberately generous: this runs during boot,
// concurrently with DB init, worker startup and the HTTP listener, and the
// probe only has to finish once. A tight budget here is what made detection
// flaky (see retry note below), and an unavailable-but-present nmap is far more
// costly than a slow boot.
const VERSION_PROBE_TIMEOUT_MS = 15_000;
const VERSION_PROBE_ATTEMPTS = 3;

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

// Run `nmap --version`, retrying transient failures.
//
// Why retry at all: detectNmap()'s result is memoized for the PROCESS lifetime,
// so a single unlucky probe permanently disables Network Reconnaissance until
// the next redeploy — the feature silently vanishes on a container that is
// perfectly capable of running it. This was observed in practice: on one
// container restart the probe failed with "Command failed: nmap --version"
// while `nmap --version` run by hand in that same container succeeded
// immediately (exit 0), i.e. the 5s budget was exceeded under boot-time CPU
// contention, not a real absence.
//
// ENOENT is the one answer worth trusting the first time: the binary genuinely
// isn't on PATH (the Vercel-hosted deployment, a bare local checkout), and no
// amount of retrying will conjure it — so bail out immediately and keep the
// feature cleanly absent without stalling boot.
async function probeNmapVersion(): Promise<string> {
  let lastErr: unknown;
  for (let attempt = 1; attempt <= VERSION_PROBE_ATTEMPTS; attempt++) {
    try {
      const { stdout } = await execFileAsync("nmap", ["--version"], {
        timeout: VERSION_PROBE_TIMEOUT_MS,
      });
      return stdout;
    } catch (err: any) {
      if (err?.code === "ENOENT") throw err; // binary absent — permanent answer
      lastErr = err;
      if (attempt < VERSION_PROBE_ATTEMPTS) await delay(250 * attempt);
    }
  }
  throw lastErr;
}

// Probe whether nmap can open a raw socket here. An explicit `-sS` (which HARD-
// requires raw sockets — nmap never silently downgrades an explicitly requested
// SYN scan) against loopback exits 0 only when the raw socket actually worked;
// a missing-privilege / socket-permission error (or a non-zero exit for any
// reason) resolves to false. Defaults to UNPRIVILEGED on any doubt, since a
// connect scan works everywhere — this never turns a runnable feature off, it
// only picks the scan technique.
async function probeNmapPrivileged(): Promise<boolean> {
  try {
    await execFileAsync(
      "nmap",
      ["-sS", "-p", "80", "-Pn", "-n", "--host-timeout", "5s", "127.0.0.1"],
      { timeout: 8000 },
    );
    return true;
  } catch {
    return false;
  }
}

export async function detectNmap(): Promise<NmapDetection> {
  try {
    const stdout = await probeNmapVersion();
    const match = /Nmap version (\S+)/.exec(stdout);
    const privileged = await probeNmapPrivileged();
    cached = { available: true, version: match?.[1], privileged };
  } catch (err: any) {
    cached = { available: false, error: err?.message || "nmap binary not found or not runnable" };
  }
  return cached;
}

export function isNmapAvailable(): boolean {
  return cached?.available ?? false;
}

// Raw-socket (SYN/-O) capability, memoized from the boot probe. False whenever
// nmap is absent or the container can't open raw sockets — the scan then runs
// unprivileged (connect scan). See buildNmapArgs().
export function isNmapPrivileged(): boolean {
  return cached?.privileged ?? false;
}

export function nmapVersionString(): string | undefined {
  return cached?.version;
}
