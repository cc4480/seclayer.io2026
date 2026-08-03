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
  error?: string;
}

let cached: NmapDetection | null = null;

export async function detectNmap(): Promise<NmapDetection> {
  try {
    const { stdout } = await execFileAsync("nmap", ["--version"], { timeout: 5000 });
    const match = /Nmap version (\S+)/.exec(stdout);
    cached = { available: true, version: match?.[1] };
  } catch (err: any) {
    cached = { available: false, error: err?.message || "nmap binary not found or not runnable" };
  }
  return cached;
}

export function isNmapAvailable(): boolean {
  return cached?.available ?? false;
}

export function nmapVersionString(): string | undefined {
  return cached?.version;
}
