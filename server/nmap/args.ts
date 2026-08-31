// Builds the nmap argument array. Array-based only — this is handed straight
// to child_process.spawn (never a shell string), so there is no command-
// injection surface regardless of input; the runtime guard below exists to
// catch internal bugs (a hostname slipping through instead of a resolved IP),
// not to sanitize anything.
import net from "node:net";

// Host-timeout ceilings (a resource cap, not a scope limit — nmap returns
// whatever it has found so far if it's hit).
// A deep sweep is all 65535 ports plus -sV, -O and UNCAPPED `vuln` scripts, and
// on a platform without CAP_NET_RAW (Railway) it runs as a TCP connect scan,
// which is markedly slower than SYN. 25 minutes did not fit that work: the scan
// hit --host-timeout and returned partial results instead of completing, which
// defeats the point of opting into the exhaustive profile. An hour is a
// realistic ceiling for a scan the user explicitly asked to be thorough.
export const DEEP_HOST_TIMEOUT_MINUTES = 60; // exhaustive all-ports sweep
export const FAST_HOST_TIMEOUT_MINUTES = 6;  // fast default; empirically ~2 min

// Backstop for the whole nmap PROCESS, derived from the profile's host-timeout
// rather than declared independently. These were two free-standing constants
// (25m host-timeout vs a 30m process kill) that could silently invert — raise
// the host-timeout past the process kill and every deep scan would be killed
// mid-run with no result at all. Deriving it makes that impossible: the process
// backstop is always the host-timeout plus a margin for nmap's own startup,
// NSE loading and XML serialization.
const PROCESS_TIMEOUT_MARGIN_MINUTES = 10;
export function nmapProcessTimeoutMs(deep = false): number {
  const envOverride = Number(process.env.NMAP_SCAN_TIMEOUT_MS);
  const derived =
    ((deep ? DEEP_HOST_TIMEOUT_MINUTES : FAST_HOST_TIMEOUT_MINUTES) + PROCESS_TIMEOUT_MARGIN_MINUTES) * 60 * 1000;
  // An explicit override still wins, but never below the derived floor — a too-
  // small override would reintroduce exactly the truncation this prevents.
  return envOverride > 0 ? Math.max(envOverride, derived) : derived;
}
// Back-compat alias — the deep/full ceiling (was the only exported constant).
export const DEFAULT_HOST_TIMEOUT_MINUTES = DEEP_HOST_TIMEOUT_MINUTES;

// Per-NSE-script wall-clock cap on the fast path. This — not the port count —
// is what actually makes a scan drag on: against a live/CDN-fronted web host
// the `vuln` category's http-* scripts can each run for MINUTES, so an
// unbounded run sat at 5+ min even after the port scope was cut to the top
// 1000. Capping each script to 60s brings the whole fast scan to ~2 min while
// still surfacing the vuln-script hits that finish in time. Deep imposes no
// script cap — it accepts the full runtime for completeness.
const FAST_SCRIPT_TIMEOUT = "60s";

// `privileged` reflects whether raw sockets are usable in this container (see
// server/nmap/detect.ts). When true we run the default SYN scan plus OS
// detection (-O) — the richest recon, needs CAP_NET_RAW. When false (e.g. on
// Railway, whose runtime strips CAP_NET_RAW) we run a TCP connect scan
// (-sT --unprivileged), drop -O, and add -Pn so nmap doesn't attempt raw-socket
// host discovery on a target we've already resolved and validated. Service/
// version detection (-sV) and the NSE `vuln` scripts work either way.
//
// `deep` selects the exhaustive all-ports (-p-), uncapped-script, 25-min sweep;
// the default is the fast top-1000-port, script-capped, 6-min scan.
export function buildNmapArgs(
  targetIp: string,
  hostTimeoutMinutes?: number,
  privileged = true,
  deep = false,
): string[] {
  if (!net.isIP(targetIp)) {
    throw new Error("Internal error: nmap target must be a literal IP address, not a hostname.");
  }
  const timeout = hostTimeoutMinutes ?? (deep ? DEEP_HOST_TIMEOUT_MINUTES : FAST_HOST_TIMEOUT_MINUTES);
  const technique = privileged
    ? ["-sV", "-O"]                             // SYN (default) + service/version + OS detection
    : ["-sT", "-sV", "--unprivileged", "-Pn"];  // TCP connect + service/version, no raw sockets, skip discovery
  const portScope = deep
    ? ["-p-"]                                    // all 65535 ports — exhaustive, opt-in
    : ["--top-ports", "1000"];                   // the 1000 most common ports — fast default
  const scriptTiming = deep ? [] : ["--script-timeout", FAST_SCRIPT_TIMEOUT];
  return [
    ...portScope,
    ...technique,
    "--script", "vuln",                            // NSE vulnerability-detection script category
    ...scriptTiming,                               // cap each script on the fast path (see above)
    "-T4",                                         // aggressive timing template
    "--host-timeout", `${timeout}m`,               // resource ceiling, not a scope limit
    "--stats-every", "10s",                        // periodic progress lines on stderr
    "-oX", "-",                                    // XML output to stdout
    targetIp,
  ];
}
