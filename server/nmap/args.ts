// Builds the nmap argument array. Array-based only — this is handed straight
// to child_process.spawn (never a shell string), so there is no command-
// injection surface regardless of input; the runtime guard below exists to
// catch internal bugs (a hostname slipping through instead of a resolved IP),
// not to sanitize anything.
import net from "node:net";

export const DEFAULT_HOST_TIMEOUT_MINUTES = 25;

// `privileged` reflects whether raw sockets are usable in this container (see
// server/nmap/detect.ts). When true we run the default SYN scan plus OS
// detection (-O) — the richest recon, needs CAP_NET_RAW. When false (e.g. on
// Railway, whose runtime strips CAP_NET_RAW) we run a TCP connect scan
// (-sT --unprivileged), drop -O, and add -Pn so nmap doesn't attempt raw-socket
// host discovery on a target we've already resolved and validated. Service/
// version detection (-sV) and the NSE `vuln` scripts work either way.
export function buildNmapArgs(
  targetIp: string,
  hostTimeoutMinutes = DEFAULT_HOST_TIMEOUT_MINUTES,
  privileged = true,
): string[] {
  if (!net.isIP(targetIp)) {
    throw new Error("Internal error: nmap target must be a literal IP address, not a hostname.");
  }
  const technique = privileged
    ? ["-sV", "-O"]                             // SYN (default) + service/version + OS detection
    : ["-sT", "-sV", "--unprivileged", "-Pn"];  // TCP connect + service/version, no raw sockets, skip discovery
  return [
    "-p-",                                        // all 65535 ports — full depth, no scope limit
    ...technique,
    "--script", "vuln",                            // NSE vulnerability-detection script category
    "-T4",                                         // aggressive timing template
    "--host-timeout", `${hostTimeoutMinutes}m`,    // resource ceiling, not a scope limit
    "--stats-every", "10s",                        // periodic progress lines on stderr
    "-oX", "-",                                    // XML output to stdout
    targetIp,
  ];
}
