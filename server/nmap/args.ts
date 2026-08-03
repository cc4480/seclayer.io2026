// Builds the nmap argument array. Array-based only — this is handed straight
// to child_process.spawn (never a shell string), so there is no command-
// injection surface regardless of input; the runtime guard below exists to
// catch internal bugs (a hostname slipping through instead of a resolved IP),
// not to sanitize anything.
import net from "node:net";

export const DEFAULT_HOST_TIMEOUT_MINUTES = 25;

export function buildNmapArgs(targetIp: string, hostTimeoutMinutes = DEFAULT_HOST_TIMEOUT_MINUTES): string[] {
  if (!net.isIP(targetIp)) {
    throw new Error("Internal error: nmap target must be a literal IP address, not a hostname.");
  }
  return [
    "-p-",                                        // all 65535 ports — full depth, no scope limit
    "-sV",                                         // service/version detection
    "-O",                                          // OS detection (needs CAP_NET_RAW/CAP_NET_ADMIN; degrades gracefully without)
    "--script", "vuln",                            // NSE vulnerability-detection script category
    "-T4",                                         // aggressive timing template
    "--host-timeout", `${hostTimeoutMinutes}m`,    // resource ceiling, not a scope limit
    "--stats-every", "10s",                        // periodic progress lines on stderr
    "-oX", "-",                                    // XML output to stdout
    targetIp,
  ];
}
