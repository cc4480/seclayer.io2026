// THE single decision for whether ACTIVE exploit probes (red-team + aggressive)
// may run against a target. Centralized so every entry point — dashboard scans,
// scan-now, monitor ticks, single-finding retest, and the MCP endpoint — gates
// identically, instead of each re-implementing the check (which had drifted:
// scan-now and MCP previously ignored the dev/operator flags entirely).
//
// Active probes are allowed when EITHER:
//   • the operator has explicitly unlocked this instance — the dev flag
//     (DEV_SKIP_DOMAIN_VERIFICATION, non-prod only) or the operator flag
//     (ALLOW_UNVERIFIED_ACTIVE_PROBES, any environment); or
//   • the user has proven ownership of the target's domain (DNS/well-known file).
//
// With neither, only passive recon runs — the ownership gate that stops the
// platform from being used as an anonymous attack proxy stays in force.
import { config } from "./config.js";
import { db } from "./db.js";
import { extractDomain } from "./domainVerify.js";

export async function activeProbesUnlocked(userId: string, targetUrl: string): Promise<boolean> {
  if (config.allowUnverifiedActiveProbes || config.devSkipDomainVerification) return true;
  return (await db.isDomainVerified(userId, extractDomain(targetUrl)));
}
