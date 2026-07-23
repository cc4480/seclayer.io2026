// OS command injection active probe. Oracle-first: inject an arithmetic
// expression with random operands and look for the COMPUTED SUM in the response.
// The literal payload never contains the sum, so its appearance can only mean the
// backend evaluated our injected command — a proof that can't be a coincidental
// page string. Falls back to the classic `id` output signature only if the
// arithmetic oracle doesn't land.
import crypto from "crypto";
import { buildProbeEvidence } from "../evidence.js";
import { probeFetch } from "./probeHttp.js";
import type { ProbeContext, RedTeamFinding } from "./types.js";

const CMD_FIX =
  "Avoid invoking underlying operating system commands entirely. If required, use strictly sanitized arguments array APIs, never shell-interpolated execution.";
const CMD_DESCRIPTION =
  "Active Red Team command-injection fuzzing evaluated an injected shell command on the backend, confirming arbitrary OS command execution.";

// Output of the Unix `id` command, e.g. "uid=0(root) gid=0(root)".
const ID_OUTPUT_SIGNATURE = /uid=\d+\([^)]*\)\s+gid=\d+\([^)]*\)/;

export async function probeCommandInjection(ctx: ProbeContext): Promise<RedTeamFinding | null> {
  const a = 100000 + crypto.randomInt(899999); // 6-digit operands so the sum
  const b = 100000 + crypto.randomInt(899999); // is a distinctive, unlikely string
  const sum = String(a + b);
  const oracleUrl = `${ctx.url}/?ping=127.0.0.1%3B+expr+${a}+%2B+${b}`;
  const oracleRes = await probeFetch(oracleUrl, ctx.fuzzHeaders);
  const oracleText = await oracleRes.text();
  const sumIdx = oracleText.indexOf(sum);

  if (sumIdx !== -1) {
    return {
      testName: "Active OS Command Injection",
      payload: `; expr ${a} + ${b}`,
      severity: "critical",
      description: CMD_DESCRIPTION,
      fix: CMD_FIX,
      evidence: buildProbeEvidence({
        method: "oracle",
        attackUrl: oracleUrl,
        requestHeaders: ctx.fuzzHeaders,
        res: oracleRes,
        body: oracleText,
        matchIndex: sumIdx,
        quote: sum,
        why: `We injected "expr ${a} + ${b}"; the server returned ${sum}, the exact arithmetic result. The literal payload never contains that number, so the backend must have executed our injected command to produce it.`,
        demonstration: `We injected the shell command "expr ${a} + ${b}" into the "ping" parameter, and the server responded with ${sum} — the computed sum. The only way that number appears is if the server ran our command, proving arbitrary OS command execution.`,
      }),
    };
  }

  // Fallback: classic `id` output signature (uid=…gid=…).
  const idUrl = `${ctx.url}/?ping=127.0.0.1%3B+id`;
  const idRes = await probeFetch(idUrl, ctx.fuzzHeaders);
  const idText = await idRes.text();
  const idMatch = ID_OUTPUT_SIGNATURE.exec(idText);
  if (!idMatch) return null;

  return {
    testName: "Active OS Command Injection",
    payload: "; id",
    severity: "critical",
    description: CMD_DESCRIPTION,
    fix: CMD_FIX,
    evidence: buildProbeEvidence({
      method: "oracle",
      attackUrl: idUrl,
      requestHeaders: ctx.fuzzHeaders,
      res: idRes,
      body: idText,
      matchIndex: idMatch.index,
      quote: idMatch[0],
      why: "This is the output of the Unix `id` command (the current user's uid/gid), returned only because the backend executed our injected `; id`. It is not static page content.",
      demonstration: `We injected "; id" into the "ping" parameter and the server returned "${idMatch[0]}" — the live output of the id command. That output only appears if the server executed our injected command.`,
    }),
  };
}
