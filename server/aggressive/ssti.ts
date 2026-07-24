// Server-Side Template Injection active probe (AGGRESSIVE tier). Arithmetic
// oracle: inject a template expression that multiplies two random operands and
// look for the COMPUTED PRODUCT in the response. The literal payload only ever
// contains "A*B", never the product, so the product's appearance can only mean
// the backend template engine evaluated our expression — a proof that can't be a
// coincidental page string. Non-destructive: it computes a number, nothing else.
import crypto from "crypto";
import { buildProbeEvidence } from "../evidence.js";
import { probeFetch } from "../redTeam/probeHttp.js";
import type { ProbeContext, RedTeamFinding } from "../redTeam/types.js";

// Common template syntaxes across engines: Jinja2/Twig/Nunjucks, Freemarker/
// JSP-EL/Thymeleaf, Ruby ERB/Slim, and JSP scriptlets.
const SYNTAXES = (a: number, b: number): string[] => [
  `{{${a}*${b}}}`,
  `\${${a}*${b}}`,
  `#{${a}*${b}}`,
  `<%= ${a}*${b} %>`,
];

export async function probeSsti(ctx: ProbeContext): Promise<RedTeamFinding | null> {
  // 4-digit operands → an 7-8 digit product that is extremely unlikely to appear
  // by coincidence, and whose factors never appear literally as the product.
  const a = 1000 + crypto.randomInt(8999);
  const b = 1000 + crypto.randomInt(8999);
  const product = String(a * b);

  for (const expr of SYNTAXES(a, b)) {
    const attackUrl = `${ctx.url}/?name=${encodeURIComponent(expr)}`;
    let body: string;
    let res: Response;
    try {
      res = await probeFetch(attackUrl, ctx.fuzzHeaders);
      body = await res.text();
    } catch {
      continue;
    }
    const idx = body.indexOf(product);
    // The product must appear AND the raw expression must NOT be reflected as-is
    // (if "A*B" is echoed verbatim the engine didn't evaluate it — that's just
    // reflection, not SSTI).
    if (idx !== -1 && !body.includes(expr)) {
      return {
        testName: "Active Server-Side Template Injection (SSTI)",
        payload: expr,
        severity: "critical",
        description:
          "Active Red Team fuzzing injected a template expression into a request parameter and the server returned its evaluated result, confirming Server-Side Template Injection. SSTI commonly escalates to remote code execution on the affected template engine.",
        fix: "Never render user input as part of a template. Pass untrusted values only as data/context to a pre-compiled template, use a logic-less/sandboxed engine, and validate/allow-list any dynamic template selection.",
        evidence: buildProbeEvidence({
          method: "oracle",
          attackUrl,
          requestHeaders: ctx.fuzzHeaders,
          res,
          body,
          matchIndex: idx,
          quote: product,
          why: `We injected the template expression "${expr}"; the response contained ${product}, the exact product of ${a}×${b}. The literal payload never contains that number, so the server-side template engine must have evaluated our expression.`,
          demonstration: `We placed the template expression "${expr}" in the "name" parameter and the server rendered ${product} — the computed product of ${a} and ${b}. Only a backend that evaluated our expression as a template could produce that value, which is the hallmark of SSTI (and a frequent path to remote code execution).`,
        }),
      };
    }
  }
  return null;
}
