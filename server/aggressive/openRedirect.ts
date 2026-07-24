// Open Redirect active probe (AGGRESSIVE tier). Injects an off-site URL into
// common redirect parameters and checks whether the app issues a 3xx Location
// pointing at our attacker-controlled host. Non-destructive: the probe follows
// nothing (redirect: manual) — it only reads the Location header.
import { aggFetchRaw, buildHeaderEvidence } from "./aggHttp.js";
import type { ProbeContext, RedTeamFinding } from "../redTeam/types.js";

const REDIRECT_PARAMS = ["next", "redirect", "url", "return", "returnUrl", "dest", "continue", "r"];

// A distinctive, non-routable marker host so a reflected Location is unmistakable
// and can never accidentally send a real user somewhere live.
const MARKER_HOST = "seclayer-openredirect-probe.example";

export async function probeOpenRedirect(ctx: ProbeContext): Promise<RedTeamFinding | null> {
  // Absolute and protocol-relative forms; both are classic open-redirect vectors.
  const payloads = [`https://${MARKER_HOST}/`, `//${MARKER_HOST}/`];

  for (const param of REDIRECT_PARAMS) {
    for (const payload of payloads) {
      const attackUrl = `${ctx.url}/?${param}=${encodeURIComponent(payload)}`;
      let res: Response;
      try {
        res = await aggFetchRaw(attackUrl, { headers: ctx.fuzzHeaders });
      } catch {
        continue;
      }
      const location = res.headers.get("location") || "";
      // A real open redirect: a 3xx whose Location points at our external marker
      // host (not merely a same-site path that happens to contain the string).
      let redirectsOffsite = false;
      if (res.status >= 300 && res.status < 400 && location) {
        try {
          redirectsOffsite = new URL(location, ctx.url).host === MARKER_HOST;
        } catch {
          redirectsOffsite = location.includes(MARKER_HOST);
        }
      }
      if (redirectsOffsite) {
        return {
          testName: "Active Open Redirect",
          payload: `${param}=${payload}`,
          severity: "medium",
          description:
            "Active Red Team fuzzing found that a request parameter is used as an unvalidated redirect target: the app issued an HTTP redirect to an attacker-controlled external host. Open redirects are used for convincing phishing, OAuth token theft, and filter bypass.",
          fix: "Do not redirect to raw user input. Redirect only to a fixed allow-list of paths/hosts, or force a relative path (strip scheme/host), and reject absolute or protocol-relative targets that don't match your own origin.",
          evidence: buildHeaderEvidence({
            method: "reflection",
            reqMethod: "GET",
            attackUrl,
            requestHeaders: ctx.fuzzHeaders,
            res,
            proofHeaders: [`Location: ${location}`],
            quote: MARKER_HOST,
            why: `The server answered with an HTTP ${res.status} redirect whose Location points at "${MARKER_HOST}" — a host we supplied in the "${param}" parameter. The app forwarded a visitor to an external destination of our choosing.`,
            demonstration: `We set "${param}" to "${payload}" and the server replied with a redirect to ${location}. Because it sends users to a host we control, an attacker can craft a link on your domain that lands victims on a phishing page.`,
          }),
        };
      }
    }
  }
  return null;
}
