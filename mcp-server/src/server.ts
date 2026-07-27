import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { scan, listScans, getReport } from "./client.js";
import { formatScanReport, formatScanList } from "./format.js";
import { VERSION } from "./version.js";
import type { ResolvedConfig } from "./cli.js";

const TOOL_DESCRIPTION =
  "Run a live security pen-test / vulnerability audit against a web application or HTTP API using Seclayer, " +
  "and get back a structured report: an overall posture score (0-100), severity level, an executive risk " +
  "summary, and a list of concrete security findings each with a description, OWASP category, business " +
  "impact, and a ready-to-apply fix. Use this before deploying, when reviewing a staging or production " +
  "endpoint's security, or when asked to check a URL for vulnerabilities. Each scan consumes one credit " +
  "from the account tied to this server's API key. Provide the target url; optionally provide authHeader " +
  "to scan authenticated endpoints.";

// Builds (but does not connect) an McpServer bound to the given backend
// config. Kept separate from index.ts's transport wiring so it can be tested
// in-process via InMemoryTransport without spawning a real stdio process.
export function buildServer(config: ResolvedConfig): McpServer {
  const server = new McpServer({ name: "seclayer-mcp", version: VERSION });

  server.registerTool(
    "seclayer_scan",
    {
      title: "Seclayer Security Scan",
      description: TOOL_DESCRIPTION,
      inputSchema: {
        url: z
          .string()
          .url()
          .describe(
            "Full URL to scan, including scheme, e.g. https://staging-checkout.example.com. Must be " +
              "publicly reachable. Active exploit probing only runs if this API key's owner has verified " +
              "domain ownership; otherwise passive recon only.",
          ),
        authHeader: z
          .string()
          .optional()
          .describe("Optional raw Authorization header value for authenticated targets, e.g. 'Bearer eyJ...'."),
      },
      annotations: {
        readOnlyHint: false,
        openWorldHint: true,
        destructiveHint: false,
      },
    },
    async ({ url, authHeader }) => {
      const outcome = await scan(config.baseUrl, config.apiKey, { url, authHeader });
      if (outcome.ok) {
        return { content: [{ type: "text", text: formatScanReport(outcome.data) }] };
      }
      return { content: [{ type: "text", text: outcome.message }], isError: true };
    },
  );

  // Review scans this key already ran — WITHOUT launching (and paying for) a new
  // one. Read-only, no credit cost. Lets an agent recall a result, check whether
  // a scan finished, or pick a scan id to fetch in full.
  server.registerTool(
    "seclayer_list_scans",
    {
      title: "List Seclayer Scans",
      description:
        "List recent Seclayer security scans run under this server's API key — newest first, with each scan's id, target, status, posture score, and severity. Read-only: it never launches a scan and costs no credits. Use it to recall a previous result, check whether a scan has finished, or find the id of a scan to fetch in full with seclayer_get_report.",
      inputSchema: {
        limit: z
          .number()
          .int()
          .min(1)
          .max(100)
          .optional()
          .describe("Maximum scans to return (default 20, max 100), newest first."),
      },
      annotations: { readOnlyHint: true, openWorldHint: true, destructiveHint: false },
    },
    async ({ limit }) => {
      const outcome = await listScans(config.baseUrl, config.apiKey, limit);
      if (outcome.ok) {
        return { content: [{ type: "text", text: formatScanList(outcome.data) }] };
      }
      return { content: [{ type: "text", text: outcome.message }], isError: true };
    },
  );

  // Fetch a completed scan's full report by id — the same report quality as a
  // fresh scan, WITHOUT re-running (or paying for) it. Read-only, no credit cost.
  server.registerTool(
    "seclayer_get_report",
    {
      title: "Get Seclayer Scan Report",
      description:
        "Fetch the full report of a completed Seclayer scan by its id — posture score, executive summary and breakdown, and every finding with its impact, fix, and ready-to-apply agent prompt. Read-only: it never re-runs the scan and costs no credits. Get scan ids from seclayer_list_scans. Use this to act on a scan you (or a teammate on the same key) already ran instead of scanning again.",
      inputSchema: {
        scanId: z
          .string()
          .min(1)
          .describe("The id of a completed scan (from seclayer_list_scans), e.g. scan_ab12cd34."),
      },
      annotations: { readOnlyHint: true, openWorldHint: true, destructiveHint: false },
    },
    async ({ scanId }) => {
      const outcome = await getReport(config.baseUrl, config.apiKey, scanId);
      if (outcome.ok) {
        return { content: [{ type: "text", text: formatScanReport(outcome.data) }] };
      }
      return { content: [{ type: "text", text: outcome.message }], isError: true };
    },
  );

  return server;
}
