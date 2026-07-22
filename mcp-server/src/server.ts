import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { scan } from "./client.js";
import { formatScanReport } from "./format.js";
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

  return server;
}
