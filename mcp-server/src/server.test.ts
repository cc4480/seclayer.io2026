import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { buildServer } from "./server.js";

async function withFakeBackend(handler: http.RequestListener, fn: (baseUrl: string) => Promise<void>) {
  const server = http.createServer(handler);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as AddressInfo).port;
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((r) => server.close(r));
  }
}

async function withConnectedClient(baseUrl: string, fn: (client: Client) => Promise<void>) {
  const server = buildServer({ apiKey: "sl_live_test", baseUrl });
  const client = new Client({ name: "test-client", version: "0.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  try {
    await fn(client);
  } finally {
    await client.close();
    await server.close();
  }
}

test("seclayer_scan is discoverable, requires url, and never exposes an apiKey parameter", async () => {
  await withFakeBackend(
    (_req, res) => res.writeHead(500).end("unused"),
    async (baseUrl) => {
      await withConnectedClient(baseUrl, async (client) => {
        const { tools } = await client.listTools();
        const tool = tools.find((t) => t.name === "seclayer_scan");
        assert.ok(tool, "seclayer_scan must be registered");
        assert.deepEqual(tool!.inputSchema.required, ["url"]);
        // Regression guard: the API key must never be a per-call tool
        // parameter — it's bound once at server startup so it's never
        // placed in the LLM's per-call context.
        assert.equal(Object.prototype.hasOwnProperty.call(tool!.inputSchema.properties ?? {}, "apiKey"), false);
        assert.ok(Object.prototype.hasOwnProperty.call(tool!.inputSchema.properties ?? {}, "url"));
        assert.ok(Object.prototype.hasOwnProperty.call(tool!.inputSchema.properties ?? {}, "authHeader"));
      });
    },
  );
});

test("calling seclayer_scan against a successful backend returns the formatted report as tool text", async () => {
  await withFakeBackend(
    (_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        success: true, targetUrl: "https://x.test", postureScore: 77, vulnerabilityLevel: "medium",
        analysisSummary: "summary text", executiveBreakdown: { overview: "o", riskAreas: [], businessImpact: "b", priorityActions: [] },
        securityFindings: [], creditsRemaining: 5,
      }));
    },
    async (baseUrl) => {
      await withConnectedClient(baseUrl, async (client) => {
        const result: any = await client.callTool({ name: "seclayer_scan", arguments: { url: "https://x.test" } });
        assert.equal(result.isError, undefined);
        assert.equal(result.content[0].type, "text");
        assert.match(result.content[0].text, /Posture score: 77\/100/);
        assert.match(result.content[0].text, /summary text/);
      });
    },
  );
});

test("calling seclayer_scan against a failing backend returns isError:true with a clear message", async () => {
  await withFakeBackend(
    (_req, res) => {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Invalid API Key, active key required, or insufficient credits." }));
    },
    async (baseUrl) => {
      await withConnectedClient(baseUrl, async (client) => {
        const result: any = await client.callTool({ name: "seclayer_scan", arguments: { url: "https://x.test" } });
        assert.equal(result.isError, true);
        assert.match(result.content[0].text, /Authentication or credit failure/);
      });
    },
  );
});

test("all three tools are discoverable and none exposes an apiKey parameter", async () => {
  await withFakeBackend(
    (_req, res) => res.writeHead(500).end("unused"),
    async (baseUrl) => {
      await withConnectedClient(baseUrl, async (client) => {
        const { tools } = await client.listTools();
        const names = tools.map((t) => t.name).sort();
        assert.deepEqual(names, ["seclayer_get_report", "seclayer_list_scans", "seclayer_scan"]);
        // The bound API key must never leak into any tool's per-call schema.
        for (const t of tools) {
          assert.equal(Object.prototype.hasOwnProperty.call(t.inputSchema.properties ?? {}, "apiKey"), false, `${t.name} must not expose apiKey`);
        }
        const getReport = tools.find((t) => t.name === "seclayer_get_report")!;
        assert.deepEqual(getReport.inputSchema.required, ["scanId"]);
      });
    },
  );
});

test("seclayer_list_scans returns the formatted history table over the MCP protocol", async () => {
  await withFakeBackend(
    (req, res) => {
      assert.match(req.url || "", /^\/api\/mcp\/scans/);
      assert.equal(req.headers["x-api-key"], "sl_live_test");
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        success: true,
        scans: [{ id: "scan_1", url: "https://x.test", status: "complete", score: 80, severity: "low", createdAt: "t0", completedAt: "t1" }],
      }));
    },
    async (baseUrl) => {
      await withConnectedClient(baseUrl, async (client) => {
        const result: any = await client.callTool({ name: "seclayer_list_scans", arguments: { limit: 10 } });
        assert.equal(result.isError, undefined);
        assert.match(result.content[0].text, /scan_1/);
        assert.match(result.content[0].text, /seclayer_get_report/);
      });
    },
  );
});

test("seclayer_get_report fetches a report by id over the MCP protocol", async () => {
  await withFakeBackend(
    (req, res) => {
      assert.equal(req.url, "/api/mcp/scans/scan_1");
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        success: true, targetUrl: "https://x.test", postureScore: 64, vulnerabilityLevel: "medium",
        analysisSummary: "retrieved", executiveBreakdown: { overview: "o", riskAreas: [], businessImpact: "b", priorityActions: [] },
        securityFindings: [], completedAt: "2026-01-01T00:00:00Z",
      }));
    },
    async (baseUrl) => {
      await withConnectedClient(baseUrl, async (client) => {
        const result: any = await client.callTool({ name: "seclayer_get_report", arguments: { scanId: "scan_1" } });
        assert.equal(result.isError, undefined);
        assert.match(result.content[0].text, /Posture score: 64\/100/);
        assert.match(result.content[0].text, /retrieved/);
      });
    },
  );
});
