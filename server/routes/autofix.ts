// CI-side "fix this one finding" endpoint used by the @seclayer/mcp autofix CLI
// (mcp-server/src/autofix.ts). The backend never receives source code — it only
// proxies a growing tool-calling transcript to DeepSeek and returns the model's
// next move; every tool call (read/list/edit a file, run the one pre-approved
// test command) executes back in the caller's own CI runner, never here. This
// preserves the product's black-box positioning even though it now closes the
// loop with a real code change instead of just a copyable prompt.
import express from "express";
import { db } from "../db.js";
import { config } from "../config.js";
import { rateLimit } from "../rateLimit.js";
import { callDeepSeekAgentTurn, DeepSeekMessage, DeepSeekToolDef } from "../deepseekClient.js";

const MODEL_AGENT = process.env.DEEPSEEK_MODEL_AGENT || "deepseek-v4-pro";
// A hard ceiling on model turns per finding, enforced here independent of
// whatever cap the CLI applies client-side — this is the backstop that bounds
// DeepSeek spend and prevents a runaway session even if a client misbehaves.
const MAX_TURNS = 25;
const TURN_TIMEOUT_MS = 120_000;
const MAX_TOKENS = 4096;

// Fixed tool schema — the single source of truth for what the autofix agent
// loop is allowed to do. mcp-server/src/autofixTools.ts implements executors
// for exactly these names, scoped to the checked-out repo. Deliberately NOT a
// generic shell tool: the finding data fed into this conversation is partly
// sourced from the scanned target's own HTTP responses (see
// evidence.signal.quote in src/types.ts), so a hostile or compromised target
// could attempt prompt injection. Keeping the surface to file edits + one
// operator-fixed command means that can't turn into arbitrary code execution.
const AUTOFIX_TOOLS: DeepSeekToolDef[] = [
  {
    type: "function",
    function: {
      name: "read_file",
      description: "Read a text file from the repository, relative to the repo root.",
      parameters: {
        type: "object",
        properties: { path: { type: "string", description: "Repo-relative file path." } },
        required: ["path"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "list_dir",
      description: "List files and directories at a path, relative to the repo root.",
      parameters: {
        type: "object",
        properties: { path: { type: "string", description: 'Repo-relative directory path ("." for root).' } },
        required: ["path"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "edit_file",
      description:
        "Replace an exact, unique occurrence of old_string with new_string in a repo file. old_string must match the file's current content exactly, including whitespace. Use this for every code change — there is no other write tool.",
      parameters: {
        type: "object",
        properties: {
          path: { type: "string", description: "Repo-relative file path." },
          old_string: { type: "string", description: "Exact existing text to replace." },
          new_string: { type: "string", description: "Replacement text." },
        },
        required: ["path", "old_string", "new_string"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "run_test_command",
      description:
        "Run the project's pre-approved test/build command and see its output. The command itself is fixed by the CI operator — you cannot choose or parameterize it. Not available if no test command was configured.",
      parameters: { type: "object", properties: {}, required: [] },
    },
  },
  {
    type: "function",
    function: {
      name: "done",
      description:
        "Call this when you're finished — either the fix is complete, or you determined the finding doesn't apply here. Always provide a short summary.",
      parameters: {
        type: "object",
        properties: {
          summary: { type: "string", description: "What changed and how you verified it, or why no change was made." },
          changed: { type: "boolean", description: "Whether you made a code change." },
        },
        required: ["summary", "changed"],
      },
    },
  },
];

export function registerAutofixRoutes(app: express.Express) {
  const startLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    keyPrefix: "mcp-autofix-start",
    message: "Autofix rate limit reached. Please wait a moment before starting another fix session.",
  });
  const turnLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    keyPrefix: "mcp-autofix-turn",
    message: "Autofix rate limit reached. Please wait a moment before the next turn.",
  });

  // Starts one fix attempt for one finding — costs 1 credit, charged on
  // attempt (not success), matching every other credit-gated MCP call. Unlike
  // /api/mcp/scan there is no async pipeline after the charge that can fail, so
  // there's no refund path here: creating the session row cannot meaningfully
  // fail once the key/credit check has passed.
  app.post("/api/mcp/autofix/start", startLimiter, async (req, res) => {
    const { apiKey, url, findingTitle, findingCategory } = req.body;
    if (!apiKey || !url || !findingTitle || !findingCategory) {
      return res.status(400).json({ error: "Missing parameters. required: apiKey, url, findingTitle, findingCategory" });
    }

    const user = config.freeMode ? (await db.validateApiKey(apiKey)) : (await db.validateApiKeyAndDeduct(apiKey, 1));
    if (!user) {
      return res.status(401).json({
        error: config.freeMode
          ? "Invalid API Key — an active key is required."
          : "Invalid API Key, active key required, or insufficient credits. Get credits at seclayerio.ai.",
      });
    }

    const session = (await db.createAutofixSession(user.id, url, findingTitle, findingCategory));
    res.json({ success: true, sessionId: session.id, creditsRemaining: user.credits });
  });

  // One turn of the tool-calling loop: caller sends the full transcript so
  // far, gets back the model's next move (a final answer and/or tool calls),
  // executes any tool calls locally, and calls this again with the result
  // appended. No credit cost per turn — the session's single credit already
  // covers the whole attempt.
  app.post("/api/mcp/autofix/turn", turnLimiter, async (req, res) => {
    const { apiKey, sessionId, messages } = req.body;
    if (!apiKey || !sessionId || !Array.isArray(messages)) {
      return res.status(400).json({ error: "Missing parameters. required: apiKey, sessionId, messages" });
    }

    const user = (await db.validateApiKey(apiKey));
    if (!user) return res.status(401).json({ error: "Invalid or missing API key." });

    const session = (await db.getAutofixSession(sessionId));
    if (!session || session.userId !== user.id) {
      return res.status(404).json({ error: "Autofix session not found." });
    }
    if (session.status !== "active") {
      return res.status(409).json({ error: `Autofix session is not active (status: ${session.status}).`, status: session.status });
    }
    if (session.turns >= MAX_TURNS) {
      (await db.completeAutofixSession(sessionId, "expired"));
      return res.status(409).json({ error: `Autofix session reached its ${MAX_TURNS}-turn limit without finishing.`, status: "expired" });
    }

    try {
      const result = await callDeepSeekAgentTurn(MODEL_AGENT, messages as DeepSeekMessage[], AUTOFIX_TOOLS, {
        maxTokens: MAX_TOKENS,
        timeoutMs: TURN_TIMEOUT_MS,
      });
      const updated = (await db.incrementAutofixTurn(sessionId));

      const calledDone = result.toolCalls.some((c) => c.function.name === "done");
      const turnCapped = updated.turns >= MAX_TURNS;
      if (calledDone || turnCapped) {
        (await db.completeAutofixSession(sessionId, calledDone ? "done" : "expired"));
      }

      res.json({
        success: true,
        content: result.content,
        toolCalls: result.toolCalls,
        turnsUsed: updated.turns,
        turnsRemaining: Math.max(0, MAX_TURNS - updated.turns),
        sessionDone: calledDone || turnCapped,
      });
    } catch (err: any) {
      res.status(500).json({ error: "Autofix turn failed.", details: err?.message || String(err) });
    }
  });
}
