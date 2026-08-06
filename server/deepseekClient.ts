// Low-level DeepSeek chat-completions client shared by the pro-tier report
// generator (server/deepseek.ts) and the flash-tier scan narrator
// (server/narrate.ts). DeepSeek exposes an OpenAI-compatible API, so this
// talks to it directly over fetch rather than pulling in a heavyweight SDK.

export const DEEPSEEK_BASE_URL = process.env.DEEPSEEK_BASE_URL || 'https://api.deepseek.com';

export function getApiKey(): string | null {
  const apiKey = process.env.DEEPSEEK_API_KEY;
  if (!apiKey || apiKey === 'MY_DEEPSEEK_API_KEY' || apiKey.trim() === '') {
    return null;
  }
  return apiKey;
}

// The effective key for a call: a per-user "bring your own key" override wins
// over the server-wide env key, so a user with their own DeepSeek key gets full
// AI reports even when the operator hasn't configured a global key (e.g. free
// mode). Falls back to the env key, then null (local-summary generation).
export function resolveApiKey(override?: string | null): string | null {
  const t = override?.trim();
  if (t) return t;
  return getApiKey();
}

export interface DeepSeekResult {
  content: string | null;
  reasoningContent?: string;
}

export interface DeepSeekCallOptions {
  // Whether to use "thinking" (chain-of-thought) mode. Pro's deep report
  // reasoning wants this on; flash's fast narration wants it off for latency.
  thinking?: 'enabled' | 'disabled';
  reasoningEffort?: 'high' | 'max';
  // NOTE: when thinking is enabled, this caps reasoning + final answer
  // COMBINED — a tight cap can silently truncate the response before any
  // JSON is emitted. Size it generously for thinking calls.
  maxTokens: number;
  // Every other outbound probe in this codebase bounds itself with an
  // AbortController; this call used to be the one exception, so a stalled
  // DeepSeek request (or a hung proxy in front of it) could leave a scan
  // sitting in "scanning"/"analyzing" forever with no fast-fail. Callers must
  // size this to their own latency profile — thinking-mode calls legitimately
  // take much longer than flash narration.
  timeoutMs: number;
}

// Calls the DeepSeek chat completions endpoint in JSON mode and returns the
// model's final answer plus its chain-of-thought (when thinking mode produced
// one). Returns { content: null } when no API key is configured so callers
// can gracefully fall back to local generation.
export async function callDeepSeek(model: string, prompt: string, opts: DeepSeekCallOptions, apiKeyOverride?: string | null): Promise<DeepSeekResult> {
  const apiKey = resolveApiKey(apiKeyOverride);
  if (!apiKey) return { content: null };

  const body: Record<string, unknown> = {
    model,
    messages: [{ role: 'user', content: prompt }],
    response_format: { type: 'json_object' },
    max_tokens: opts.maxTokens,
    stream: false,
  };
  // temperature/top_p have no effect in thinking mode, so they're deliberately
  // never sent — a dead parameter is just noise.
  if (opts.thinking) body.thinking = { type: opts.thinking };
  if (opts.reasoningEffort) body.reasoning_effort = opts.reasoningEffort;

  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), opts.timeoutMs);
  let response: Response;
  try {
    response = await fetch(`${DEEPSEEK_BASE_URL}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body: JSON.stringify(body),
      signal: ctl.signal,
    });
  } catch (err: any) {
    if (err?.name === 'AbortError') {
      throw new Error(`DeepSeek API call timed out after ${opts.timeoutMs}ms`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }

  if (!response.ok) {
    const errBody = await response.text().catch(() => '');
    throw new Error(`DeepSeek API error ${response.status}: ${errBody}`);
  }

  const data = await response.json();
  const message = data?.choices?.[0]?.message;
  const content = typeof message?.content === 'string' ? message.content : null;
  const reasoningContent = typeof message?.reasoning_content === 'string' ? message.reasoning_content : undefined;
  return { content, reasoningContent };
}

// --- Multi-turn tool-calling (autofix agent loop) ---
//
// Separate from callDeepSeek above on purpose: that function's contract (one
// user-role prompt in, JSON-mode content out) is depended on verbatim by
// server/deepseek.ts and server/narrate.ts. The autofix agent loop instead
// needs a growing multi-role transcript (system/user/assistant/tool) and
// OpenAI-style function calling, so it gets its own request/response shape
// rather than overloading the existing one.
export interface DeepSeekToolDef {
  type: 'function';
  function: {
    name: string;
    description: string;
    parameters: Record<string, unknown>;
  };
}

export interface DeepSeekMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string;
  tool_call_id?: string;   // required on role:'tool' messages
  tool_calls?: DeepSeekToolCall[]; // present on an assistant message that called tools
}

export interface DeepSeekToolCall {
  id: string;
  type: 'function';
  function: { name: string; arguments: string };
}

export interface DeepSeekAgentTurnResult {
  content: string | null;
  toolCalls: DeepSeekToolCall[];
}

// One turn of an agentic tool-calling conversation: sends the full transcript
// so far plus the fixed tool schema, and returns the model's next move (either
// a final text answer or one/more tool calls for the caller to execute).
// Never falls back to local generation on a missing key — the autofix route
// that calls this always runs server-side where DEEPSEEK_API_KEY is required,
// unlike the optional-everywhere report generators.
export async function callDeepSeekAgentTurn(
  model: string,
  messages: DeepSeekMessage[],
  tools: DeepSeekToolDef[],
  opts: { maxTokens: number; timeoutMs: number },
): Promise<DeepSeekAgentTurnResult> {
  const apiKey = getApiKey();
  if (!apiKey) throw new Error('DEEPSEEK_API_KEY is not configured; the autofix agent loop requires it.');

  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), opts.timeoutMs);
  let response: Response;
  try {
    response = await fetch(`${DEEPSEEK_BASE_URL}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model,
        messages,
        tools,
        tool_choice: 'auto',
        max_tokens: opts.maxTokens,
        stream: false,
      }),
      signal: ctl.signal,
    });
  } catch (err: any) {
    if (err?.name === 'AbortError') {
      throw new Error(`DeepSeek agent-turn call timed out after ${opts.timeoutMs}ms`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }

  if (!response.ok) {
    const errBody = await response.text().catch(() => '');
    throw new Error(`DeepSeek API error ${response.status}: ${errBody}`);
  }

  const data = await response.json();
  const message = data?.choices?.[0]?.message;
  const content = typeof message?.content === 'string' ? message.content : null;
  const toolCalls: DeepSeekToolCall[] = Array.isArray(message?.tool_calls) ? message.tool_calls : [];
  return { content, toolCalls };
}
