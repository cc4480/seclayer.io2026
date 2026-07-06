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
}

// Calls the DeepSeek chat completions endpoint in JSON mode and returns the
// model's final answer plus its chain-of-thought (when thinking mode produced
// one). Returns { content: null } when no API key is configured so callers
// can gracefully fall back to local generation.
export async function callDeepSeek(model: string, prompt: string, opts: DeepSeekCallOptions): Promise<DeepSeekResult> {
  const apiKey = getApiKey();
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

  const response = await fetch(`${DEEPSEEK_BASE_URL}/chat/completions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`,
    },
    body: JSON.stringify(body),
  });

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
