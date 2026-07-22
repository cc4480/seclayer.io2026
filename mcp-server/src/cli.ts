// Minimal, dependency-free argv parsing — this server only ever needs two
// configuration values, so a full arg-parsing library would be pure overhead.

export interface RawArgs {
  key?: string;
  url?: string;
  help?: boolean;
  version?: boolean;
}

const FLAG_ALIASES: Record<string, "key" | "url"> = {
  "--key": "key",
  "-k": "key",
  "--url": "url",
  "-u": "url",
};

const BOOLEAN_FLAGS: Record<string, "help" | "version"> = {
  "--help": "help",
  "-h": "help",
  "--version": "version",
  "-v": "version",
};

export function parseArgs(argv: string[]): RawArgs {
  const args: RawArgs = {};
  for (let i = 0; i < argv.length; i++) {
    const raw = argv[i];
    if (!raw.startsWith("-")) continue;

    // Support --flag=value in addition to --flag value.
    const eqIndex = raw.indexOf("=");
    const flag = eqIndex !== -1 ? raw.slice(0, eqIndex) : raw;
    const inlineValue = eqIndex !== -1 ? raw.slice(eqIndex + 1) : undefined;

    if (flag in BOOLEAN_FLAGS) {
      args[BOOLEAN_FLAGS[flag]] = true;
      continue;
    }

    if (flag in FLAG_ALIASES) {
      const key = FLAG_ALIASES[flag];
      const value = inlineValue ?? argv[++i];
      if (value !== undefined) (args as Record<string, string>)[key] = value;
      continue;
    }

    // Unknown flag: warn but don't fail hard — a future flag from a newer
    // client config shouldn't hard-break this server.
    process.stderr.write(`[seclayer-mcp] Warning: unrecognized flag "${flag}" ignored.\n`);
  }
  return args;
}

export interface ResolvedConfig {
  apiKey: string;
  baseUrl: string;
}

export type ConfigResult =
  | { ok: true; config: ResolvedConfig }
  | { ok: false; error: string };

const DEFAULT_BASE_URL = "https://seclayer.io";

export function resolveConfig(args: RawArgs, env: NodeJS.ProcessEnv): ConfigResult {
  const apiKey = args.key ?? env.SECLAYER_API_KEY;
  if (!apiKey) {
    return {
      ok: false,
      error:
        "No API key provided. Pass --key <key> or set the SECLAYER_API_KEY environment variable. " +
        "Generate a key from the Seclayer dashboard's Developer API Keys panel.",
    };
  }

  const rawBaseUrl = args.url ?? env.SECLAYER_API_URL ?? DEFAULT_BASE_URL;
  const baseUrl = rawBaseUrl.replace(/\/+$/, "");

  return { ok: true, config: { apiKey, baseUrl } };
}
