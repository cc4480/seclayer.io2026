import crypto from "crypto";
import { Finding, Severity } from "../src/types.js";

// A declarative, nuclei-style detection engine. Each template describes one or
// more HTTP requests plus matchers; a match yields a Finding. New checks are
// added as data (see server/templates.ts) without touching engine code. All
// network I/O is performed via an injected, SSRF-safe fetch.

export type MatcherPart = "body" | "header" | "status";

export interface Matcher {
  type: "status" | "word" | "regex";
  part?: MatcherPart; // default "body" for word/regex
  status?: number[]; // for type "status"
  words?: string[]; // for type "word"
  regex?: string; // for type "regex"
  condition?: "and" | "or"; // combine words (default "or")
  negative?: boolean; // invert this matcher's result
}

export interface TemplateRequest {
  method?: "GET" | "POST";
  path: string;
  headers?: Record<string, string>;
  body?: string;
  matchers: Matcher[];
  matchersCondition?: "and" | "or"; // combine matchers (default "and")
}

export interface Template {
  id: string;
  name: string;
  severity: Severity;
  category: "DAST" | "SAST" | "IAST" | "SCA" | "EASM" | "RED_TEAM";
  confidence?: "low" | "medium" | "high";
  description: string;
  fix: string;
  requests: TemplateRequest[];
  // Optional tech tags (e.g. "wordpress", "spring"). A tagged template only
  // runs when one of its tags is in the detected tech profile; untagged
  // templates are generic and always run.
  tags?: string[];
}

// Selects which templates to run for a target: all generic (untagged)
// templates, plus tagged templates whose tech was detected. Keeps large packs
// fast by skipping framework-specific checks on irrelevant stacks. Pure.
export function selectTemplates(templates: Template[], activeTags: Set<string>): Template[] {
  return templates.filter((t) => !t.tags || t.tags.length === 0 || t.tags.some((tag) => activeTags.has(tag)));
}

export interface ResponseView {
  status: number;
  body: string;
  headers: string; // serialized "key: value\n" lines
}

function evalMatcher(m: Matcher, r: ResponseView): boolean {
  let result = false;
  if (m.type === "status") {
    result = !!m.status && m.status.includes(r.status);
  } else {
    const hay = m.part === "header" ? r.headers : m.part === "status" ? String(r.status) : r.body;
    if (m.type === "word" && m.words && m.words.length) {
      const cond = m.condition || "or";
      result = cond === "and" ? m.words.every((w) => hay.includes(w)) : m.words.some((w) => hay.includes(w));
    } else if (m.type === "regex" && m.regex) {
      try {
        // Multiline + case-insensitive: ^/$ match line boundaries as authors
        // expect. JS does not support inline (?m) flags, so set them here.
        result = new RegExp(m.regex, "im").test(hay);
      } catch {
        result = false;
      }
    }
  }
  return m.negative ? !result : result;
}

// Pure matcher evaluation — the heart of the engine, fully unit-testable.
export function matchResponse(
  matchers: Matcher[],
  condition: "and" | "or" | undefined,
  r: ResponseView,
): boolean {
  if (!matchers || matchers.length === 0) return false;
  const results = matchers.map((m) => evalMatcher(m, r));
  return (condition || "and") === "and" ? results.every(Boolean) : results.some(Boolean);
}

function toFinding(t: Template, matchedUrl: string): Finding {
  let where = matchedUrl;
  try {
    where = new URL(matchedUrl).pathname;
  } catch {}
  return {
    id: "f_tpl_" + crypto.randomBytes(4).toString("hex"),
    title: t.name,
    description: `${t.description} (Confirmed at ${where}.)`,
    severity: t.severity,
    confidence: t.confidence || "high",
    fix: t.fix,
    category: t.category,
  };
}

type FetchFn = (url: string, init: RequestInit) => Promise<Response>;

// Runs a single template; returns a Finding on the first request that matches.
export async function runTemplate(
  t: Template,
  baseUrl: string,
  fetchFn: FetchFn,
  timeoutMs = 3500,
): Promise<Finding | null> {
  for (const req of t.requests) {
    let url: string;
    try {
      url = new URL(req.path, baseUrl).toString();
    } catch {
      continue;
    }
    const ctl = new AbortController();
    const id = setTimeout(() => ctl.abort(), timeoutMs);
    try {
      const res = await fetchFn(url, {
        method: req.method || "GET",
        headers: req.headers,
        body: req.body,
        signal: ctl.signal,
      });
      const body = (await res.text().catch(() => "")).slice(0, 200_000);
      let headers = "";
      res.headers.forEach((v, k) => {
        headers += `${k}: ${v}\n`;
      });
      if (matchResponse(req.matchers, req.matchersCondition, { status: res.status, body, headers })) {
        return toFinding(t, url);
      }
    } catch {
      /* request failed / aborted — no match */
    } finally {
      clearTimeout(id);
    }
  }
  return null;
}

// Runs all templates against a base origin with a bounded worker pool.
export async function runTemplates(
  baseUrl: string,
  fetchFn: FetchFn,
  templates: Template[],
  concurrency = 4,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  let i = 0;
  async function worker() {
    while (i < templates.length) {
      const t = templates[i++];
      const f = await runTemplate(t, baseUrl, fetchFn);
      if (f) findings.push(f);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, templates.length) }, () => worker()));
  return findings;
}
