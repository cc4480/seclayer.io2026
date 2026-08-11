// API-first testing: discover an OpenAPI (3.x) / Swagger (2.0) document at the
// target and turn every declared operation into the SAME InjectableTarget shape
// the parameter fuzzer already consumes (server/paramFuzzer.ts). This reaches
// the *declared* API surface — every path, method, query param and JSON/form
// body field — instead of only what the HTML/JS crawl happened to reference.
//
// Design notes that keep this safe and self-contained:
//  - Same-origin only. Even when a spec's `servers`/`host` names another origin,
//    we keep just its PATH and issue requests against the scan target's origin,
//    so ownership-gating and the SSRF guard still bound everything.
//  - Path templates (`/users/{id}`) get a benign placeholder; the fuzzer injects
//    into query params (GET) and body fields (POST), which is its native surface.
//    Path-parameter injection is a documented follow-up, not covered here.
//  - JSON specs only (no YAML dependency). Swagger-UI backends serve JSON at the
//    discovery paths below, which is the common case.
import type { InjectableTarget } from "./crawler.js";

type FetchFn = (url: string, init: RequestInit) => Promise<Response>;

export interface ApiSchemaResult {
  specUrl: string;
  format: string; // human label, e.g. "OpenAPI 3.0.1" / "Swagger 2.0"
  operationCount: number; // GET/POST operations that yielded a fuzzable target
  targets: InjectableTarget[];
}

// Common, well-known locations a JSON spec is served from (Swagger UI / springdoc
// / FastAPI / Swashbuckle / Redoc defaults). Tried concurrently; first valid wins.
export const SPEC_PATHS: readonly string[] = [
  "/openapi.json",
  "/openapi",
  "/swagger.json",
  "/swagger/v1/swagger.json",
  "/swagger/v2/swagger.json",
  "/v3/api-docs",
  "/v2/api-docs",
  "/api-docs",
  "/api-docs.json",
  "/api/openapi.json",
  "/api/swagger.json",
  "/api/v1/openapi.json",
  "/.well-known/openapi.json",
];

const DEFAULT_MAX_OPS = 40;
const PLACEHOLDER = "1"; // benign value substituted for `{pathParam}` templates

// Resolve a `$ref` (and chains of them) within the spec. Handles the JSON-pointer
// escaping (~1 => "/", ~0 => "~"). Returns the node, or the input unchanged when
// it isn't a ref / can't be resolved.
function deref(spec: any, node: any, depth = 0): any {
  if (!node || typeof node !== "object" || !node.$ref || depth > 12) return node;
  const path = String(node.$ref).replace(/^#\//, "").split("/");
  let cur: any = spec;
  for (const raw of path) {
    const key = decodeURIComponent(raw).replace(/~1/g, "/").replace(/~0/g, "~");
    cur = cur == null ? undefined : cur[key];
  }
  return deref(spec, cur, depth + 1);
}

// Collect property names from a (possibly $ref'd / allOf-composed) JSON schema.
function schemaFieldNames(spec: any, schema: any, depth = 0): string[] {
  const s = deref(spec, schema);
  if (!s || typeof s !== "object" || depth > 6) return [];
  const out = new Set<string>();
  if (s.properties && typeof s.properties === "object") {
    for (const k of Object.keys(s.properties)) out.add(k);
  }
  for (const part of ([] as any[]).concat(s.allOf || [], s.oneOf || [], s.anyOf || [])) {
    for (const n of schemaFieldNames(spec, part, depth + 1)) out.add(n);
  }
  return [...out];
}

// Normalize a list of parameter objects (deref'd) to {name, in}.
function paramList(spec: any, params: any): Array<{ name: string; in: string }> {
  if (!Array.isArray(params)) return [];
  const out: Array<{ name: string; in: string }> = [];
  for (const raw of params) {
    const p = deref(spec, raw);
    if (p && typeof p.name === "string" && typeof p.in === "string") out.push({ name: p.name, in: p.in });
  }
  return out;
}

// Path-only base (same-origin enforced): OpenAPI 3 `servers[0].url` or Swagger 2
// `basePath`, reduced to a pathname on the scan target's own origin.
function apiBasePath(spec: any, origin: string): string {
  try {
    if (spec.openapi && Array.isArray(spec.servers) && spec.servers[0] && typeof spec.servers[0].url === "string") {
      // `new URL(raw, origin)` resolves a relative server URL; for an absolute one
      // we still take only the pathname, discarding any foreign host (same-origin).
      return new URL(spec.servers[0].url, origin).pathname.replace(/\/+$/, "");
    }
  } catch { /* fall through */ }
  if (spec.swagger === "2.0" && typeof spec.basePath === "string") return spec.basePath.replace(/\/+$/, "");
  return "";
}

function looksLikeSpec(o: any): boolean {
  return !!o && typeof o === "object" && (typeof o.openapi === "string" || o.swagger === "2.0") && !!o.paths && typeof o.paths === "object";
}

function specFormat(spec: any): string {
  if (typeof spec.openapi === "string") return `OpenAPI ${spec.openapi}`;
  if (spec.swagger === "2.0") return "Swagger 2.0";
  return "OpenAPI";
}

// Parse an already-fetched spec object into fuzzable targets. GET operations
// always yield targets (reads); POST operations only when `includePost` is set
// (they can create state — held to the aggressive opt-in by the caller).
export function parseApiSpec(
  spec: any,
  targetUrl: string,
  opts: { includePost: boolean; maxOps?: number } = { includePost: false },
): { format: string; operationCount: number; targets: InjectableTarget[] } {
  const targets: InjectableTarget[] = [];
  if (!looksLikeSpec(spec)) return { format: "unknown", operationCount: 0, targets };

  let origin: string;
  try {
    origin = new URL(/^https?:\/\//i.test(targetUrl) ? targetUrl : "https://" + targetUrl).origin;
  } catch {
    return { format: specFormat(spec), operationCount: 0, targets };
  }
  const base = apiBasePath(spec, origin);
  const maxOps = opts.maxOps ?? DEFAULT_MAX_OPS;
  const methods = opts.includePost ? ["get", "post"] : ["get"];
  const seen = new Set<string>();
  let operationCount = 0;

  for (const [rawPath, pathItemRaw] of Object.entries<any>(spec.paths)) {
    if (operationCount >= maxOps) break;
    const pathItem = deref(spec, pathItemRaw);
    if (!pathItem || typeof pathItem !== "object") continue;
    // Parameters declared once for the whole path apply to every operation on it.
    const sharedParams = paramList(spec, pathItem.parameters);
    const concretePath = rawPath.replace(/\{[^}]+\}/g, PLACEHOLDER);
    const urlBase = origin + base + (concretePath.startsWith("/") ? concretePath : "/" + concretePath);

    for (const method of methods) {
      if (operationCount >= maxOps) break;
      const op = deref(spec, pathItem[method]);
      if (!op || typeof op !== "object") continue;
      const params = [...sharedParams, ...paramList(spec, op.parameters)];

      if (method === "get") {
        const query = [...new Set(params.filter((p) => p.in === "query").map((p) => p.name))];
        if (query.length === 0) continue; // nothing on a GET the fuzzer can inject into
        const key = "GET " + urlBase;
        if (seen.has(key)) continue;
        seen.add(key);
        targets.push({ url: urlBase, method: "GET", params: query, source: "openapi" });
        operationCount++;
        continue;
      }

      // POST: prefer a request body's fields; support OpenAPI 3 requestBody,
      // Swagger 2 `in: body` (JSON) and `in: formData` (form).
      let fields: string[] = [];
      let contentType: "json" | "form" = "json";
      const reqBody = deref(spec, op.requestBody);
      if (reqBody && reqBody.content && typeof reqBody.content === "object") {
        const json = reqBody.content["application/json"];
        const form = reqBody.content["application/x-www-form-urlencoded"] || reqBody.content["multipart/form-data"];
        if (json && json.schema) { fields = schemaFieldNames(spec, json.schema); contentType = "json"; }
        else if (form && form.schema) { fields = schemaFieldNames(spec, form.schema); contentType = "form"; }
      }
      if (fields.length === 0) {
        // Swagger 2 body / formData parameters.
        const bodyParam = (Array.isArray(op.parameters) ? op.parameters : []).map((p: any) => deref(spec, p)).find((p: any) => p && p.in === "body");
        if (bodyParam && bodyParam.schema) { fields = schemaFieldNames(spec, bodyParam.schema); contentType = "json"; }
        else {
          const formData = params.filter((p) => p.in === "formData").map((p) => p.name);
          if (formData.length) { fields = [...new Set(formData)]; contentType = "form"; }
        }
      }
      if (fields.length === 0) continue;
      const key = "POST " + urlBase;
      if (seen.has(key)) continue;
      seen.add(key);
      targets.push({ url: urlBase, method: "POST", params: [...new Set(fields)], source: "openapi", contentType });
      operationCount++;
    }
  }

  return { format: specFormat(spec), operationCount, targets };
}

// Fetch one candidate spec URL and return the parsed JSON if it is a spec.
async function tryFetchSpec(specUrl: string, fetchFn: FetchFn): Promise<any | null> {
  const ctl = new AbortController();
  const id = setTimeout(() => ctl.abort(), 4500);
  try {
    const res = await fetchFn(specUrl, { headers: { Accept: "application/json" }, signal: ctl.signal });
    if (!res.ok) return null;
    const ct = (res.headers.get("content-type") || "").toLowerCase();
    // Guard against huge/binary bodies; specs are JSON text.
    const text = (await res.text()).slice(0, 4_000_000);
    if (ct.includes("html")) return null;
    const obj = JSON.parse(text);
    return looksLikeSpec(obj) ? obj : null;
  } catch {
    return null;
  } finally {
    clearTimeout(id);
  }
}

// Discover + parse in one call. Tries an explicit spec URL first (owner-supplied),
// then the well-known paths concurrently, returning the first that parses as a
// valid spec. Returns null when no spec is found. Never throws.
export async function discoverAndParseApi(
  targetUrl: string,
  fetchFn: FetchFn,
  opts: { explicitUrl?: string; includePost?: boolean; maxOps?: number } = {},
): Promise<ApiSchemaResult | null> {
  let origin: string;
  try {
    origin = new URL(/^https?:\/\//i.test(targetUrl) ? targetUrl : "https://" + targetUrl).origin;
  } catch {
    return null;
  }

  const candidates: string[] = [];
  if (opts.explicitUrl) {
    try { candidates.push(new URL(opts.explicitUrl, origin).toString()); } catch { /* ignore bad URL */ }
  }
  for (const p of SPEC_PATHS) candidates.push(origin + p);

  // Explicit URL is checked first on its own (owner intent wins); then the
  // well-known paths concurrently for speed.
  let specUrl = "";
  let spec: any = null;
  if (opts.explicitUrl && candidates.length) {
    spec = await tryFetchSpec(candidates[0], fetchFn);
    if (spec) specUrl = candidates[0];
  }
  if (!spec) {
    const pathCandidates = candidates.slice(opts.explicitUrl ? 1 : 0);
    const results = await Promise.all(
      pathCandidates.map(async (u) => ({ u, spec: await tryFetchSpec(u, fetchFn) })),
    );
    const hit = results.find((r) => r.spec);
    if (hit) { spec = hit.spec; specUrl = hit.u; }
  }
  if (!spec) return null;

  const parsed = parseApiSpec(spec, targetUrl, { includePost: !!opts.includePost, maxOps: opts.maxOps });
  if (parsed.targets.length === 0) return null;
  return { specUrl, format: parsed.format, operationCount: parsed.operationCount, targets: parsed.targets };
}
