import { test } from "node:test";
import assert from "node:assert/strict";
import { parseApiSpec, discoverAndParseApi } from "./openapi.js";

const TARGET = "https://target.test";

// --- OpenAPI 3.x -----------------------------------------------------------
const oas3 = {
  openapi: "3.0.1",
  servers: [{ url: "/api/v2" }],
  paths: {
    "/users": {
      get: { parameters: [{ name: "q", in: "query" }, { name: "limit", in: "query" }] },
      post: { requestBody: { content: { "application/json": { schema: { type: "object", properties: { email: {}, name: {} } } } } } },
    },
    "/users/{id}": {
      parameters: [{ name: "id", in: "path" }], // path-level, shared by all methods
      get: { parameters: [{ name: "expand", in: "query" }] },
    },
    "/health": { get: {} }, // no query params → nothing to fuzz
  },
};

test("OpenAPI 3: GET ops → query-param targets, path template substituted, server basePath applied", () => {
  const r = parseApiSpec(oas3, TARGET, { includePost: false });
  const gets = r.targets.filter((t) => t.method === "GET");
  assert.equal(r.targets.length, 2, "two GET ops with query params; /health skipped, POST excluded");
  const users = gets.find((t) => t.url.endsWith("/api/v2/users"));
  assert.ok(users, "servers[0].url basePath is applied");
  assert.deepEqual(users!.params.sort(), ["limit", "q"]);
  assert.equal(users!.source, "openapi");
  const byId = gets.find((t) => t.url.includes("/users/"));
  assert.equal(byId!.url, "https://target.test/api/v2/users/1", "{id} → placeholder, path param merged from path level");
  assert.deepEqual(byId!.params, ["expand"]);
  assert.ok(!r.targets.some((t) => t.url.endsWith("/health")), "GET with no query params is not fuzzable");
});

test("OpenAPI 3: POST ops only appear when includePost (aggressive) is set", () => {
  const off = parseApiSpec(oas3, TARGET, { includePost: false });
  assert.ok(!off.targets.some((t) => t.method === "POST"), "POST held back without the aggressive opt-in");

  const on = parseApiSpec(oas3, TARGET, { includePost: true });
  const post = on.targets.find((t) => t.method === "POST");
  assert.ok(post, "POST op included under includePost");
  assert.equal(post!.url, "https://target.test/api/v2/users");
  assert.equal(post!.contentType, "json");
  assert.deepEqual(post!.params.sort(), ["email", "name"], "JSON requestBody schema fields become body params");
});

// --- Swagger 2.0 -----------------------------------------------------------
const sw2 = {
  swagger: "2.0",
  host: "api.example.com", // MUST be ignored — same-origin only
  basePath: "/v1",
  paths: {
    "/search": { get: { parameters: [{ name: "term", in: "query" }] } },
    "/orders": { post: { parameters: [{ name: "body", in: "body", schema: { properties: { sku: {}, qty: {} } } }] } },
    "/upload": { post: { parameters: [{ name: "file", in: "formData" }, { name: "tag", in: "formData" }] } },
  },
};

test("Swagger 2.0: basePath, in:query, in:body(JSON) and in:formData(form); foreign host ignored", () => {
  const r = parseApiSpec(sw2, TARGET, { includePost: true });
  for (const t of r.targets) assert.ok(t.url.startsWith("https://target.test/v1/"), `same-origin + basePath: ${t.url}`);
  const get = r.targets.find((t) => t.method === "GET");
  assert.deepEqual(get!.params, ["term"]);
  const orders = r.targets.find((t) => t.url.endsWith("/orders"));
  assert.equal(orders!.contentType, "json");
  assert.deepEqual(orders!.params.sort(), ["qty", "sku"], "in:body schema.properties → JSON body fields");
  const upload = r.targets.find((t) => t.url.endsWith("/upload"));
  assert.equal(upload!.contentType, "form");
  assert.deepEqual(upload!.params.sort(), ["file", "tag"], "in:formData → form fields");
});

// --- $ref resolution -------------------------------------------------------
test("resolves $ref parameters and requestBody schemas", () => {
  const refSpec = {
    openapi: "3.0.0",
    components: {
      parameters: { Q: { name: "search", in: "query" } },
      schemas: { NewItem: { type: "object", properties: { title: {}, price: {} } } },
    },
    paths: {
      "/items": {
        get: { parameters: [{ $ref: "#/components/parameters/Q" }] },
        post: { requestBody: { content: { "application/json": { schema: { $ref: "#/components/schemas/NewItem" } } } } },
      },
    },
  };
  const r = parseApiSpec(refSpec, TARGET, { includePost: true });
  assert.deepEqual(r.targets.find((t) => t.method === "GET")!.params, ["search"], "$ref parameter resolved");
  assert.deepEqual(r.targets.find((t) => t.method === "POST")!.params.sort(), ["price", "title"], "$ref schema resolved");
});

test("maxOps caps how many operations are queued", () => {
  const paths: any = {};
  for (let i = 0; i < 50; i++) paths[`/r${i}`] = { get: { parameters: [{ name: "x", in: "query" }] } };
  const r = parseApiSpec({ openapi: "3.0.0", paths }, TARGET, { includePost: false, maxOps: 10 });
  assert.equal(r.targets.length, 10);
});

test("non-spec / malformed input yields no targets, never throws", () => {
  assert.equal(parseApiSpec({ hello: "world" }, TARGET, { includePost: true }).targets.length, 0);
  assert.equal(parseApiSpec(null, TARGET, { includePost: true }).targets.length, 0);
  assert.equal(parseApiSpec({ openapi: "3.0.0", paths: {} }, TARGET, { includePost: true }).targets.length, 0);
});

// --- discovery -------------------------------------------------------------
function mockFetch(routes: Record<string, { body: string; status?: number; ct?: string }>) {
  return async (u: string, _init: RequestInit) => {
    const path = new URL(u).pathname;
    const hit = routes[path];
    if (!hit) return new Response("not found", { status: 404 });
    return new Response(hit.body, { status: hit.status ?? 200, headers: { "content-type": hit.ct ?? "application/json" } });
  };
}

test("discoverAndParseApi finds a spec at a well-known path", async () => {
  const fetchFn = mockFetch({ "/v3/api-docs": { body: JSON.stringify(oas3) } });
  const r = await discoverAndParseApi(TARGET, fetchFn, { includePost: true });
  assert.ok(r, "spec discovered");
  assert.equal(new URL(r!.specUrl).pathname, "/v3/api-docs");
  assert.ok(r!.targets.length >= 2);
});

test("discoverAndParseApi honors an explicit non-standard spec URL first", async () => {
  const fetchFn = mockFetch({ "/internal/schema.json": { body: JSON.stringify(sw2) } });
  const r = await discoverAndParseApi(TARGET, fetchFn, { explicitUrl: "/internal/schema.json", includePost: true });
  assert.ok(r, "explicit URL used even though it isn't a well-known path");
  assert.equal(new URL(r!.specUrl).pathname, "/internal/schema.json");
});

test("discoverAndParseApi returns null when nothing is a valid spec", async () => {
  // 404 everywhere, plus a decoy: valid JSON that isn't a spec, and an HTML page.
  const fetchFn = mockFetch({
    "/openapi.json": { body: JSON.stringify({ just: "data" }) },
    "/swagger.json": { body: "<html>docs</html>", ct: "text/html" },
  });
  assert.equal(await discoverAndParseApi(TARGET, fetchFn, { includePost: true }), null);
});
