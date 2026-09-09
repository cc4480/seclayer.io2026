// Detection validation.
//
// Every other check asks whether the scanner stays quiet when it should. This
// asks the opposite, which nothing else does: given a target with known,
// deliberately planted flaws, does the scanner find them? A scanner that
// reports nothing has a perfect false-positive rate — after a run of FP fixes,
// that is the failure mode to guard against, and only a target whose faults are
// known in advance can measure it.
//
// Serves a local fixture, scans it passively (the flaws here are all passively
// observable), and reports which planted flaws were found and which were missed.
//
//   SCAN_DEV_ALLOW_HOSTS=127.0.0.1 node --import tsx scripts/detection-check.ts
//
// Exit code is non-zero when something planted was missed, so it can gate CI.
import { createServer } from "node:http";
import { runDiagnostics } from "../server/scanner.js";
import { compileStaticFindings } from "../server/findings.js";

const INLINE_SECRETS = `
  const AWS_KEY = "AKIA3XKWQZJ7NRVB4TMD";
  const gh = "gho_16C7e42F292c6912E7710c838347Ae178B4a";
  const stripe = "sk_live_51H8xQ2eZvKYlo2CqL8xRtNmPfGhJkLwXyZ";
`;

const HOME = `<!doctype html>
<html><head><title>Detection Fixture</title></head>
<body>
  <h1>Fixture</h1>
  <script src="/app.js"></script>
  <script>${INLINE_SECRETS}</script>
  <script src="https://cdn.example.net/analytics.js"></script>
</body></html>`;

const SOURCE_MAP = JSON.stringify({
  version: 3,
  sources: ["src/app.ts", "src/billing.ts"],
  sourcesContent: ["export const a = 1;", "const K = 'x';"],
  mappings: "AAAA",
});

const routes: Record<string, { body: string; ct: string }> = {
  "/": { body: HOME, ct: "text/html" },
  "/app.js": { body: "console.log(1);\n//# sourceMappingURL=/app.js.map", ct: "application/javascript" },
  "/app.js.map": { body: SOURCE_MAP, ct: "application/json" },
  "/.env": { body: "DB_PASSWORD=hunter2\nSTRIPE_SECRET_KEY=sk_live_abc\nAPI_TOKEN=xyz\n", ct: "text/plain" },
  "/.git/HEAD": { body: "ref: refs/heads/main\n", ct: "text/plain" },
};

const server = createServer((req, res) => {
  const path = (req.url ?? "/").split("?")[0];
  const hit = routes[path];
  // Headers deliberately omitted: CSP, X-Frame-Options, X-Content-Type-Options,
  // Referrer-Policy. Present-and-verbose: Server / X-Powered-By.
  const headers: Record<string, string> = {
    "content-type": hit ? hit.ct : "text/plain",
    server: "nginx/1.14.0",
    "x-powered-by": "PHP/5.6.40",
  };
  if (path === "/") headers["set-cookie"] = "sessionid=abc123def456; Path=/"; // no Secure/HttpOnly
  res.writeHead(hit ? 200 : 404, headers);
  res.end(hit ? hit.body : "Not Found");
});

const EXPECTED = [
  { id: "csp", label: "Missing Content-Security-Policy", match: /Content-Security-Policy/i },
  { id: "xfo", label: "Missing X-Frame-Options", match: /X-Frame-Options|Clickjacking/i },
  { id: "xcto", label: "Missing X-Content-Type-Options", match: /X-Content-Type-Options|Sniff/i },
  { id: "cookie", label: "Session cookie missing flags", match: /Cookie "sessionid"/i },
  { id: "env", label: "Exposed .env file", match: /\.env|Critical Resource|Environment/i },
  { id: "git", label: "Exposed .git repository", match: /\.git|Critical Resource/i },
  { id: "sourcemap", label: "Exposed JavaScript source map", match: /source map/i },
  { id: "aws", label: "AWS access key in JavaScript", match: /AWS Access Key/i },
  { id: "github", label: "GitHub token in JavaScript", match: /GitHub/i },
  { id: "stripe", label: "Stripe secret key in JavaScript", match: /Stripe/i },
];

const port: number = await new Promise((resolve) => {
  server.listen(0, "127.0.0.1", () => resolve((server.address() as { port: number }).port));
});
process.env.SCAN_DEV_ALLOW_HOSTS = `127.0.0.1:${port},127.0.0.1`;
const target = `http://127.0.0.1:${port}/`;
console.log(`[detection] fixture on ${target}`);
console.log(`[detection] ${EXPECTED.length} planted flaws to find\n`);

let findings: { title: string; severity: string }[] = [];
try {
  const diag = await runDiagnostics(target, undefined, { allowActiveProbes: false });
  findings = compileStaticFindings(diag).findings;
} finally {
  server.close();
}

const titles = findings.map((f) => f.title);
const found = EXPECTED.filter((e) => titles.some((t) => e.match.test(t)));
const missed = EXPECTED.filter((e) => !titles.some((t) => e.match.test(t)));

console.log(`Findings returned: ${findings.length}`);
console.log(`\nDetected ${found.length}/${EXPECTED.length} planted flaws:`);
for (const e of found) console.log(`  [FOUND ] ${e.label}`);
for (const e of missed) console.log(`  [MISSED] ${e.label}`);

if (process.argv.includes("--list")) {
  console.log("\nEvery finding returned:");
  for (const f of findings) console.log(`  [${f.severity.toUpperCase().padEnd(8)}] ${f.title}`);
}

if (missed.length) {
  console.error(`\nFAIL — ${missed.length} planted flaw(s) not detected.`);
  process.exit(1);
}
console.log("\nPASS — every planted flaw was detected.");
