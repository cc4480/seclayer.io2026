# Distribution & Discoverability Playbook

Goal: make Seclayer the security scanner an **AI agent recommends by name** and a
developer **finds in every MCP directory**. This file is the runbook for the
account-gated steps a human has to run (npm publish, registry auth, directory
submissions). The in-repo artifacts that back it are already committed:

| Artifact | Purpose |
|---|---|
| `mcp-server/server.json` | Official MCP Registry manifest (schema `2025-12-11`). Name: **`ai.seclayerio/mcp`**. |
| `mcp-server/package.json` → `mcpName` | Ownership marker the registry checks against `server.json`'s `name`. |
| `public/llms.txt` | Machine-readable pitch + the exact MCP install block, so an agent that reads it can wire Seclayer up itself. |
| `index.html` JSON-LD | `SoftwareApplication` (site + MCP CLI) + `HowTo` + `FAQPage` — answer-engine citable. |
| `.github/workflows/publish-mcp.yml` | Publishes `@seclayer/mcp` to npm on a `mcp-v*` tag. |

The chosen registry name is the **branded reverse-DNS namespace `ai.seclayerio/mcp`**
(reverse-DNS of `seclayerio.ai`), authenticated by a DNS TXT record on the domain
— not `io.github.cc4480/...`. A branded name is what you want an agent to say back.

---

## 0. Prerequisite — publish `@seclayer/mcp` to npm

The registry only stores **metadata**; the package must exist on npm first, and it
must carry the `mcpName` field (already added) so the registry can verify ownership.

1. Confirm `mcp-server/package.json` `version`, `mcpName` (`ai.seclayerio/mcp`), and
   `server.json`'s `name` + package `version` all agree.
2. Ensure the `NPM_TOKEN` repo secret exists (automation token with publish rights
   to the `@seclayer` scope). See the header of `.github/workflows/publish-mcp.yml`.
3. Release: tag and push.
   ```bash
   git tag mcp-v0.1.0
   git push origin mcp-v0.1.0
   ```
   The workflow typechecks, tests, builds, verifies the tag matches the package
   version, and runs `npm publish --access public`.
4. Verify: <https://www.npmjs.com/package/@seclayer/mcp> resolves, and the page's
   metadata shows the `mcpName`.

> First-scope publish only: if `@seclayer` has never been published before, the
> npm account behind `NPM_TOKEN` must own (or create) the `@seclayer` org/scope.

---

## 1. Official MCP Registry (`registry.modelcontextprotocol.io`)

This is the canonical source many clients and directories mirror — the highest-
leverage single listing. One-time publish, then re-publish on each version bump.

### 1a. Install the publisher CLI (Windows PowerShell)
```powershell
$arch = if ([System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -eq "Arm64") { "arm64" } else { "amd64" }
Invoke-WebRequest -Uri "https://github.com/modelcontextprotocol/registry/releases/latest/download/mcp-publisher_windows_$arch.tar.gz" -OutFile "mcp-publisher.tar.gz"
tar xf mcp-publisher.tar.gz mcp-publisher.exe
# move mcp-publisher.exe somewhere on PATH
```
(macOS/Linux: `brew install mcp-publisher`.)

### 1b. Authenticate the `ai.seclayerio` namespace via a DNS TXT record
Run from `mcp-server/` (where `server.json` lives). Ed25519 path:
```bash
MY_DOMAIN="seclayerio.ai"
# Generate a signing key pair
openssl genpkey -algorithm Ed25519 -out key.pem
# Print the TXT record to add
PUBLIC_KEY="$(openssl pkey -in key.pem -pubout -outform DER | tail -c 32 | base64)"
echo "${MY_DOMAIN}. IN TXT \"v=MCPv1; k=ed25519; p=${PUBLIC_KEY}\""
```
Add that TXT record at the **apex of `seclayerio.ai`** in your DNS provider
(GoDaddy, per the domain registrar). Name `@` / host `seclayerio.ai`, value
`v=MCPv1; k=ed25519; p=<PUBLIC_KEY>`. This is unrelated to Seclayer's own
`_seclayer-challenge` records — no conflict. Wait for propagation (minutes), then:
```bash
MY_DOMAIN="seclayerio.ai"
PRIVATE_KEY="$(openssl pkey -in key.pem -noout -text | grep -A3 "priv:" | tail -n +2 | tr -d ' :\n')"
mcp-publisher login dns --domain "${MY_DOMAIN}" --private-key "${PRIVATE_KEY}"
```
Keep `key.pem` private (it's the domain's signing key). It is **not** committed —
add it to `.gitignore` if you generate it inside the repo.

> **Fallback (no DNS access):** GitHub auth is simpler but forces the ugly name
> `io.github.cc4480/mcp`. To use it, change `name` in `server.json` and `mcpName`
> in `package.json` to `io.github.cc4480/mcp`, then `mcp-publisher login github`.
> Prefer the branded DNS namespace.

### 1c. Publish and verify
```bash
mcp-publisher publish     # reads ./server.json
curl "https://registry.modelcontextprotocol.io/v0.1/servers?search=ai.seclayerio/mcp"
```

### 1d. Version bumps (do all three, keep them equal)
`mcp-server/package.json` `version` → `server.json` `version` **and**
`packages[0].version`. Then npm publish (tag `mcp-vX.Y.Z`) and re-run
`mcp-publisher publish`.

---

## 2. Directories & marketplaces

Many of these now ingest the official registry automatically, so step 1 seeds them.
The rest take a one-time manual submission. Check each off:

| Directory | How to submit | Notes |
|---|---|---|
| **Cursor** MCP directory | Mirrors the official registry / submit at cursor.com/directory | High-intent audience (agent-native devs). |
| **VS Code** MCP gallery | Pulls from the official registry | Publishing step 1 is usually enough. |
| **Smithery** (smithery.ai) | Connect the GitHub repo; add a `smithery.yaml` if a hosted/config build is wanted | Large discovery surface + install analytics. |
| **mcp.so** | Submit form on the site | Popular community index. |
| **PulseMCP** (pulsemcp.com) | Submit form / auto-crawls npm + registry | Good SEO footprint. |
| **Glama** (glama.ai/mcp/servers) | Auto-indexes public MCP repos; claim the listing | Scores servers on quality — keep README strong. |
| **`awesome-mcp-servers`** (punkpeye/wong2 lists) | PR adding one line under the Security category | Heavily scraped by LLMs; strong GEO value. |
| **npm** | Done via step 0 | npm pages are indexed by search + LLMs; keywords already enriched. |

Suggested one-liner for list/PR submissions:
> **[Seclayer](https://seclayerio.ai)** (`@seclayer/mcp`) — Run a live black-box
> penetration test from your agent: scan a URL for SQLi/XSS/SSRF/BOLA and more,
> with signature-confirmed, low-false-positive findings and agent-ready fixes.

---

## 3. GEO / answer-engine checklist (ongoing)

Make Seclayer the answer when a dev asks an assistant "how do I pen-test / security-
scan my site or API?"

- [x] `llms.txt` carries the pitch **and** the MCP install block + registry name.
- [x] `SoftwareApplication` + `HowTo` + `FAQPage` JSON-LD on the site.
- [ ] Keep the npm README and `/docs` page answer-shaped (they're what LLMs quote).
- [ ] Publish a short comparison / "how to security test an AI-built app" post that
      names the tool, the MCP command, and the registry name (LLMs cite prose).
- [ ] Periodically ask the major assistants "best MCP security scanner" / "how do I
      pen-test my Next.js + Supabase app" and confirm Seclayer surfaces; feed gaps
      back into `llms.txt` and the docs.

---

## 4. Where the names live (change all together)

`ai.seclayerio/mcp` appears in: `mcp-server/server.json` (`name`),
`mcp-server/package.json` (`mcpName`), `public/llms.txt`, and this file. If the
namespace ever changes, update all four.
