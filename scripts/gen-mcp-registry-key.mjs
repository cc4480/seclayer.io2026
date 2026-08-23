// One-shot generator for the MCP Registry DNS-auth signing key. Produces the
// Ed25519 keypair the `mcp-publisher login dns` flow needs and the exact TXT
// record to add at the apex of seclayerio.ai. Replaces the openssl recipe in
// DISTRIBUTION.md §1b for machines without openssl (uses Node's crypto).
//
//   node scripts/gen-mcp-registry-key.mjs
//
// Writes mcp-server/key.pem (PEM private key) and mcp-server/.registry-login.local
// (the ready-to-run login command) — both gitignored. Prints the public TXT record.
import crypto from "node:crypto";
import { writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const DOMAIN = "seclayerio.ai";
const here = path.dirname(fileURLToPath(import.meta.url));
const mcpDir = path.join(here, "..", "mcp-server");

const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");

// Raw 32-byte Ed25519 keys are the trailing 32 bytes of the DER encodings.
const rawPub = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
const rawPriv = privateKey.export({ type: "pkcs8", format: "der" }).subarray(-32);
const pubB64 = rawPub.toString("base64");
const privHex = rawPriv.toString("hex");
const pem = privateKey.export({ type: "pkcs8", format: "pem" });

const txtValue = `v=MCPv1; k=ed25519; p=${pubB64}`;
const loginCmd = `mcp-publisher login dns --domain "${DOMAIN}" --private-key "${privHex}"`;

writeFileSync(path.join(mcpDir, "key.pem"), pem);
writeFileSync(
  path.join(mcpDir, ".registry-login.local"),
  `# MCP Registry DNS-auth login for ${DOMAIN} (SECRET — gitignored, do not share).\n` +
    `# Run this from mcp-server/ AFTER the TXT record below has propagated:\n${loginCmd}\n`,
);

console.log("=== MCP Registry DNS auth — add this TXT record at the APEX of " + DOMAIN + " ===");
console.log("Host/Name:  @   (i.e. " + DOMAIN + ", the apex — NOT a subdomain)");
console.log("Type:       TXT");
console.log("Value:      " + txtValue);
console.log("");
console.log("Saved: mcp-server/key.pem  and  mcp-server/.registry-login.local (both gitignored).");
console.log("After the TXT record propagates, run (from mcp-server/): mcp-publisher login dns … (see .registry-login.local)");
