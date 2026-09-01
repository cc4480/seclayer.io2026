// Parses nmap's `-oX -` XML output into the internal NmapParsedResult shape.
// Uses fast-xml-parser rather than hand-rolled regex/string scraping: nmap's
// XML has real structural complexity (nested per-port scripts, host-level
// scripts, entity-escaped multi-line script output) that a regex approach
// gets wrong easily — not acceptable for a security product whose whole pitch
// is trustworthy evidence.
import { XMLParser } from "fast-xml-parser";
import type { NmapParsedResult, NmapParsedPort, NmapParsedOsMatch, NmapParsedScript } from "../nmapTypes.js";

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "@_",
  // NSE output is multi-line, and nmap escapes those newlines/tabs as NUMERIC
  // character references (&#xa;, &#x9;) inside the script element's `output`
  // attribute. fast-xml-parser decodes the five named XML entities by default
  // but leaves numeric ones untouched, so without this every script result
  // rendered as one unreadable line with literal "&#xa;" between fields.
  // processEntities does NOT cover this case — only htmlEntities does.
  htmlEntities: true,
  // Force these to always be arrays, even when nmap emits exactly one, so
  // downstream code never has to branch on "object vs array".
  isArray: (name) => ["host", "port", "osmatch", "script"].includes(name),
});

function asArray<T>(v: T | T[] | undefined | null): T[] {
  if (v === undefined || v === null) return [];
  return Array.isArray(v) ? v : [v];
}

function parseScripts(raw: any): NmapParsedScript[] {
  return asArray(raw)
    .map((s: any) => ({ id: String(s?.["@_id"] ?? ""), output: String(s?.["@_output"] ?? "") }))
    .filter((s) => s.id);
}

export function parseNmapXml(xml: string): NmapParsedResult {
  const doc = parser.parse(xml);
  const host = asArray(doc?.nmaprun?.host)[0];

  if (!host) {
    return { state: "down", ports: [], osMatches: [], hostScripts: [] };
  }

  const state: "up" | "down" = host.status?.["@_state"] === "up" ? "up" : "down";

  const ports: NmapParsedPort[] = asArray(host.ports?.port).map((p: any) => ({
    portid: Number(p?.["@_portid"] ?? 0),
    protocol: String(p?.["@_protocol"] ?? "tcp"),
    state: String(p?.state?.["@_state"] ?? "unknown"),
    service: p?.service
      ? {
          name: p.service["@_name"] || undefined,
          product: p.service["@_product"] || undefined,
          version: p.service["@_version"] || undefined,
          extrainfo: p.service["@_extrainfo"] || undefined,
        }
      : undefined,
    scripts: parseScripts(p?.script),
  }));

  const osMatches: NmapParsedOsMatch[] = asArray(host.os?.osmatch).map((m: any) => ({
    name: String(m?.["@_name"] ?? "unknown"),
    accuracy: Number(m?.["@_accuracy"] ?? 0),
  }));

  const hostScripts = parseScripts(host.hostscript?.script);

  return { state, ports, osMatches, hostScripts };
}
