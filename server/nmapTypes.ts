// Pipeline-internal shapes — the raw structure straight off fast-xml-parser,
// distinct from the persisted NmapResult in src/types.ts. Mirrors scanTypes.ts's
// split between DiagnosticResult (internal) and Scan/ScanEvidence (persisted).

export interface NmapParsedScript {
  id: string;
  output: string;
}

export interface NmapParsedPort {
  portid: number;
  protocol: string;
  state: string;
  service?: { name?: string; product?: string; version?: string; extrainfo?: string };
  scripts: NmapParsedScript[];
}

export interface NmapParsedOsMatch {
  name: string;
  accuracy: number;
}

export interface NmapParsedResult {
  state: 'up' | 'down';
  ports: NmapParsedPort[];
  osMatches: NmapParsedOsMatch[];
  hostScripts: NmapParsedScript[];
}
