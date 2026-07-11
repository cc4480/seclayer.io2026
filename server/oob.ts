import crypto from "crypto";
import { OobEvent } from "../src/types.js";

// Out-of-band collaborator. Seclayer's own public server doubles as the callback
// listener a classic pentest "collaborator"/OAST server provides: the scanner
// mints a unique URL, embeds it in a payload, and if the TARGET reaches back to
// that URL we have proof of a BLIND vulnerability (SSRF/RCE/XXE) that reflects
// nothing inline. This closes docs/confirmed-evidence-spec.md §7 #4.
//
// The scanner receives this via ScanOptions.oob so it never imports the DB — the
// collaborator is the only bridge, which keeps the scanner unit-testable with a
// fake (see server/scanner.test.ts).

export interface OobProbe {
  token: string; // unique per-probe secret embedded in the URL
  url: string;   // the collaborator URL to inject into a payload
}

export interface OobCollaborator {
  baseUrl: string;
  // Mint a fresh probe URL, registering its token so the public endpoint will
  // accept the target's callback for it.
  issue(scanId?: string): OobProbe;
  // Resolve with the first callback recorded for `token`, or null if none
  // arrives within `timeoutMs`. Polls the store on a short interval.
  poll(token: string, timeoutMs: number): Promise<OobEvent | null>;
}

// Minimal store surface the collaborator needs — satisfied by SqliteDb, or by a
// fake in tests. Kept narrow so neither side depends on the other's internals.
export interface OobStore {
  registerOobToken(token: string, scanId?: string): void;
  getOobEvents(token: string): OobEvent[];
}

const POLL_INTERVAL_MS = 400;

export function createOobCollaborator(store: OobStore, baseUrl: string): OobCollaborator {
  const base = baseUrl.replace(/\/+$/, "");
  return {
    baseUrl: base,
    issue(scanId?: string): OobProbe {
      // 24 random bytes → 48 hex chars: unguessable, so the public endpoint
      // can't be probed for valid tokens and a callback can't be forged.
      const token = crypto.randomBytes(24).toString("hex");
      store.registerOobToken(token, scanId);
      return { token, url: `${base}/api/oob/${token}` };
    },
    async poll(token: string, timeoutMs: number): Promise<OobEvent | null> {
      const deadline = Date.now() + Math.max(0, timeoutMs);
      // Fast path: a callback may already be recorded before we start polling.
      const existing = store.getOobEvents(token);
      if (existing.length > 0) return existing[0];
      while (Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
        const events = store.getOobEvents(token);
        if (events.length > 0) return events[0];
      }
      return null;
    },
  };
}
