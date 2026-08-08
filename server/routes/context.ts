// Shared dependencies handed to each route-registration module, so route
// handlers keep the exact behavior they had as closures inside startServer
// (identity from the signed session, the background scan worker, the OOB
// collaborator) without server.ts owning every handler body.
import type express from "express";
import type { OobCollaborator } from "../oob.js";
import type { BolaIdentity, LoginCredentials } from "../../src/types.js";

export type ProcessScanJob = (
  scanId: string,
  allowActiveProbes: boolean,
  bolaIdentities?: [BolaIdentity, BolaIdentity],
  allowAggressiveProbes?: boolean,
  loginCredentials?: LoginCredentials,
) => void;

export type ProcessNmapScanJob = (scanId: string) => void;

export interface RouteContext {
  requireAuth: express.RequestHandler;
  getUserId: (req: express.Request) => string;
  processScanJob: ProcessScanJob;
  processNmapScanJob: ProcessNmapScanJob;
  // Whether the nmap binary was detected at boot — probed once (see
  // server/nmap/detect.ts) and threaded through here rather than read from
  // the singleton directly in each route module, matching how
  // processScanJob/oobCollaborator are already injected.
  nmapAvailable: boolean;
  oobCollaborator?: OobCollaborator;
  cookieOptions: express.CookieOptions;
  sessionCookie: string;
}
