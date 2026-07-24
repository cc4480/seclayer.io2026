// Shared dependencies handed to each route-registration module, so route
// handlers keep the exact behavior they had as closures inside startServer
// (identity from the signed session, the background scan worker, the OOB
// collaborator) without server.ts owning every handler body.
import type express from "express";
import type { OobCollaborator } from "../oob.js";
import type { BolaIdentity } from "../../src/types.js";

export type ProcessScanJob = (
  scanId: string,
  allowActiveProbes: boolean,
  bolaIdentities?: [BolaIdentity, BolaIdentity],
  allowAggressiveProbes?: boolean,
) => void;

export interface RouteContext {
  requireAuth: express.RequestHandler;
  getUserId: (req: express.Request) => string;
  processScanJob: ProcessScanJob;
  oobCollaborator?: OobCollaborator;
  cookieOptions: express.CookieOptions;
  sessionCookie: string;
}
