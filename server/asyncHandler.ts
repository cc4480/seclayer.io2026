import type { NextFunction, Request, RequestHandler, Response } from "express";

/**
 * Wraps an async Express handler so a rejected promise reaches the JSON
 * error-handling middleware in server.ts instead of leaving the request
 * hanging with no response ever sent.
 *
 * Express 4 does not do this on its own: an async handler that throws (an
 * unguarded await on a DB call, an external API call, anything) rejects a
 * promise Express never looks at, since it only knows to route errors passed
 * to `next(err)` — a synchronous throw inside a synchronous handler, or an
 * explicit `next(err)` call, both work; a rejected promise from an async
 * function does neither. The request is then only ever seen by the
 * process-level unhandledRejection listener, which just logs — nothing
 * responds to the client, which sits until its own timeout. See the
 * session-resolving middleware in server.ts, fixed the same way for the same
 * reason, for the concrete version of this that was actually hit.
 *
 * A handler with its own try/catch that always sends a response is
 * unaffected by wrapping it here too — this only ever does anything on a
 * path that would otherwise have gone unhandled.
 */
export function asyncHandler<Req extends Request = Request, Res extends Response = Response>(
  fn: (req: Req, res: Res, next: NextFunction) => Promise<unknown>,
): RequestHandler {
  return (req, res, next) => {
    Promise.resolve(fn(req as Req, res as Res, next)).catch(next);
  };
}
