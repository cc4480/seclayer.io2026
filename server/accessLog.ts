// Minimal, dependency-free access logging. Emits one structured line per HTTP
// request (method, path, status, duration, client IP) once the response
// finishes, giving production request-level observability without pulling in a
// logging framework. The health-check path is skipped by default so
// orchestrator liveness polling doesn't drown the log.
import type express from 'express';

export interface AccessLogOptions {
  // Paths to never log (exact match on req.path). Defaults to the health probe.
  skipPaths?: string[];
  // Sink for the formatted line; overridable in tests. Defaults to console.log.
  write?: (line: string) => void;
}

export function formatAccessLogLine(parts: {
  method: string;
  path: string;
  status: number;
  durationMs: number;
  ip: string;
}): string {
  const { method, path, status, durationMs, ip } = parts;
  return `[access] ${method} ${path} ${status} ${durationMs}ms ip=${ip}`;
}

export function accessLog(options: AccessLogOptions = {}) {
  const skip = new Set(options.skipPaths ?? ['/api/system/health']);
  const write = options.write ?? ((line: string) => console.log(line));

  return function accessLogMiddleware(
    req: express.Request,
    res: express.Response,
    next: express.NextFunction,
  ) {
    if (skip.has(req.path)) return next();
    const start = process.hrtime.bigint();
    res.on('finish', () => {
      const durationMs = Number(process.hrtime.bigint() - start) / 1e6;
      write(
        formatAccessLogLine({
          method: req.method,
          path: req.path,
          status: res.statusCode,
          durationMs: Math.round(durationMs),
          ip: req.ip || req.socket?.remoteAddress || 'unknown',
        }),
      );
    });
    next();
  };
}
