// Automated SQLite snapshot worker. On a configurable cadence it writes a
// consistent, compacted copy of the database (VACUUM INTO) to a backup
// directory and prunes all but the most recent N snapshots. This closes the
// "one volume, no backup story" gap: a snapshot is a single self-contained file
// an operator can copy off-box (cron rsync, object-store upload, volume
// snapshot) for point-in-time recovery.
//
// Config (all optional):
//   BACKUP_ENABLED           "false" disables it entirely (default on, except
//                            for an in-memory DB which can't be snapshotted).
//   BACKUP_DIR               where snapshots are written (default: a `backups/`
//                            dir next to the database file).
//   BACKUP_INTERVAL_HOURS    cadence in hours (default 24).
//   BACKUP_RETENTION         number of snapshots to keep (default 7).
import fs from 'fs';
import path from 'path';
import { db } from './db.js';

const DEFAULT_INTERVAL_HOURS = 24;
const DEFAULT_RETENTION = 7;
const SNAPSHOT_RE = /^seclayer-.*\.sqlite$/;

export interface BackupConfig {
  dbPath: string;
  inMemory: boolean;
  disabled: boolean;
  dir: string;
  intervalHours: number;
  retention: number;
}

export function backupConfig(): BackupConfig {
  const dbPath = process.env.DB_PATH || path.join(process.cwd(), 'data.sqlite');
  const inMemory = dbPath === ':memory:' || dbPath.startsWith('file::memory:');
  // This worker snapshots the SQLite FILE. When DATABASE_URL is set the live
  // database is Postgres and that file is not the data — it is a stale or
  // absent artifact, usually on ephemeral container storage. Snapshotting it
  // produced backups of nothing while logging as though the database were
  // protected, which is worse than not running: it reads as a working backup.
  // Postgres backups belong to the provider (Railway PITR) or to pg_dump.
  const postgres = !!process.env.DATABASE_URL;
  const disabled = process.env.BACKUP_ENABLED === 'false' || inMemory || postgres;
  const dir = process.env.BACKUP_DIR || path.join(path.dirname(dbPath), 'backups');
  const intervalHours = Number(process.env.BACKUP_INTERVAL_HOURS) || DEFAULT_INTERVAL_HOURS;
  const retention = Math.max(1, Number(process.env.BACKUP_RETENTION) || DEFAULT_RETENTION);
  return { dbPath, inMemory, disabled, dir, intervalHours, retention };
}

// Filesystem-safe snapshot filename for a given instant. ISO timestamps sort
// lexicographically in chronological order, so a plain lexical sort of the
// directory is also newest-last — which the pruner relies on.
export function snapshotFilename(now: Date): string {
  return `seclayer-${now.toISOString().replace(/[:.]/g, '-')}.sqlite`;
}

// Deletes the oldest snapshots so at most `retention` remain. Only touches files
// matching our own snapshot naming, so an operator's other files in the dir are
// never removed. Returns the list of deleted filenames.
export function pruneOldBackups(dir: string, retention: number): string[] {
  if (!fs.existsSync(dir)) return [];
  const files = fs.readdirSync(dir).filter((f) => SNAPSHOT_RE.test(f)).sort();
  const excess = files.length - retention;
  const deleted: string[] = [];
  for (let i = 0; i < excess; i++) {
    fs.unlinkSync(path.join(dir, files[i]));
    deleted.push(files[i]);
  }
  return deleted;
}

// Runs one backup pass: snapshot + prune. Returns the snapshot path, or null if
// backups are disabled (e.g. in-memory DB). Throws only on a real I/O failure,
// which the worker tick catches so one failed backup never crashes the process.
export async function runBackup(now: Date = new Date()): Promise<string | null> {
  const cfg = backupConfig();
  if (cfg.disabled) return null;
  fs.mkdirSync(cfg.dir, { recursive: true });
  const dest = path.join(cfg.dir, snapshotFilename(now));
  // false = this backend does not write file snapshots (Postgres). Returning
  // null keeps the caller from announcing a file that was never created, and
  // skips the prune — pruning against a directory nothing is being added to
  // would only delete the last snapshots the previous backend left behind.
  const wrote = (await db.backupTo(dest));
  if (!wrote) return null;
  pruneOldBackups(cfg.dir, cfg.retention);
  return dest;
}

export function startBackupWorker(): NodeJS.Timeout | undefined {
  const cfg = backupConfig();
  if (cfg.disabled) {
    if (cfg.inMemory) return undefined; // silent: tests / ephemeral runs
    // Say WHICH reason. An operator scanning logs for "are my backups running"
    // must not read a Postgres deployment as a switched-off one, or vice versa.
    console.log(
      process.env.DATABASE_URL
        ? '[backup] Postgres is the live database — this SQLite-file snapshotter is off. Backups are the provider\'s (e.g. Railway PITR) or pg_dump\'s.'
        : '[backup] BACKUP_ENABLED=false — automated database snapshots are off.',
    );
    return undefined;
  }
  const interval = setInterval(async () => {
    try {
      const dest = await runBackup();
      if (dest) console.log(`[backup] Wrote snapshot ${path.basename(dest)}.`);
    } catch (err) {
      console.error('[backup] Snapshot failed:', err);
    }
  }, cfg.intervalHours * 60 * 60 * 1000);

  // Take one immediately instead of waiting a whole interval, and use it to
  // report what is actually happening.
  //
  // Two bugs this closes. The timer only ever fired after intervalHours, so a
  // service redeployed more often than that never snapshotted once — the
  // schedule restarted every boot. And on a backend that cannot snapshot, the
  // startup line claimed snapshots were being written every N hours to a
  // directory nothing would ever be added to.
  void (async () => {
    try {
      const dest = await runBackup();
      if (dest) {
        console.log(`[backup] Snapshots every ${cfg.intervalHours}h to ${cfg.dir} (keeping ${cfg.retention}). Wrote ${path.basename(dest)}.`);
      } else {
        clearInterval(interval);
        console.warn(
          '[backup] This database backend does not write file snapshots — ' +
          'backups are handled by the platform (e.g. Railway PITR or ' +
          'scheduled database backups). NOTHING is being backed up by this ' +
          'process; make sure the platform side is actually enabled.',
        );
      }
    } catch (err) {
      console.error('[backup] Startup snapshot failed:', err);
    }
  })();
  interval.unref();
  return interval;
}
