// In-memory live event bus for the real-time scan ticker. As a scan runs, the
// diagnostics pipeline emits fine-grained events (recon phases, each red-team /
// aggressive injection as it fires, confirmed findings, and interleaved DeepSeek
// Flash narration). The ScanProgress UI polls GET /api/scans/:id/events?since=N
// and appends new lines, so the user watches the scan happen live.
//
// Deliberately in-memory (not the DB): a scan finishes in seconds–minutes and is
// watched live, so durability isn't needed here. The worker persists the final
// feed into the scan's narrationLog on completion, so re-opening a finished scan
// still renders it (see server/scanWorker.ts + src/components/scanProgress/scanLogs.ts).

export type EventChannel = "system" | "recon" | "probe" | "result" | "flash";

export interface LiveEvent {
  seq: number; // monotonic per scan; the cursor the client polls with
  ts: number; // epoch ms
  channel: EventChannel;
  text: string;
}

// The callback the pipeline receives (via ScanOptions.emit) to report a step.
import { db } from "./db.js";

export type EmitFn = (channel: EventChannel, text: string) => void;

// A handle the worker holds for the duration of one scan.
export interface ScanEventStream {
  emit: EmitFn;
  close: () => void;
}

interface StreamState {
  events: LiveEvent[];
  seq: number;
  closedAt?: number;
}

// Bound so a pathological scan (or a bug) can't grow the buffer without limit.
// A live viewer polling every ~1s keeps up well within this window.
const MAX_EVENTS = 500;
// How long a closed scan's feed lingers so a slow poller can still drain the
// tail after completion before it's evicted.
const EVICT_AFTER_MS = 5 * 60 * 1000;

const streams = new Map<string, StreamState>();

// Lazy eviction: runs on each open()/emit() rather than on a timer, so the
// module holds no interval and adds nothing to shut down.
function sweep(): void {
  const now = Date.now();
  for (const [id, s] of streams) {
    if (s.closedAt !== undefined && now - s.closedAt > EVICT_AFTER_MS) {
      streams.delete(id);
    }
  }
}

// Begin (or restart) a scan's event stream and return the worker's handle.
export function openStream(scanId: string): ScanEventStream {
  sweep();
  const state: StreamState = { events: [], seq: 0 };
  streams.set(scanId, state);
  return {
    emit: (channel, text) => {
      const t = (text ?? "").toString();
      if (!t.trim()) return;
      state.seq += 1;
      const ev: LiveEvent = { seq: state.seq, ts: Date.now(), channel, text: t };
      state.events.push(ev);
      if (state.events.length > MAX_EVENTS) state.events.splice(0, state.events.length - MAX_EVENTS);
      // Write through so a poll that lands on another instance can still see
      // this feed. Queued, not awaited: emit() sits in the scanner's hot loop
      // and must not take a database round-trip per event, and the ticker is
      // cosmetic — a failed flush must never fail the scan.
      if (sharedEnabled) { pending.push({ scanId, ev }); scheduleFlush(); }
    },
    close: () => {
      const s = streams.get(scanId);
      if (s) s.closedAt = Date.now();
      // Flush the tail immediately: the last events of a scan are the ones a
      // viewer is most likely to be waiting on, and the timer may not fire
      // again before the poll arrives.
      if (sharedEnabled) void flushNow();
    },
  };
}

// Read events newer than `cursor` (a seq). `found` distinguishes "stream exists
// but nothing new" from "no stream for this scan" (e.g. a finished scan whose
// feed has been evicted — the client then falls back to narrationLog).
// --- cross-instance sharing -------------------------------------------------
//
// The scan runs on ONE instance and buffers its events in the map above. With
// more than one replica the client's poll can land on an instance that never
// ran the scan, which sees no stream and reports found:false — the ticker then
// silently shows nothing for a scan that is running perfectly well.
//
// So emit() also writes through to the database, and getSince() falls back to
// that copy when it has no local stream. Local memory stays the fast path: a
// poll served by the instance running the scan never touches the database.
let sharedEnabled = false;
const pending: { scanId: string; ev: LiveEvent }[] = [];
let flushTimer: NodeJS.Timeout | undefined;
// Batched rather than per-event: a scan emits in bursts, and this sits inside
// the scanner's loop. 400ms is well under the client's ~1s poll, so the delay
// is invisible while cutting writes by an order of magnitude.
const FLUSH_MS = 400;

async function flushNow(): Promise<void> {
  if (!pending.length) return;
  const batch = pending.splice(0, pending.length);
  const byScan = new Map<string, LiveEvent[]>();
  for (const { scanId, ev } of batch) {
    const list = byScan.get(scanId) ?? [];
    list.push(ev);
    byScan.set(scanId, list);
  }
  for (const [scanId, events] of byScan) {
    try {
      await db.appendScanEvents(scanId, events);
    } catch (err: any) {
      // Never surface as a scan failure: this feed is cosmetic and the client
      // already degrades to the stored narration log.
      console.warn('[scanEvents] could not persist events for', scanId, '-', err?.message || err);
    }
  }
}

function scheduleFlush(): void {
  if (flushTimer) return;
  flushTimer = setTimeout(() => {
    flushTimer = undefined;
    void flushNow();
  }, FLUSH_MS);
  flushTimer.unref?.();
}

// Call once at boot. Keyed on DATABASE_URL, the same signal createDb() uses to
// pick a networked backend: on SQLite there is exactly one instance by
// construction, so the in-memory feed is already correct and sharing it would
// only add writes.
// `enabled` defaults to the DATABASE_URL signal but is injectable so the
// cross-instance path can be exercised against any backend rather than only
// wherever a Postgres happens to be reachable.
export function installSharedScanEvents(enabled = !!process.env.DATABASE_URL): boolean {
  if (!enabled) return false;
  sharedEnabled = true;
  // Fire-and-forget for the same reason as the rate limiter's: a slow CREATE
  // must not block boot, and a failure degrades the ticker rather than the scan.
  void db.ensureScanEventSchema().catch((err: any) =>
    console.error('[scanEvents] could not ensure scan_events exists — the live ticker will not cross instances:', err?.message || err));
  return true;
}

// Drop a finished scan's rows. The in-memory copy is evicted by sweep(); this is
// the shared copy's equivalent so the table does not grow without bound.
export async function discardSharedEvents(scanId: string): Promise<void> {
  if (!sharedEnabled) return;
  try {
    await db.deleteScanEvents(scanId);
  } catch { /* best effort — a stale feed is harmless next to a failed scan */ }
}

export async function getSince(
  scanId: string,
  cursor: number,
): Promise<{ events: LiveEvent[]; cursor: number; found: boolean }> {
  const s = streams.get(scanId);
  if (!s) {
    // No local stream. Either another instance is running this scan, or it
    // finished and was evicted here. Both are answered by the shared copy.
    if (!sharedEnabled) return { events: [], cursor, found: false };
    const { events, found } = await db.getScanEventsSince(scanId, cursor);
    const next = events.length ? events[events.length - 1].seq : cursor;
    return { events: events as LiveEvent[], cursor: next, found };
  }
  const events = s.events.filter((e) => e.seq > cursor);
  const nextCursor = events.length ? events[events.length - 1].seq : cursor;
  return { events, cursor: nextCursor, found: true };
}
