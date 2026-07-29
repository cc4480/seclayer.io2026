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
      state.events.push({ seq: state.seq, ts: Date.now(), channel, text: t });
      if (state.events.length > MAX_EVENTS) state.events.splice(0, state.events.length - MAX_EVENTS);
    },
    close: () => {
      const s = streams.get(scanId);
      if (s) s.closedAt = Date.now();
    },
  };
}

// Read events newer than `cursor` (a seq). `found` distinguishes "stream exists
// but nothing new" from "no stream for this scan" (e.g. a finished scan whose
// feed has been evicted — the client then falls back to narrationLog).
export function getSince(
  scanId: string,
  cursor: number,
): { events: LiveEvent[]; cursor: number; found: boolean } {
  const s = streams.get(scanId);
  if (!s) return { events: [], cursor, found: false };
  const events = s.events.filter((e) => e.seq > cursor);
  const nextCursor = events.length ? events[events.length - 1].seq : cursor;
  return { events, cursor: nextCursor, found: true };
}
