import { useEffect, useRef, useState } from 'react';
import { LiveEvent } from '../types.js';

// Polls the live scan event feed (GET /api/scans/:id/events?since=<cursor>) about
// once a second and accumulates the events, driving the real-time ticker on the
// ScanProgress page. Faster than useScanPolling (which is for the coarse status /
// progress bar) because this is the play-by-play. Starting at cursor 0 pulls any
// backlog already buffered server-side, so opening the page mid-scan still shows
// everything from the start. Stops once the scan is terminal and the tail has
// drained; unmounting also stops it.
export function useScanEvents(scanId: string): LiveEvent[] {
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const cursorRef = useRef(0);

  useEffect(() => {
    // Fresh accumulation whenever the watched scan changes.
    setEvents([]);
    cursorRef.current = 0;
    let alive = true;

    const tick = async () => {
      try {
        const res = await fetch(`/api/scans/${scanId}/events?since=${cursorRef.current}`);
        if (!alive || !res.ok) return;
        const data = await res.json();
        if (!alive) return;

        if (Array.isArray(data.events) && data.events.length > 0) {
          cursorRef.current = data.cursor;
          setEvents((prev) => [...prev, ...(data.events as LiveEvent[])]);
        }

        // Once the scan is terminal AND this tick drained nothing new, the feed
        // is complete — stop polling. (One post-terminal tick guarantees the
        // tail is fetched before we stop.)
        const terminal =
          data.scanStatus === 'complete' || data.scanStatus === 'failed' || data.scanStatus === 'canceled';
        if (terminal && (!data.events || data.events.length === 0)) {
          clearInterval(timer);
        }
      } catch {
        /* transient network/server blip — keep polling */
      }
    };

    void tick();
    const timer = setInterval(tick, 1000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [scanId]);

  return events;
}
