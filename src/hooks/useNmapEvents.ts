import { useEffect, useRef, useState } from 'react';
import { LiveEvent, NmapScanStatus } from '../types.js';

// Polls the live nmap event feed (GET /api/nmap/scans/:id/events?since=<cursor>)
// about once a second — mirrors useScanEvents.ts exactly, pointed at the
// independent nmap endpoint, so the same ScanConsole/liveEventsToLogs render
// path works unmodified for the Network Reconnaissance progress ticker.
//
// Unlike useScanEvents (only ever mounted once a real scanId is known, from
// ScanProgress), this hook's caller — NetworkReconCard — has no in-flight
// scan most of the time and still must call it unconditionally (rules of
// hooks), so scanId is often ''. Guard on that rather than polling a
// malformed URL every second forever.
export function useNmapEvents(scanId: string): LiveEvent[] {
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const cursorRef = useRef(0);

  useEffect(() => {
    setEvents([]);
    cursorRef.current = 0;
    if (!scanId) return;
    let alive = true;

    const tick = async () => {
      try {
        const res = await fetch(`/api/nmap/scans/${scanId}/events?since=${cursorRef.current}`);
        if (!alive || !res.ok) return;
        const data = await res.json();
        if (!alive) return;

        if (Array.isArray(data.events) && data.events.length > 0) {
          cursorRef.current = data.cursor;
          setEvents((prev) => [...prev, ...(data.events as LiveEvent[])]);
        }

        const terminal: NmapScanStatus[] = ['complete', 'failed', 'canceled'];
        if (terminal.includes(data.scanStatus) && (!data.events || data.events.length === 0)) {
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
