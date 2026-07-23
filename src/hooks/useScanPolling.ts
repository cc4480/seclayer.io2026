import { useEffect, useRef, useState } from 'react';
import { Scan } from '../types.js';

const MAX_CONSECUTIVE_POLL_ERRORS = 5;

export interface ScanPollingState {
  scan: Scan | null;
  progressPercent: number;
  // Set only when polling has permanently failed (server/network kept erroring).
  pollError: string | null;
}

// Polls GET /api/scans/:id every 3s and maps the scan's status to a progress
// percentage, driving the ScanProgress view. Fires onScanFinished once when the
// scan completes and onCancel if it was canceled elsewhere. After
// MAX_CONSECUTIVE_POLL_ERRORS consecutive failures it stops and surfaces
// pollError instead of spinning forever. Behavior is identical to when this
// lived inline in ScanProgress.
export function useScanPolling(
  scanId: string,
  onScanFinished: (scanId: string) => void,
  onCancel: () => void,
): ScanPollingState {
  const [scan, setScan] = useState<Scan | null>(null);
  const [progressPercent, setProgressPercent] = useState(10);
  const [pollError, setPollError] = useState<string | null>(null);
  const finishedRef = useRef(false);

  useEffect(() => {
    let active = true;
    let consecutiveErrors = 0;

    const fetchStatus = async () => {
      try {
        const res = await fetch(`/api/scans/${scanId}`);
        if (!active) return;

        if (!res.ok) {
          throw new Error(res.status === 404 ? 'This scan no longer exists.' : `Server returned ${res.status}.`);
        }
        const data = await res.json();
        if (!active) return;

        if (!data.scan) throw new Error('Scan status is unavailable.');

        consecutiveErrors = 0;
        setPollError(null);
        const currentScan = data.scan as Scan;
        setScan(currentScan);

        if (currentScan.status === 'complete') {
          setProgressPercent(100);
          clearInterval(pollTimer);
          if (!finishedRef.current) {
            finishedRef.current = true;
            setTimeout(() => {
              if (active) onScanFinished(scanId);
            }, 1000);
          }
          return;
        }

        if (currentScan.status === 'failed') {
          setProgressPercent(100);
          clearInterval(pollTimer);
          return;
        }

        if (currentScan.status === 'canceled') {
          // Covers cancellation from elsewhere (another tab/session) — the
          // same-tab "Cancel scan" button already unmounts this component
          // immediately, so this path only fires for that case.
          clearInterval(pollTimer);
          if (active) onCancel();
          return;
        }

        // Advance progression bar corresponding to state
        if (currentScan.status === 'queued') {
          setProgressPercent(20);
        } else if (currentScan.status === 'scanning') {
          setProgressPercent(50);
        } else if (currentScan.status === 'analyzing') {
          setProgressPercent(80);
        }
      } catch (err: any) {
        if (!active) return;
        console.error('Error polling scan status:', err);
        consecutiveErrors += 1;
        if (consecutiveErrors >= MAX_CONSECUTIVE_POLL_ERRORS) {
          clearInterval(pollTimer);
          setPollError(err?.message || 'Lost connection to the scan. Please return to the dashboard and try again.');
        }
      }
    };

    fetchStatus();
    const pollTimer = setInterval(fetchStatus, 3000);

    return () => {
      active = false;
      clearInterval(pollTimer);
    };
  }, [scanId]);

  return { scan, progressPercent, pollError };
}
