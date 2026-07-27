import { useEffect, useState } from 'react';
import { AlertTriangle, Loader2 } from 'lucide-react';
import { Scan } from '../types.js';
import ReportViewer from './ReportViewer.js';

// Standalone, no-account view of a scan shared via /r/<token>. Fetches the
// sanitized public report and renders the normal ReportViewer in read-only mode
// (no dashboard chrome, no owner controls). A revoked/unknown token shows a
// friendly "not available" state rather than an error.
export default function PublicReport({ token }: { token: string }) {
  const [state, setState] = useState<'loading' | 'ok' | 'notfound' | 'error'>('loading');
  const [scan, setScan] = useState<Scan | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch(`/api/public/report/${encodeURIComponent(token)}`);
        if (cancelled) return;
        if (res.status === 404) { setState('notfound'); return; }
        if (!res.ok) { setState('error'); return; }
        const data = await res.json();
        setScan(data.report as Scan);
        setState('ok');
      } catch {
        if (!cancelled) setState('error');
      }
    })();
    return () => { cancelled = true; };
  }, [token]);

  if (state === 'loading') {
    return (
      <div className="min-h-screen bg-[#09090b] text-[#a1a1aa] flex items-center justify-center font-mono text-xs">
        <span className="flex items-center gap-2"><Loader2 className="w-4 h-4 animate-spin text-[#22c55e]" /> Loading shared report…</span>
      </div>
    );
  }

  if (state === 'ok' && scan) {
    // In public mode ReportViewer hides all owner-only controls; "back" simply
    // sends a visitor to the Seclayer landing page to run their own scan.
    return <ReportViewer scan={scan} isPublic onBack={() => { window.location.href = '/'; }} />;
  }

  return (
    <div className="min-h-screen bg-[#09090b] text-[#a1a1aa] flex items-center justify-center px-6 font-mono">
      <div className="max-w-md w-full bg-[#0c0c0e] border border-[#27272a] rounded p-8 text-center space-y-4">
        <AlertTriangle className="w-8 h-8 text-[#f87171] mx-auto" />
        <h1 className="text-white text-sm font-bold uppercase tracking-wider">
          {state === 'notfound' ? 'Report Not Available' : 'Something Went Wrong'}
        </h1>
        <p className="text-xs text-[#a1a1aa] leading-relaxed">
          {state === 'notfound'
            ? 'This shared report link is no longer active — it may have been revoked by its owner.'
            : 'We could not load this report right now. Please try again in a moment.'}
        </p>
        <a
          href="/"
          className="inline-block px-4 py-2 bg-[#22c55e] hover:bg-[#4ade80] text-black text-[11px] font-bold uppercase tracking-wider rounded transition-all cursor-pointer"
        >
          Scan your own site with Seclayer
        </a>
      </div>
    </div>
  );
}
