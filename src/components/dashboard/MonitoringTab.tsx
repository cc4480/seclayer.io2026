import { Clock, Globe, Plus, RefreshCw, AlertTriangle, Play, Pause, Zap } from 'lucide-react';
import { useMonitoring } from '../../hooks/useMonitoring.js';

// Human-readable last-scan result for a monitor row, linking completed scans to
// their report. In-flight/failed/never-run states are shown as plain text.
function LastScanResult({ lastScan, onViewReport }: { lastScan: any; onViewReport: (scanId: string) => void }) {
  if (!lastScan) return <span className="text-[#52525b]">No scans run yet</span>;

  if (lastScan.status === 'complete') {
    const sev = String(lastScan.severity || '').toLowerCase();
    const sevColor =
      sev === 'critical' || sev === 'high' ? 'text-[#f87171]'
        : sev === 'medium' ? 'text-amber-400'
        : 'text-[#22c55e]';
    return (
      <button
        onClick={() => onViewReport(lastScan.id)}
        className="text-[#a1a1aa] hover:text-white transition-colors cursor-pointer underline decoration-dotted underline-offset-2"
      >
        Last scan: score <span className={`font-bold ${sevColor}`}>{lastScan.score ?? 'N/A'}/100</span>
        {sev ? <span className={`uppercase ${sevColor}`}> · {sev}</span> : null} → View report
      </button>
    );
  }
  if (lastScan.status === 'failed') return <span className="text-[#f87171]">Last scan failed</span>;
  if (lastScan.status === 'canceled') return <span className="text-[#52525b]">Last scan canceled</span>;
  return <span className="text-purple-400">Scanning now…</span>;
}

// Continuous-monitoring tab: the Slack-compatible alert webhook, the add-target
// form (cadence + weekday + UTC time), and the list of active monitors.
export default function MonitoringTab({ m, onViewReport }: { m: ReturnType<typeof useMonitoring>; onViewReport: (scanId: string) => void }) {
  return (
    <div className="space-y-6 animate-fade-in text-xs font-mono">
      <div className="bg-[#18181b]/35 border border-[#27272a] rounded p-4 flex items-start space-x-3.5">
        <Clock className="w-5 h-5 text-[#22c55e] shrink-0 mt-0.5" />
        <div className="space-y-1">
          <h4 className="text-white text-xs uppercase font-bold">Continuous Security Monitoring</h4>
          <p className="text-[11px] text-[#a1a1aa] leading-relaxed">
            Set up automated, recurring scans for your critical infrastructure. Monitoring tasks will automatically deduct credits from your balance per execution.
          </p>
        </div>
      </div>

      <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-5">
        <h3 className="text-sm font-bold font-mono text-white mb-1.5">Alert Webhook <span className="text-[10px] text-[#52525b] font-normal">(Slack-compatible, optional)</span></h3>
        <p className="text-[10px] text-[#a1a1aa] mb-3">Get notified when any scan (manual or monitored) finds high/critical issues. Paste a Slack incoming webhook or any JSON endpoint.</p>
        <div className="flex flex-col sm:flex-row gap-2">
          <div className="flex-1 bg-black border border-[#27272a] rounded p-1.5 focus-within:border-[#22c55e] transition-colors flex items-center">
            <input
              type="text"
              className="bg-transparent text-white text-xs font-mono w-full focus:outline-none p-1 placeholder-[#52525b]"
              placeholder="https://hooks.slack.com/services/…"
              value={m.webhookUrl}
              onChange={(e) => m.setWebhookUrl(e.target.value)}
              id="webhook-input"
            />
          </div>
          <button
            type="button"
            onClick={m.saveWebhook}
            disabled={m.webhookSaving}
            className="px-4 py-2 bg-[#18181b] hover:bg-[#27272a] text-white text-[11px] font-mono font-bold uppercase tracking-wider border border-[#27272a] rounded transition-all disabled:opacity-50 cursor-pointer whitespace-nowrap"
          >
            {m.webhookSaving ? 'Saving…' : m.webhookSaved ? 'Saved ✓' : m.webhookUrl.trim() ? 'Save Webhook' : 'Disable'}
          </button>
        </div>
      </div>

      <div className="bg-[#0c0c0e] border border-[#27272a] rounded p-5">
        <h3 className="text-sm font-bold font-mono text-white mb-4">Add Monitor Target</h3>
        <form onSubmit={m.handleAddMonitor} className="flex flex-col gap-3">
          <div className="flex-1 bg-black border border-[#27272a] rounded p-1.5 focus-within:border-[#22c55e] transition-colors flex items-center">
            <Globe className="w-4 h-4 text-[#52525b] mx-2" />
            <input
              type="text"
              className="bg-transparent text-white text-xs font-mono w-full focus:outline-none p-1"
              placeholder="https://production.api.yoursite.com"
              value={m.monitorUrl}
              onChange={(e) => m.setMonitorUrl(e.target.value)}
              disabled={m.isAddingMonitor}
            />
          </div>
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="w-full sm:w-auto bg-black border border-[#27272a] rounded p-1.5 flex items-center">
              <select
                value={m.monitorFreq}
                onChange={(e) => m.setMonitorFreq(Number(e.target.value))}
                className="bg-transparent text-white text-xs font-mono w-full focus:outline-none p-1 cursor-pointer"
                disabled={m.isAddingMonitor}
              >
                <option value={1} className="bg-black">Daily</option>
                <option value={7} className="bg-black">Weekly</option>
                <option value={30} className="bg-black">Monthly</option>
              </select>
            </div>

            {m.monitorFreq === 7 && (
              <div className="w-full sm:w-auto bg-black border border-[#27272a] rounded p-1.5 flex items-center">
                <select
                  value={m.monitorDay}
                  onChange={(e) => m.setMonitorDay(e.target.value)}
                  className="bg-transparent text-white text-xs font-mono w-full focus:outline-none p-1 cursor-pointer"
                  disabled={m.isAddingMonitor}
                >
                  <option value="Monday" className="bg-black">Monday</option>
                  <option value="Tuesday" className="bg-black">Tuesday</option>
                  <option value="Wednesday" className="bg-black">Wednesday</option>
                  <option value="Thursday" className="bg-black">Thursday</option>
                  <option value="Friday" className="bg-black">Friday</option>
                  <option value="Saturday" className="bg-black">Saturday</option>
                  <option value="Sunday" className="bg-black">Sunday</option>
                </select>
              </div>
            )}

            <div className="w-full sm:w-auto bg-black border border-[#27272a] rounded p-1.5 flex items-center gap-1.5">
              <input
                type="time"
                value={m.monitorTime}
                onChange={(e) => m.setMonitorTime(e.target.value)}
                className="bg-transparent text-white text-xs font-mono w-full focus:outline-none p-1 cursor-pointer [color-scheme:dark]"
                disabled={m.isAddingMonitor}
              />
              <span className="text-[9px] text-[#52525b] font-mono pr-1 shrink-0">UTC</span>
            </div>

            <button
              type="submit"
              disabled={m.isAddingMonitor || !m.monitorUrl.trim()}
              className="px-5 py-2.5 bg-[#22c55e] hover:bg-[#4ade80] text-black text-xs font-bold uppercase tracking-wider rounded disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center justify-center space-x-2 shrink-0 cursor-pointer w-full sm:w-auto ml-auto"
            >
              {m.isAddingMonitor ? <RefreshCw className="w-4 h-4 animate-spin text-black" /> : <Plus className="w-4 h-4 text-black" />}
              <span>Add Monitor</span>
            </button>
          </div>
          {m.monitorError && (
            <div className="text-[#f87171] text-[10px] font-mono">{m.monitorError}</div>
          )}
        </form>
      </div>

      <div className="space-y-3">
        {m.monitoredTargets.length === 0 ? (
          <div className="text-center py-8 bg-black rounded border border-[#27272a]">
            <span className="text-xs text-[#52525b] font-mono">No active monitoring targets configured</span>
          </div>
        ) : (
          m.monitoredTargets.map((target) => {
            const busy = m.busyTargetId === target.id;
            const notice = m.rowNotice && m.rowNotice.id === target.id ? m.rowNotice : null;
            return (
            <div key={target.id} className="p-4 bg-black border border-[#27272a] rounded flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="space-y-1.5">
                <div className="flex items-center space-x-2">
                  <Globe className="w-4 h-4 text-[#52525b]" />
                  <span className="text-white font-bold uppercase text-xs">{target.url}</span>
                  {target.paused ? (
                    <span className="bg-[#52525b]/15 text-[#a1a1aa] text-[9px] px-2 py-0.5 rounded border border-[#52525b]/40 flex items-center gap-1">
                      <Pause className="w-2.5 h-2.5" />
                      PAUSED
                    </span>
                  ) : target.lastError ? (
                    <span className="bg-amber-500/10 text-amber-400 text-[9px] px-2 py-0.5 rounded border border-amber-500/30 flex items-center gap-1">
                      <AlertTriangle className="w-2.5 h-2.5" />
                      NEEDS ATTENTION
                    </span>
                  ) : (
                    <span className="bg-[#22c55e]/10 text-[#22c55e] text-[9px] px-2 py-0.5 rounded border border-[#22c55e]/30">ACTIVE</span>
                  )}
                </div>
                <div className="text-[#a1a1aa] text-[10px] flex flex-wrap items-center gap-x-3 gap-y-1">
                  <span>Schedule: {target.scheduleString || `Every ${target.frequencyDays} ${target.frequencyDays === 1 ? 'day' : 'days'}`}</span>
                  <span>&bull;</span>
                  <span>{target.paused ? 'Paused — next scan on resume' : `Next scan: ${new Date(target.nextScanAt).toLocaleString()}`}</span>
                  {target.lastScannedAt && (
                    <>
                      <span>&bull;</span>
                      <span>Last run: {new Date(target.lastScannedAt).toLocaleString()}</span>
                    </>
                  )}
                </div>
                <div className="text-[10px]">
                  <LastScanResult lastScan={(target as any).lastScan} onViewReport={onViewReport} />
                </div>
                {target.lastError && (
                  <div className="text-amber-400/90 text-[10px]">{target.lastError}</div>
                )}
                {notice && (
                  <div className={`text-[10px] ${notice.tone === 'error' ? 'text-[#f87171]' : 'text-[#22c55e]'}`}>{notice.message}</div>
                )}
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  onClick={() => m.scanNow(target.id)}
                  disabled={busy}
                  className="px-3 py-1.5 bg-[#18181b] border border-[#27272a] hover:border-[#22c55e]/40 hover:text-[#22c55e] text-[#a1a1aa] rounded text-[10px] uppercase font-bold tracking-wider transition-all cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-1.5"
                  id={`scan-now-${target.id}`}
                >
                  {busy ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Zap className="w-3 h-3" />}
                  Scan now
                </button>
                <button
                  onClick={() => m.togglePause(target.id, !target.paused)}
                  disabled={busy}
                  className="px-3 py-1.5 bg-[#18181b] border border-[#27272a] hover:border-[#3f3f46] hover:text-white text-[#a1a1aa] rounded text-[10px] uppercase font-bold tracking-wider transition-all cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-1.5"
                >
                  {target.paused ? <><Play className="w-3 h-3" />Resume</> : <><Pause className="w-3 h-3" />Pause</>}
                </button>
                <button
                  onClick={() => m.handleDeleteMonitor(target.id)}
                  className="px-3 py-1.5 bg-[#18181b] border border-[#27272a] hover:bg-[#f87171] hover:text-white text-[#f87171] rounded text-[10px] uppercase font-bold tracking-wider transition-all cursor-pointer"
                >
                  Remove
                </button>
              </div>
            </div>
            );
          })
        )}
      </div>
    </div>
  );
}
