import { Clock, Globe, Plus, RefreshCw, AlertTriangle } from 'lucide-react';
import { useMonitoring } from '../../hooks/useMonitoring.js';

// Continuous-monitoring tab: the Slack-compatible alert webhook, the add-target
// form (cadence + weekday + UTC time), and the list of active monitors.
export default function MonitoringTab({ m }: { m: ReturnType<typeof useMonitoring> }) {
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
          m.monitoredTargets.map((target) => (
            <div key={target.id} className="p-4 bg-black border border-[#27272a] rounded flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="space-y-1.5">
                <div className="flex items-center space-x-2">
                  <Globe className="w-4 h-4 text-[#52525b]" />
                  <span className="text-white font-bold uppercase text-xs">{target.url}</span>
                  {target.lastError ? (
                    <span className="bg-amber-500/10 text-amber-400 text-[9px] px-2 py-0.5 rounded border border-amber-500/30 flex items-center gap-1">
                      <AlertTriangle className="w-2.5 h-2.5" />
                      NEEDS ATTENTION
                    </span>
                  ) : (
                    <span className="bg-[#22c55e]/10 text-[#22c55e] text-[9px] px-2 py-0.5 rounded border border-[#22c55e]/30">ACTIVE</span>
                  )}
                </div>
                <div className="text-[#a1a1aa] text-[10px] flex items-center space-x-3">
                  <span>Schedule: {target.scheduleString || `Every ${target.frequencyDays} ${target.frequencyDays === 1 ? 'day' : 'days'}`}</span>
                  <span>&bull;</span>
                  <span>Next scan: {new Date(target.nextScanAt).toLocaleString()}</span>
                </div>
                {target.lastError && (
                  <div className="text-amber-400/90 text-[10px]">{target.lastError}</div>
                )}
              </div>
              <button
                onClick={() => m.handleDeleteMonitor(target.id)}
                className="px-3 py-1.5 bg-[#18181b] border border-[#27272a] hover:bg-[#f87171] hover:text-white text-[#f87171] rounded text-[10px] uppercase font-bold tracking-wider transition-all cursor-pointer w-fit"
              >
                Remove
              </button>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
