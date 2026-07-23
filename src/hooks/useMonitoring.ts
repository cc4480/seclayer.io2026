import { useState, useEffect, type FormEvent } from 'react';
import { User, Scan } from '../types.js';

// Account-tab data: continuous-monitoring targets (+ the add form), the
// Slack-compatible alert webhook, and the false-positive suppression rules.
// Refetched when the user or their scan list changes. onDataChanged (when
// provided) refreshes the app's authoritative scan list — used after "scan now"
// so the launched scan appears in history and its report becomes viewable.
export function useMonitoring(user: User, scans: Scan[], onDataChanged?: () => void) {
  const [suppressRules, setSuppressRules] = useState<any[]>([]);
  const [monitoredTargets, setMonitoredTargets] = useState<any[]>([]);
  const [monitorUrl, setMonitorUrl] = useState('');
  const [monitorFreq, setMonitorFreq] = useState(7);
  const [monitorDay, setMonitorDay] = useState('Monday');
  const [monitorTime, setMonitorTime] = useState('09:00');
  const [isAddingMonitor, setIsAddingMonitor] = useState(false);
  const [monitorError, setMonitorError] = useState('');
  // The target currently being acted on (pause/resume/scan-now), so its row
  // buttons can show a busy state, plus a per-row notice for the outcome.
  const [busyTargetId, setBusyTargetId] = useState<string | null>(null);
  const [rowNotice, setRowNotice] = useState<{ id: string; message: string; tone: 'ok' | 'error' } | null>(null);

  const [webhookUrl, setWebhookUrl] = useState(user.notifyWebhook || '');
  const [webhookSaving, setWebhookSaving] = useState(false);
  const [webhookSaved, setWebhookSaved] = useState(false);

  const fetchSuppressRules = async () => {
    try {
      const res = await fetch(`/api/suppressions`);
      if (res.ok) {
        const data = await res.json();
        setSuppressRules(data.suppressions || []);
      }
    } catch (err) {
      console.error('Error loading exclusion rules:', err);
    }
  };

  const fetchMonitoredTargets = async () => {
    try {
      const res = await fetch(`/api/monitoring`);
      if (res.ok) {
        const data = await res.json();
        setMonitoredTargets(data.monitoredTargets || []);
      }
    } catch (err) {
      console.error('Error loading monitoring targets:', err);
    }
  };

  useEffect(() => {
    fetchSuppressRules();
    fetchMonitoredTargets();
  }, [user.id, scans]);

  const saveWebhook = async () => {
    setWebhookSaving(true);
    setWebhookSaved(false);
    try {
      const res = await fetch('/api/user/webhook', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: webhookUrl.trim() })
      });
      if (res.ok) {
        setWebhookSaved(true);
        setTimeout(() => setWebhookSaved(false), 2500);
      }
    } catch (err) {
      console.error('Error saving webhook:', err);
    } finally {
      setWebhookSaving(false);
    }
  };

  const handleAddMonitor = async (e: FormEvent) => {
    e.preventDefault();
    if (!monitorUrl.trim()) return;
    setIsAddingMonitor(true);
    setMonitorError('');

    // The time input is interpreted as UTC (see the label below). Send the
    // schedule as structured fields; the server derives the human label and the
    // exact next-run instant so display and timing can't drift apart.
    const WEEKDAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    const [hourStr, minuteStr] = (monitorTime || '09:00').split(':');
    const body: Record<string, unknown> = {
      url: monitorUrl,
      frequencyDays: monitorFreq,
      hour: Number(hourStr),
      minute: Number(minuteStr),
    };
    if (monitorFreq === 7) body.weekday = WEEKDAYS.indexOf(monitorDay);

    try {
      const res = await fetch('/api/monitoring', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        setMonitorUrl('');
        fetchMonitoredTargets();
      } else {
        // The route responds with { error: "..." } rather than { message: "..." }.
        setMonitorError(data.error || data.message || 'Could not add this monitor. Please check the URL and try again.');
      }
    } catch {
      setMonitorError('Could not add this monitor — check your connection and try again.');
    } finally {
      setIsAddingMonitor(false);
    }
  };

  const handleDeleteMonitor = async (id: string) => {
    try {
      const res = await fetch(`/api/monitoring/${id}`, { method: 'DELETE' });
      if (res.ok) fetchMonitoredTargets();
    } catch (err) {
      console.error(err);
    }
  };

  // Pause or resume a monitor (keeps its configuration; the worker skips paused
  // targets). `paused` is the desired new state.
  const togglePause = async (id: string, paused: boolean) => {
    setBusyTargetId(id);
    setRowNotice(null);
    try {
      const res = await fetch(`/api/monitoring/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ paused }),
      });
      if (res.ok) await fetchMonitoredTargets();
    } catch (err) {
      console.error('Error toggling monitor pause:', err);
    } finally {
      setBusyTargetId(null);
    }
  };

  // Run a monitor's scan immediately. The row's last-scan result then updates
  // as the scan progresses; a few delayed refetches catch its completion
  // without the user leaving the tab.
  const scanNow = async (id: string) => {
    setBusyTargetId(id);
    setRowNotice(null);
    try {
      const res = await fetch(`/api/monitoring/${id}/scan-now`, { method: 'POST' });
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        setRowNotice({ id, message: 'Scan started — the result will appear here shortly.', tone: 'ok' });
        // Refresh the monitor rows AND the app's scan list, so the new scan
        // shows up in history and its report is viewable once complete.
        const refresh = () => { fetchMonitoredTargets(); onDataChanged?.(); };
        refresh();
        [4000, 10000, 20000].forEach((ms) => setTimeout(refresh, ms));
      } else {
        setRowNotice({ id, message: data.error || 'Could not start the scan.', tone: 'error' });
      }
    } catch {
      setRowNotice({ id, message: 'Could not start the scan — check your connection and try again.', tone: 'error' });
    } finally {
      setBusyTargetId(null);
    }
  };

  return {
    suppressRules, fetchSuppressRules,
    monitoredTargets, monitorUrl, setMonitorUrl, monitorFreq, setMonitorFreq,
    monitorDay, setMonitorDay, monitorTime, setMonitorTime, isAddingMonitor, monitorError,
    handleAddMonitor, handleDeleteMonitor, togglePause, scanNow, busyTargetId, rowNotice,
    webhookUrl, setWebhookUrl, webhookSaving, webhookSaved, saveWebhook,
  };
}
