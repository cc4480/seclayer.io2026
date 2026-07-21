import { useState, useEffect, type FormEvent } from 'react';
import { User, Scan } from '../types.js';

// Account-tab data: continuous-monitoring targets (+ the add form), the
// Slack-compatible alert webhook, and the false-positive suppression rules.
// Refetched when the user or their scan list changes.
export function useMonitoring(user: User, scans: Scan[]) {
  const [suppressRules, setSuppressRules] = useState<any[]>([]);
  const [monitoredTargets, setMonitoredTargets] = useState<any[]>([]);
  const [monitorUrl, setMonitorUrl] = useState('');
  const [monitorFreq, setMonitorFreq] = useState(7);
  const [monitorDay, setMonitorDay] = useState('Monday');
  const [monitorTime, setMonitorTime] = useState('09:00');
  const [isAddingMonitor, setIsAddingMonitor] = useState(false);

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
      if (res.ok) {
        setMonitorUrl('');
        fetchMonitoredTargets();
      }
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

  return {
    suppressRules, fetchSuppressRules,
    monitoredTargets, monitorUrl, setMonitorUrl, monitorFreq, setMonitorFreq,
    monitorDay, setMonitorDay, monitorTime, setMonitorTime, isAddingMonitor,
    handleAddMonitor, handleDeleteMonitor,
    webhookUrl, setWebhookUrl, webhookSaving, webhookSaved, saveWebhook,
  };
}
