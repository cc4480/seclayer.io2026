// Continuous-monitoring targets. The next-run instant and the human
// scheduleString are both derived from one schedule (see server/schedule.ts) so
// they can't drift.
import type Database from 'better-sqlite3';
import crypto from 'crypto';
import { MonitoredTarget } from '../../src/types.js';
import { MonitorSchedule, computeNextRun, describeSchedule } from '../schedule.js';

export function makeMonitoringRepo(db: Database.Database) {
  const listMonitoredTargets = (userId: string): MonitoredTarget[] =>
    db.prepare('SELECT * FROM monitored_targets WHERE userId = ?').all(userId) as MonitoredTarget[];

  // Accepts either a full schedule (daily/weekly/monthly + time-of-day) or a
  // bare frequency in days (legacy callers).
  const addMonitoredTarget = (userId: string, url: string, schedule: number | MonitorSchedule): MonitoredTarget => {
    const s: MonitorSchedule = typeof schedule === 'number' ? { frequencyDays: schedule } : schedule;
    const id = 'mon_' + crypto.randomBytes(8).toString('hex');
    const now = new Date().toISOString();
    const nextScanAt = computeNextRun(new Date(), s).toISOString();
    db.prepare('INSERT INTO monitored_targets (id, userId, url, frequencyDays, scheduleString, scanHour, scanMinute, scanWeekday, nextScanAt, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .run(id, userId, url, s.frequencyDays, describeSchedule(s), s.hour ?? null, s.minute ?? null, s.weekday ?? null, nextScanAt, now);
    return db.prepare('SELECT * FROM monitored_targets WHERE id = ?').get(id) as MonitoredTarget;
  };

  const removeMonitoredTarget = (userId: string, id: string): boolean =>
    db.prepare('DELETE FROM monitored_targets WHERE id = ? AND userId = ?').run(id, userId).changes > 0;

  // Targets whose next scheduled scan is due (used by the monitoring worker).
  const listDueMonitoredTargets = (nowIso: string): MonitoredTarget[] =>
    db.prepare('SELECT * FROM monitored_targets WHERE nextScanAt IS NOT NULL AND nextScanAt <= ?').all(nowIso) as MonitoredTarget[];

  const markMonitoredScanned = (id: string, lastScannedAt: string, nextScanAt: string): void => {
    db.prepare('UPDATE monitored_targets SET lastScannedAt = ?, nextScanAt = ? WHERE id = ?')
      .run(lastScannedAt, nextScanAt, id);
  };

  return { listMonitoredTargets, addMonitoredTarget, removeMonitoredTarget, listDueMonitoredTargets, markMonitoredScanned };
}
