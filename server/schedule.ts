// Pure scheduling for continuous-monitoring targets. Turns a target's chosen
// cadence (daily / weekly / monthly) plus a time-of-day and, for weekly, a
// weekday into the exact next run instant — so the schedule the user picks is
// the schedule that actually runs, instead of a fixed "now + N days" drift that
// ignored the time and day entirely.
//
// All times are computed in UTC. The dashboard labels the chosen time as UTC so
// what the user sees and what the worker does can never disagree.

export interface MonitorSchedule {
  frequencyDays: number;        // 1 = daily, 7 = weekly, 30 = monthly (calendar 1st)
  hour?: number | null;         // 0–23 UTC; when null, falls back to a fixed interval
  minute?: number | null;       // 0–59 UTC
  weekday?: number | null;      // 0 = Sunday … 6 = Saturday (weekly only)
}

export const WEEKDAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
const DAY_MS = 24 * 60 * 60 * 1000;

function clamp(n: number, lo: number, hi: number): number {
  if (!Number.isFinite(n)) return lo;
  return Math.min(hi, Math.max(lo, Math.trunc(n)));
}

function hasTimeOfDay(s: MonitorSchedule): boolean {
  return s.hour != null && s.minute != null;
}

// Normalizes a legacy bare frequency (a number) or a partial schedule object
// into a well-formed MonitorSchedule.
export function toSchedule(input: number | MonitorSchedule): MonitorSchedule {
  if (typeof input === 'number') return { frequencyDays: input || 7 };
  return {
    frequencyDays: input.frequencyDays && input.frequencyDays > 0 ? Math.trunc(input.frequencyDays) : 7,
    hour: input.hour == null ? null : clamp(Number(input.hour), 0, 23),
    minute: input.minute == null ? null : clamp(Number(input.minute), 0, 59),
    weekday: input.weekday == null ? null : clamp(Number(input.weekday), 0, 6),
  };
}

// The next instant strictly after `from` that matches the schedule.
export function computeNextRun(from: Date, input: number | MonitorSchedule): Date {
  const s = toSchedule(input);
  const freq = s.frequencyDays;

  // No pinned time-of-day → legacy fixed interval from the reference instant.
  if (!hasTimeOfDay(s)) {
    return new Date(from.getTime() + freq * DAY_MS);
  }

  const hour = s.hour as number;
  const minute = s.minute as number;
  const atTimeOn = (y: number, m: number, d: number) =>
    new Date(Date.UTC(y, m, d, hour, minute, 0, 0));

  // Daily: today at HH:MM, or tomorrow if that already passed.
  if (freq === 1) {
    let c = atTimeOn(from.getUTCFullYear(), from.getUTCMonth(), from.getUTCDate());
    while (c.getTime() <= from.getTime()) c = new Date(c.getTime() + DAY_MS);
    return c;
  }

  // Weekly: the next matching weekday at HH:MM, strictly in the future.
  if (freq === 7) {
    const target = s.weekday != null ? s.weekday : from.getUTCDay();
    let c = atTimeOn(from.getUTCFullYear(), from.getUTCMonth(), from.getUTCDate());
    for (let i = 0; i < 8; i++) {
      if (c.getUTCDay() === target && c.getTime() > from.getTime()) return c;
      c = new Date(c.getTime() + DAY_MS);
    }
    return c; // not reached: a matching weekday always falls within 8 days
  }

  // Monthly: the 1st of the month at HH:MM, this month or the next.
  if (freq === 30) {
    let c = atTimeOn(from.getUTCFullYear(), from.getUTCMonth(), 1);
    if (c.getTime() <= from.getTime()) {
      c = atTimeOn(from.getUTCFullYear(), from.getUTCMonth() + 1, 1);
    }
    return c;
  }

  // Arbitrary cadence: advance by the interval but land on HH:MM.
  let c = new Date(from.getTime() + freq * DAY_MS);
  c = atTimeOn(c.getUTCFullYear(), c.getUTCMonth(), c.getUTCDate());
  while (c.getTime() <= from.getTime()) c = new Date(c.getTime() + freq * DAY_MS);
  return c;
}

// Human-readable description of a schedule — the single source of truth for the
// `scheduleString` shown in the dashboard, derived server-side so the label and
// the worker's actual timing can never drift apart.
export function describeSchedule(input: number | MonitorSchedule): string {
  const s = toSchedule(input);
  const freq = s.frequencyDays;
  if (!hasTimeOfDay(s)) {
    if (freq === 1) return 'Every day';
    if (freq === 7) return 'Every week';
    if (freq === 30) return 'Monthly on the 1st';
    return `Every ${freq} days`;
  }
  const hh = String(s.hour).padStart(2, '0');
  const mm = String(s.minute).padStart(2, '0');
  const t = `${hh}:${mm} UTC`;
  if (freq === 1) return `Every day at ${t}`;
  if (freq === 7) {
    return s.weekday != null ? `Every ${WEEKDAYS[s.weekday]} at ${t}` : `Every week at ${t}`;
  }
  if (freq === 30) return `Monthly on the 1st at ${t}`;
  return `Every ${freq} days at ${t}`;
}
