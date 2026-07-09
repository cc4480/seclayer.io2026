import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeNextRun, describeSchedule } from './schedule.js';

test('daily: fires today at HH:MM when still ahead, else tomorrow', () => {
  const before = computeNextRun(new Date('2026-07-09T08:00:00Z'), { frequencyDays: 1, hour: 9, minute: 0 });
  assert.equal(before.toISOString(), '2026-07-09T09:00:00.000Z');

  const after = computeNextRun(new Date('2026-07-09T10:00:00Z'), { frequencyDays: 1, hour: 9, minute: 0 });
  assert.equal(after.toISOString(), '2026-07-10T09:00:00.000Z');
});

test('weekly: lands on the chosen weekday at HH:MM, strictly in the future', () => {
  const from = new Date('2026-07-09T08:00:00Z'); // a Thursday (getUTCDay() === 4)
  const today = from.getUTCDay();

  // Same weekday, time still ahead today → today at that time.
  const sameDayAhead = computeNextRun(from, { frequencyDays: 7, hour: 9, minute: 30, weekday: today });
  assert.equal(sameDayAhead.getUTCDay(), today);
  assert.equal(sameDayAhead.toISOString(), '2026-07-09T09:30:00.000Z');

  // Same weekday, time already passed → a week later.
  const sameDayPassed = computeNextRun(from, { frequencyDays: 7, hour: 7, minute: 0, weekday: today });
  assert.equal(sameDayPassed.getUTCDay(), today);
  assert.equal(sameDayPassed.toISOString(), '2026-07-16T07:00:00.000Z');

  // A different weekday → the next occurrence of it.
  const tomorrow = (today + 1) % 7;
  const nextDay = computeNextRun(from, { frequencyDays: 7, hour: 9, minute: 0, weekday: tomorrow });
  assert.equal(nextDay.getUTCDay(), tomorrow);
  assert.ok(nextDay.getTime() > from.getTime());
});

test('monthly: fires on the 1st at HH:MM, this month or next', () => {
  const midMonth = computeNextRun(new Date('2026-07-09T08:00:00Z'), { frequencyDays: 30, hour: 6, minute: 0 });
  assert.equal(midMonth.toISOString(), '2026-08-01T06:00:00.000Z');

  const beforeFirst = computeNextRun(new Date('2026-07-01T05:00:00Z'), { frequencyDays: 30, hour: 6, minute: 0 });
  assert.equal(beforeFirst.toISOString(), '2026-07-01T06:00:00.000Z');
});

test('monthly rolls over December → January of the next year', () => {
  const dec = computeNextRun(new Date('2026-12-15T00:00:00Z'), { frequencyDays: 30, hour: 6, minute: 0 });
  assert.equal(dec.toISOString(), '2027-01-01T06:00:00.000Z');
});

test('no time-of-day falls back to a fixed now+frequency interval', () => {
  const from = new Date('2026-07-09T08:00:00Z');
  const next = computeNextRun(from, { frequencyDays: 7 });
  assert.equal(next.getTime(), from.getTime() + 7 * 24 * 60 * 60 * 1000);
});

test('describeSchedule renders a stable, UTC-labelled human string', () => {
  assert.equal(describeSchedule({ frequencyDays: 1, hour: 9, minute: 0 }), 'Every day at 09:00 UTC');
  assert.equal(describeSchedule({ frequencyDays: 7, hour: 9, minute: 5, weekday: 1 }), 'Every Monday at 09:05 UTC');
  assert.equal(describeSchedule({ frequencyDays: 30, hour: 14, minute: 0 }), 'Monthly on the 1st at 14:00 UTC');
  assert.equal(describeSchedule({ frequencyDays: 7 }), 'Every week');
});
