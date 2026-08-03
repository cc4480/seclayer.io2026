import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseNmapProgress } from './nmapProgress.js';
import { LiveEvent } from '../types.js';

function evt(channel: LiveEvent['channel'], text: string, seq: number): LiveEvent {
  return { seq, ts: Date.now(), channel, text };
}

test('parseNmapProgress returns null with no recon events yet', () => {
  assert.equal(parseNmapProgress([]), null);
  assert.equal(parseNmapProgress([evt('system', 'Resolving example.com…', 1)]), null);
});

test('parseNmapProgress extracts phase + percent + ETA from a Timing: line', () => {
  const progress = parseNmapProgress([
    evt('recon', 'Stats: 0:00:10 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan', 1),
    evt('recon', 'SYN Stealth Scan Timing: About 35.71% done; ETC: 12:34 (0:10:52 remaining)', 2),
  ]);
  assert.ok(progress);
  assert.equal(progress!.phase, 'SYN Stealth Scan');
  assert.equal(progress!.percent, 35.71);
  assert.equal(progress!.eta, '12:34');
  assert.equal(progress!.remaining, '0:10:52');
});

test('parseNmapProgress handles a Timing: line with no ETC clause (e.g. NSE)', () => {
  const progress = parseNmapProgress([evt('recon', 'NSE Timing: About 96.71% done', 1)]);
  assert.ok(progress);
  assert.equal(progress!.phase, 'NSE');
  assert.equal(progress!.percent, 96.71);
  assert.equal(progress!.eta, undefined);
});

test('parseNmapProgress uses the latest event, tracking phase transitions', () => {
  const progress = parseNmapProgress([
    evt('recon', 'SYN Stealth Scan Timing: About 100.00% done; ETC: 12:30 (0:00:00 remaining)', 1),
    evt('recon', 'Stats: 0:02:00 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan', 2),
    evt('recon', 'Service scan Timing: About 10.00% done; ETC: 12:35 (0:04:30 remaining)', 3),
  ]);
  assert.equal(progress!.phase, 'Service scan');
  assert.equal(progress!.percent, 10);
});

test('parseNmapProgress does not reset a known percent back to null on the next bare Stats: line for the same phase', () => {
  const progress = parseNmapProgress([
    evt('recon', 'Service scan Timing: About 40.00% done; ETC: 12:35 (0:02:00 remaining)', 1),
    // 10s later: the next tick's Stats: line for the SAME phase, its own Timing: line hasn't arrived yet
    evt('recon', 'Stats: 0:02:10 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan', 2),
  ]);
  assert.equal(progress!.phase, 'Service scan');
  assert.equal(progress!.percent, 40, 'percent from the prior Timing: line is preserved, not cleared');
  assert.equal(progress!.elapsed, '0:02:10', 'elapsed still refreshes from the new Stats: line');
});

test('parseNmapProgress starts a fresh (percent-less) snapshot when the phase actually changes without a Timing: line yet', () => {
  const progress = parseNmapProgress([
    evt('recon', 'SYN Stealth Scan Timing: About 100.00% done; ETC: 12:30 (0:00:00 remaining)', 1),
    evt('recon', 'Stats: 0:02:00 elapsed; 0 hosts completed (1 up), 1 undergoing OS detection', 2),
  ]);
  assert.equal(progress!.phase, 'OS detection');
  assert.equal(progress!.percent, null);
});

test('parseNmapProgress ignores non-recon channels', () => {
  const progress = parseNmapProgress([
    evt('system', 'SYN Stealth Scan Timing: About 50.00% done', 1),
  ]);
  assert.equal(progress, null);
});
