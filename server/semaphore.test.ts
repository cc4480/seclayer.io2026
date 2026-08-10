import { test } from "node:test";
import assert from "node:assert/strict";
import { Semaphore } from "./semaphore.js";

const tick = () => new Promise((r) => setImmediate(r));

test("never runs more than `max` tasks at once", async () => {
  const sem = new Semaphore(2);
  let active = 0;
  let peak = 0;
  let completed = 0;
  const release: Array<() => void> = []; // each running task's resolver
  const task = () =>
    sem.run(
      () =>
        new Promise<void>((resolve) => {
          active++;
          peak = Math.max(peak, active);
          release.push(() => { active--; completed++; resolve(); });
        }),
    );

  const all = [task(), task(), task(), task()];
  await tick();
  assert.equal(active, 2, "only 2 start immediately");
  assert.equal(sem.activeCount, 2);
  assert.equal(sem.queuedCount, 2, "the other 2 are parked");

  // Drain: finish whatever is running one at a time; each completion frees a
  // slot that a parked task then takes (on a microtask, hence the tick).
  while (completed < 4) {
    if (release.length) release.shift()!();
    await tick();
  }
  await Promise.all(all);
  assert.equal(peak, 2, "concurrency never exceeded max");
  assert.equal(sem.activeCount, 0);
  assert.equal(sem.queuedCount, 0);
});

test("preserves FIFO order among waiters", async () => {
  const sem = new Semaphore(1);
  const order: number[] = [];
  const gate: Array<() => void> = [];
  const task = (n: number) =>
    sem.run(
      () =>
        new Promise<void>((resolve) => {
          order.push(n);
          gate.push(resolve);
        }),
    );
  const all = [task(1), task(2), task(3)];
  await tick();
  assert.deepEqual(order, [1]);
  gate.shift()!(); await tick();
  gate.shift()!(); await tick();
  gate.shift()!(); await tick();
  await Promise.all(all);
  assert.deepEqual(order, [1, 2, 3], "waiters run in the order they arrived");
});

test("releases the slot even when the task throws (no deadlock)", async () => {
  const sem = new Semaphore(1);
  await assert.rejects(sem.run(async () => { throw new Error("boom"); }), /boom/);
  assert.equal(sem.activeCount, 0, "slot released after the task threw");

  // A leaked slot would make this hang forever — guard with a cleared timeout so
  // a regression FAILS fast instead of hanging the suite.
  let timer: ReturnType<typeof setTimeout> | undefined;
  const guard = new Promise<never>((_, rej) => { timer = setTimeout(() => rej(new Error("slot leaked — deadlock")), 1000); });
  try {
    const ran = await Promise.race([sem.run(async () => "ok"), guard]);
    assert.equal(ran, "ok");
  } finally {
    clearTimeout(timer);
  }
});

test("clamps a nonsensical max to at least 1", async () => {
  for (const bad of [0, -3, NaN]) {
    const sem = new Semaphore(bad as number);
    const ran = await sem.run(async () => 42);
    assert.equal(ran, 42, `max=${bad} still runs (clamped to >=1)`);
  }
});
