// A tiny async concurrency limiter (counting semaphore) with FIFO fairness.
// Used to cap how many scans run concurrently in one process so a burst of
// requests can't spawn unbounded runDiagnostics work and exhaust the instance.
// In a horizontally-scaled deployment this is also the natural per-worker
// concurrency cap.
export class Semaphore {
  private active = 0;
  private readonly waiters: Array<() => void> = [];
  private readonly max: number;

  constructor(max: number) {
    this.max = Math.max(1, Math.floor(max) || 1);
  }

  /** Slots currently in use. */
  get activeCount(): number {
    return this.active;
  }

  /** Callers parked waiting for a slot. */
  get queuedCount(): number {
    return this.waiters.length;
  }

  private acquire(): Promise<void> {
    if (this.active < this.max) {
      this.active++;
      return Promise.resolve();
    }
    // At capacity — park until a slot is released.
    return new Promise<void>((resolve) => this.waiters.push(resolve));
  }

  private release(): void {
    const next = this.waiters.shift();
    if (next) {
      // Hand the just-freed slot straight to the next waiter — active stays put.
      next();
    } else {
      this.active--;
    }
  }

  /** Run fn once a slot is free; always releases the slot, even if fn throws. */
  async run<T>(fn: () => Promise<T>): Promise<T> {
    await this.acquire();
    try {
      return await fn();
    } finally {
      this.release();
    }
  }
}
