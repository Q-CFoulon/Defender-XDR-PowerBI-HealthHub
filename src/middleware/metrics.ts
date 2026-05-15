import { logger } from "../config/logger";

interface MetricSample {
  value: number;
  timestamp: number;
}

class Counter {
  private count = 0;

  public increment(amount = 1): void {
    this.count += amount;
  }

  public get(): number {
    return this.count;
  }
}

class Histogram {
  private readonly samples: MetricSample[] = [];
  private readonly maxSamples: number;

  public constructor(maxSamples = 100) {
    this.maxSamples = maxSamples;
  }

  public observe(value: number): void {
    this.samples.push({ value, timestamp: Date.now() });
    if (this.samples.length > this.maxSamples) {
      this.samples.shift();
    }
  }

  public summary(): { count: number; avg: number; p50: number; p95: number; last: number } {
    if (this.samples.length === 0) {
      return { count: 0, avg: 0, p50: 0, p95: 0, last: 0 };
    }
    const sorted = [...this.samples].map((s) => s.value).sort((a, b) => a - b);
    const count = sorted.length;
    const avg = sorted.reduce((sum, v) => sum + v, 0) / count;
    const p50 = sorted[Math.floor(count * 0.5)];
    const p95 = sorted[Math.floor(count * 0.95)];
    const last = sorted[sorted.length - 1];
    return { count, avg: Math.round(avg), p50, p95, last };
  }
}

class AppMetrics {
  public readonly httpRequests = new Counter();
  public readonly httpErrors = new Counter();
  public readonly refreshCount = new Counter();
  public readonly refreshFailures = new Counter();
  public readonly refreshDuration = new Histogram();
  public readonly defenderApiErrors = new Counter();
  public readonly graphApiErrors = new Counter();
  private readonly startTime = Date.now();

  public snapshot(): Record<string, unknown> {
    return {
      uptimeSeconds: Math.round((Date.now() - this.startTime) / 1000),
      http: {
        totalRequests: this.httpRequests.get(),
        totalErrors: this.httpErrors.get()
      },
      refresh: {
        totalRefreshes: this.refreshCount.get(),
        totalFailures: this.refreshFailures.get(),
        durationMs: this.refreshDuration.summary()
      },
      apiErrors: {
        defender: this.defenderApiErrors.get(),
        graph: this.graphApiErrors.get()
      }
    };
  }
}

export const metrics = new AppMetrics();

export const startTimer = (): (() => number) => {
  const start = Date.now();
  return () => Date.now() - start;
};
