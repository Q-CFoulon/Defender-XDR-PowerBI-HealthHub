import { describe, it, expect } from "vitest";
import { metrics } from "./metrics";

describe("AppMetrics", () => {
  it("snapshot returns structured metrics data", () => {
    // The singleton metrics object should return a snapshot
    const snap = metrics.snapshot();
    expect(snap).toHaveProperty("uptimeSeconds");
    expect(snap).toHaveProperty("http");
    expect(snap).toHaveProperty("refresh");
    expect(snap).toHaveProperty("apiErrors");
  });

  it("counters track increments via snapshot", () => {
    const before = metrics.snapshot() as any;
    const prevRequests = before.http.totalRequests;
    metrics.httpRequests.increment();
    const after = metrics.snapshot() as any;
    expect(after.http.totalRequests).toBe(prevRequests + 1);
  });

  it("histogram computes summary", () => {
    metrics.refreshDuration.observe(100);
    metrics.refreshDuration.observe(200);
    const snap = metrics.snapshot() as any;
    expect(snap.refresh.durationMs.count).toBeGreaterThanOrEqual(2);
    expect(snap.refresh.durationMs.avg).toBeGreaterThan(0);
  });
});
