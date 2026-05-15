import { describe, it, expect } from "vitest";
import { CircuitBreaker } from "./circuitBreaker";

describe("CircuitBreaker", () => {
  it("allows calls in closed state", async () => {
    const cb = new CircuitBreaker("test", { failureThreshold: 3, resetTimeoutMs: 100 });
    const result = await cb.execute(() => Promise.resolve("ok"));
    expect(result).toBe("ok");
    expect(cb.isOpen()).toBe(false);
  });

  it("opens after reaching failure threshold", async () => {
    const cb = new CircuitBreaker("test", { failureThreshold: 2, resetTimeoutMs: 100 });

    for (let i = 0; i < 2; i++) {
      await expect(cb.execute(() => Promise.reject(new Error("fail")))).rejects.toThrow("fail");
    }

    expect(cb.isOpen()).toBe(true);
    await expect(cb.execute(() => Promise.resolve("ok"))).rejects.toThrow("Circuit breaker");
  });

  it("transitions to half-open after reset timeout", async () => {
    const cb = new CircuitBreaker("test", { failureThreshold: 1, resetTimeoutMs: 50 });

    await expect(cb.execute(() => Promise.reject(new Error("fail")))).rejects.toThrow("fail");
    expect(cb.isOpen()).toBe(true);

    // Wait for reset timeout
    await new Promise((resolve) => setTimeout(resolve, 60));

    const result = await cb.execute(() => Promise.resolve("recovered"));
    expect(result).toBe("recovered");
    expect(cb.isOpen()).toBe(false);
  });
});
