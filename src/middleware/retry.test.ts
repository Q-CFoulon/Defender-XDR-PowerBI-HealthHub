import { describe, it, expect, vi } from "vitest";
import { withRetry } from "./retry";
import axios, { AxiosError, AxiosHeaders } from "axios";

function makeAxiosError(status: number, message = "error"): AxiosError {
  const headers = new AxiosHeaders();
  return new AxiosError(message, "ERR_BAD_RESPONSE", undefined, undefined, {
    status,
    statusText: message,
    headers: {},
    config: { headers },
    data: null
  });
}

describe("withRetry", () => {
  it("returns result on first success", async () => {
    const result = await withRetry(() => Promise.resolve(42), "test-success");
    expect(result).toBe(42);
  });

  it("retries on 5xx then succeeds", async () => {
    let attempt = 0;
    const result = await withRetry(
      () => {
        attempt++;
        if (attempt < 3) {
          throw makeAxiosError(500);
        }
        return Promise.resolve("ok");
      },
      "test-retry",
      { maxRetries: 3, baseDelayMs: 10, maxDelayMs: 50 }
    );
    expect(result).toBe("ok");
    expect(attempt).toBe(3);
  });

  it("throws immediately on non-retryable 4xx error", async () => {
    await expect(
      withRetry(
        () => { throw makeAxiosError(400, "bad request"); },
        "test-no-retry",
        { maxRetries: 3, baseDelayMs: 10, maxDelayMs: 50 }
      )
    ).rejects.toThrow("bad request");
  });

  it("throws after max retries exhausted", async () => {
    await expect(
      withRetry(
        () => { throw makeAxiosError(503, "server down"); },
        "test-exhaust",
        { maxRetries: 2, baseDelayMs: 10, maxDelayMs: 50 }
      )
    ).rejects.toThrow("server down");
  });
});
