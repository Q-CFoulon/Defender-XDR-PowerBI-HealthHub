import axios from "axios";
import { logger } from "../config/logger";

interface RetryOptions {
  maxRetries: number;
  baseDelayMs: number;
  maxDelayMs: number;
}

const DEFAULT_OPTIONS: RetryOptions = {
  maxRetries: 3,
  baseDelayMs: 500,
  maxDelayMs: 8_000
};

const isRetryable = (error: unknown): boolean => {
  if (!axios.isAxiosError(error)) {
    return false;
  }
  const status = error.response?.status;
  if (!status) {
    return true; // network error / timeout
  }
  return status === 429 || status >= 500;
};

const delay = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

export const withRetry = async <T>(
  operation: () => Promise<T>,
  label: string,
  options: Partial<RetryOptions> = {}
): Promise<T> => {
  const opts = { ...DEFAULT_OPTIONS, ...options };

  for (let attempt = 0; attempt <= opts.maxRetries; attempt++) {
    try {
      return await operation();
    } catch (error) {
      const isLast = attempt === opts.maxRetries;

      if (isLast || !isRetryable(error)) {
        throw error;
      }

      const jitter = Math.random() * 200;
      const backoff = Math.min(
        opts.baseDelayMs * Math.pow(2, attempt) + jitter,
        opts.maxDelayMs
      );

      logger.debug(
        { label, attempt: attempt + 1, maxRetries: opts.maxRetries, backoffMs: Math.round(backoff) },
        "Retrying after transient failure"
      );

      await delay(backoff);
    }
  }

  throw new Error(`withRetry: unreachable for ${label}`);
};
