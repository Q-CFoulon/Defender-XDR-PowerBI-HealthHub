import { logger } from "../config/logger";

interface CircuitBreakerOptions {
  failureThreshold: number;
  resetTimeoutMs: number;
}

type CircuitState = "closed" | "open" | "half-open";

export class CircuitBreaker {
  private state: CircuitState = "closed";
  private failureCount = 0;
  private lastFailureTime = 0;

  public constructor(
    private readonly label: string,
    private readonly options: CircuitBreakerOptions = {
      failureThreshold: 3,
      resetTimeoutMs: 60_000
    }
  ) {}

  public async execute<T>(operation: () => Promise<T>): Promise<T> {
    if (this.state === "open") {
      if (Date.now() - this.lastFailureTime >= this.options.resetTimeoutMs) {
        this.state = "half-open";
        logger.info({ label: this.label }, "Circuit breaker entering half-open state");
      } else {
        throw new Error(`Circuit breaker [${this.label}] is open — skipping call`);
      }
    }

    try {
      const result = await operation();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  public isOpen(): boolean {
    return this.state === "open";
  }

  private onSuccess(): void {
    if (this.state === "half-open") {
      logger.info({ label: this.label }, "Circuit breaker closing after successful probe");
    }
    this.failureCount = 0;
    this.state = "closed";
  }

  private onFailure(): void {
    this.failureCount++;
    this.lastFailureTime = Date.now();

    if (this.failureCount >= this.options.failureThreshold) {
      this.state = "open";
      logger.warn(
        { label: this.label, failureCount: this.failureCount, resetTimeoutMs: this.options.resetTimeoutMs },
        "Circuit breaker opened after repeated failures"
      );
    }
  }
}
