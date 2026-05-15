import { createApplication } from "./app";
import { config } from "./config/env";
import { logger } from "./config/logger";

const start = async (): Promise<void> => {
  const runtime = await createApplication();
  const runOnce = process.argv.includes("--once");

  if (runOnce) {
    await runtime.pipelineService.refresh("one-shot-cli");
    logger.info("One-time refresh completed successfully");
    return;
  }

  if (!runtime.pipelineService.getLatestSnapshot()) {
    try {
      await runtime.pipelineService.refresh("startup");
    } catch (error) {
      logger.warn({ error }, "Startup refresh failed; API will run with no snapshot until next refresh");
    }
  }

  runtime.startScheduler();

  const server = runtime.app.listen(config.appPort, () => {
    logger.info({ port: config.appPort }, "Defender XDR Power BI Health Hub API is listening");
  });

  const shutdown = (signal: string): void => {
    logger.info({ signal }, "Shutdown signal received");
    runtime.stopScheduler();

    const waitForRefresh = (): void => {
      if (runtime.pipelineService.isRefreshing()) {
        logger.info("Waiting for in-flight refresh to complete before shutdown...");
        setTimeout(waitForRefresh, 500);
        return;
      }

      server.close(() => {
        logger.info("HTTP server closed");
        process.exit(0);
      });
    };

    waitForRefresh();

    setTimeout(() => {
      logger.error("Force exiting after shutdown timeout");
      process.exit(1);
    }, 10_000).unref();
  };

  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
};

void start().catch((error) => {
  logger.error({ error }, "Fatal startup error");
  process.exit(1);
});
