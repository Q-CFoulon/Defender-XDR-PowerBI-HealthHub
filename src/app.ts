import cors from "cors";
import express, { type Express } from "express";
import cron, { type ScheduledTask } from "node-cron";
import path from "node:path";
import { DefenderClient } from "./clients/defenderClient";
import { GraphClient } from "./clients/graphClient";
import { OAuthClient } from "./clients/oauthClient";
import { config } from "./config/env";
import { logger } from "./config/logger";
import { McpBridgeClient } from "./remediation/mcpBridgeClient";
import { RemediationService } from "./remediation/remediation.service";
import { createHealthRouter } from "./routes/health.routes";
import { createPowerBiRouter } from "./routes/powerbi.routes";
import { NormalizeService } from "./services/normalize.service";
import { PipelineService } from "./services/pipeline.service";
import { PowerBiExporterService } from "./services/powerbiExporter.service";
import { SnapshotStoreService } from "./services/snapshotStore.service";

export interface ApplicationRuntime {
  app: Express;
  pipelineService: PipelineService;
  startScheduler: () => void;
  stopScheduler: () => void;
}

export const createApplication = async (): Promise<ApplicationRuntime> => {
  const app = express();

  app.use(cors());
  app.use(express.json({ limit: "1mb" }));
  app.use("/static", express.static(path.join(__dirname, "..", "public")));

  app.get("/", (_req, res) => {
    res.json({
      service: "defender-xdr-powerbi-healthhub",
      message: "Use /api endpoints for health, Power BI data, and refresh control.",
      endpoints: {
        adminDashboard: "/admin",
        health: "/api/health",
        powerBiOverview: "/api/powerbi/overview",
        powerBiIngestionStatus: "/api/powerbi/ingestion-status",
        manualRefresh: "POST /api/admin/refresh"
      }
    });
  });

  app.get("/admin", (_req, res) => {
    res.sendFile(path.join(__dirname, "..", "public", "index.html"));
  });

  const oauthClient = new OAuthClient(config);
  const defenderClient = new DefenderClient(config, oauthClient);
  const graphClient = new GraphClient(config, oauthClient);
  const normalizeService = new NormalizeService();
  const mcpBridgeClient = new McpBridgeClient(config);
  const remediationService = new RemediationService(mcpBridgeClient);
  const snapshotStore = new SnapshotStoreService(config.dataDirectory);
  const powerBiExporter = new PowerBiExporterService(config);

  const pipelineService = new PipelineService(
    config,
    defenderClient,
    graphClient,
    normalizeService,
    remediationService,
    snapshotStore,
    powerBiExporter
  );

  await pipelineService.hydrateFromDisk();

  app.use("/api/health", createHealthRouter(pipelineService));
  app.use(
    "/api/powerbi",
    createPowerBiRouter(
      () => pipelineService.getLatestSnapshot(),
      () => pipelineService.getIngestionStatus()
    )
  );

  app.post("/api/admin/refresh", async (_req, res) => {
    try {
      const snapshot = await pipelineService.refresh("manual-api-trigger");
      res.json({
        ok: true,
        collectedAt: snapshot.collectedAt,
        recommendationCount: snapshot.remediationRecommendations.length
      });
    } catch (error) {
      logger.error({ error }, "Manual refresh request failed");
      res.status(500).json({
        ok: false,
        message: "Refresh failed. Check logs for details."
      });
    }
  });

  let scheduledTask: ScheduledTask | null = null;

  const startScheduler = (): void => {
    if (scheduledTask) {
      return;
    }

    if (!cron.validate(config.refreshCron)) {
      throw new Error(`Invalid REFRESH_CRON value: ${config.refreshCron}`);
    }

    scheduledTask = cron.schedule(config.refreshCron, () => {
      void pipelineService.refresh("scheduled-cron").catch((error: unknown) => {
        logger.error({ error }, "Scheduled refresh failed");
      });
    });

    logger.info({ cron: config.refreshCron }, "Refresh scheduler started");
  };

  const stopScheduler = (): void => {
    if (!scheduledTask) {
      return;
    }

    scheduledTask.stop();
    scheduledTask = null;
    logger.info("Refresh scheduler stopped");
  };

  return {
    app,
    pipelineService,
    startScheduler,
    stopScheduler
  };
};
