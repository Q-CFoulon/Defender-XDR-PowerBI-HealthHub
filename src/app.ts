import cors from "cors";
import express, { type Express } from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cron, { type ScheduledTask } from "node-cron";
import path from "node:path";
import { DefenderClient } from "./clients/defenderClient";
import { GraphClient } from "./clients/graphClient";
import { OAuthClient } from "./clients/oauthClient";
import { config } from "./config/env";
import { logger } from "./config/logger";
import { createAdminAuth } from "./middleware/adminAuth";
import { metrics } from "./middleware/metrics";
import { McpBridgeClient } from "./remediation/mcpBridgeClient";
import { RemediationService } from "./remediation/remediation.service";
import { createHealthRouter } from "./routes/health.routes";
import { createPowerBiRouter } from "./routes/powerbi.routes";
import { NormalizeService } from "./services/normalize.service";
import { PipelineService } from "./services/pipeline.service";
import { analyzePermissions } from "./services/permissionDiagnostics.service";
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

  // Security headers
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"]
      }
    }
  }));

  // CORS
  const corsOrigins = config.corsAllowedOrigins.trim();
  app.use(cors(corsOrigins.length > 0
    ? { origin: corsOrigins.split(",").map((o) => o.trim()), credentials: true }
    : undefined
  ));

  // Global rate limiter: 100 requests per minute per IP
  app.use(rateLimit({
    windowMs: 60_000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Too many requests, please try again later." }
  }));

  app.use(express.json({ limit: "1mb" }));

  // Request counting middleware
  app.use((_req, res, next) => {
    metrics.httpRequests.increment();
    res.on("finish", () => {
      if (res.statusCode >= 400) {
        metrics.httpErrors.increment();
      }
    });
    next();
  });

  app.use("/static", express.static(path.join(__dirname, "..", "public")));

  // Admin auth middleware
  const adminAuth = createAdminAuth(config.adminApiKey);

  // Stricter rate limit for refresh endpoint: 5 per minute
  const refreshLimiter = rateLimit({
    windowMs: 60_000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Refresh rate limit exceeded. Max 5 per minute." }
  });

  app.get("/", (_req, res) => {
    res.json({
      service: "defender-xdr-powerbi-healthhub",
      message: "Use /api endpoints for health, Power BI data, and refresh control.",
      endpoints: {
        dashboard: "/dashboard",
        adminDashboard: "/admin",
        health: "/api/health",
        powerBiOverview: "/api/powerbi/overview",
        powerBiIngestionStatus: "/api/powerbi/ingestion-status",
        permissionDiagnostics: "/api/diagnostics/permissions",
        manualRefresh: "POST /api/admin/refresh"
      }
    });
  });

  app.get("/dashboard", adminAuth, (_req, res) => {
    res.sendFile(path.join(__dirname, "..", "public", "index.html"));
  });

  app.get("/admin", adminAuth, (_req, res) => {
    res.sendFile(path.join(__dirname, "..", "public", "admin.html"));
  });

  // Convenience redirects for .html paths
  app.get("/admin.html", (_req, res) => res.redirect("/admin"));
  app.get("/index.html", (_req, res) => res.redirect("/dashboard"));

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

  app.get("/api/metrics", adminAuth, (_req, res) => {
    res.json(metrics.snapshot());
  });

  app.get("/api/diagnostics/permissions", adminAuth, (_req, res) => {
    const report = analyzePermissions(pipelineService.getIngestionStatus());
    res.json(report);
  });

  app.use(
    "/api/powerbi",
    createPowerBiRouter(
      () => pipelineService.getLatestSnapshot(),
      () => pipelineService.getIngestionStatus()
    )
  );

  app.post("/api/admin/refresh", adminAuth, refreshLimiter, async (_req, res) => {
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
