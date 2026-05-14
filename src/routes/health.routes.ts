import { Router } from "express";
import type { PipelineService } from "../services/pipeline.service";

export const createHealthRouter = (pipelineService: PipelineService): Router => {
  const router = Router();

  router.get("/", (_req, res) => {
    const snapshot = pipelineService.getLatestSnapshot();
    const ingestionStatus = pipelineService.getIngestionStatus();

    res.json({
      status: "ok",
      service: "defender-xdr-powerbi-healthhub",
      uptimeSeconds: Number(process.uptime().toFixed(2)),
      hasSnapshot: Boolean(snapshot),
      latestCollectionTime: snapshot?.collectedAt ?? null,
      tenantId: snapshot?.metadata.tenantId ?? null,
      ingestionStatus
    });
  });

  return router;
};
