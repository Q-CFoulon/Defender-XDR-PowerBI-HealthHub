import { Router } from "express";
import type { IngestionStatusSnapshot, UnifiedSnapshot } from "../types/domain";

type SnapshotGetter = () => UnifiedSnapshot | null;
type IngestionStatusGetter = () => IngestionStatusSnapshot;

const requireSnapshot = (
  res: Parameters<Router["get"]>[1] extends (req: infer _Req, res: infer TRes, ...args: unknown[]) => unknown
    ? TRes
    : never,
  getSnapshot: SnapshotGetter
): UnifiedSnapshot | null => {
  const snapshot = getSnapshot();
  if (!snapshot) {
    res.status(503).json({
      error: "Snapshot unavailable",
      message: "No Defender snapshot is available yet. Trigger a refresh and retry."
    });
    return null;
  }
  return snapshot;
};

export const createPowerBiRouter = (
  getSnapshot: SnapshotGetter,
  getIngestionStatus: IngestionStatusGetter
): Router => {
  const router = Router();

  router.get("/ingestion-status", (_req, res) => {
    const snapshot = getSnapshot();
    const ingestionStatus = getIngestionStatus();

    res.json({
      hasSnapshot: Boolean(snapshot),
      latestCollectionTime: snapshot?.collectedAt ?? null,
      ...ingestionStatus
    });
  });

  router.get("/overview", (_req, res) => {
    const snapshot = requireSnapshot(res, getSnapshot);
    if (!snapshot) {
      return;
    }

    res.json({
      collectedAt: snapshot.collectedAt,
      secureScores: snapshot.secureScores,
      vulnerabilityOverview: snapshot.vulnerabilityOverview,
      recommendationCount: snapshot.remediationRecommendations.length,
      dataFreshness: snapshot.dataFreshness
    });
  });

  router.get("/program-initiatives", (_req, res) => {
    const snapshot = requireSnapshot(res, getSnapshot);
    if (!snapshot) {
      return;
    }
    res.json({
      items: snapshot.programInitiatives,
      dataAsOf: snapshot.dataFreshness.programInitiatives
    });
  });

  router.get("/top-initiatives", (_req, res) => {
    const snapshot = requireSnapshot(res, getSnapshot);
    if (!snapshot) {
      return;
    }
    res.json({
      items: snapshot.topInitiatives,
      dataAsOf: snapshot.dataFreshness.topInitiatives
    });
  });

  router.get("/secure-scores", (_req, res) => {
    const snapshot = requireSnapshot(res, getSnapshot);
    if (!snapshot) {
      return;
    }
    res.json({
      ...snapshot.secureScores,
      dataAsOf: {
        cloud: snapshot.dataFreshness.cloudSecureScore,
        m365: snapshot.dataFreshness.m365SecureScore
      }
    });
  });

  router.get("/vulnerability-overview", (_req, res) => {
    const snapshot = requireSnapshot(res, getSnapshot);
    if (!snapshot) {
      return;
    }
    res.json({
      ...snapshot.vulnerabilityOverview,
      dataAsOf: snapshot.dataFreshness.vulnerabilityOverview
    });
  });

  router.get("/remediation-recommendations", (_req, res) => {
    const snapshot = requireSnapshot(res, getSnapshot);
    if (!snapshot) {
      return;
    }
    res.json({
      items: snapshot.remediationRecommendations,
      dataAsOf: snapshot.dataFreshness.remediationRecommendations
    });
  });

  router.get("/full-snapshot", (_req, res) => {
    const snapshot = requireSnapshot(res, getSnapshot);
    if (!snapshot) {
      return;
    }
    res.json(snapshot);
  });

  return router;
};
