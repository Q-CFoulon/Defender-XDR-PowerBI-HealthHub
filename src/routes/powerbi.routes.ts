import { Router } from "express";
import type { UnifiedSnapshot } from "../types/domain";

type SnapshotGetter = () => UnifiedSnapshot | null;

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

export const createPowerBiRouter = (getSnapshot: SnapshotGetter): Router => {
  const router = Router();

  router.get("/overview", (_req, res) => {
    const snapshot = requireSnapshot(res, getSnapshot);
    if (!snapshot) {
      return;
    }

    res.json({
      collectedAt: snapshot.collectedAt,
      secureScores: snapshot.secureScores,
      vulnerabilityOverview: snapshot.vulnerabilityOverview,
      recommendationCount: snapshot.remediationRecommendations.length
    });
  });

  router.get("/program-initiatives", (_req, res) => {
    const snapshot = requireSnapshot(res, getSnapshot);
    if (!snapshot) {
      return;
    }
    res.json(snapshot.programInitiatives);
  });

  router.get("/top-initiatives", (_req, res) => {
    const snapshot = requireSnapshot(res, getSnapshot);
    if (!snapshot) {
      return;
    }
    res.json(snapshot.topInitiatives);
  });

  router.get("/secure-scores", (_req, res) => {
    const snapshot = requireSnapshot(res, getSnapshot);
    if (!snapshot) {
      return;
    }
    res.json(snapshot.secureScores);
  });

  router.get("/vulnerability-overview", (_req, res) => {
    const snapshot = requireSnapshot(res, getSnapshot);
    if (!snapshot) {
      return;
    }
    res.json(snapshot.vulnerabilityOverview);
  });

  router.get("/remediation-recommendations", (_req, res) => {
    const snapshot = requireSnapshot(res, getSnapshot);
    if (!snapshot) {
      return;
    }
    res.json(snapshot.remediationRecommendations);
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
