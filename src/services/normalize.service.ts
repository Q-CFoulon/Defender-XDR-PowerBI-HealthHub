import type {
  DefenderRawData,
  DeviceExposureDistribution,
  GraphRawData,
  ProgramInitiative,
  ScoreHistoryPoint,
  SecureScores,
  TopInitiative,
  TrendDirection,
  VulnerabilityOverview
} from "../types/domain";

export interface NormalizedDataset {
  programInitiatives: ProgramInitiative[];
  topInitiatives: TopInitiative[];
  secureScores: SecureScores;
  vulnerabilityOverview: VulnerabilityOverview;
}

const asRecord = (value: unknown): Record<string, unknown> | null => {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
};

const pickArray = (value: unknown): unknown[] => {
  if (Array.isArray(value)) {
    return value;
  }

  const record = asRecord(value);
  if (!record) {
    return [];
  }

  const candidateKeys = ["value", "items", "data", "results"];
  for (const key of candidateKeys) {
    if (Array.isArray(record[key])) {
      return record[key] as unknown[];
    }
  }

  return [];
};

const toNumber = (value: unknown): number | null => {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === "string") {
    const cleaned = value.replace("%", "").trim();
    const parsed = Number(cleaned);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }

  return null;
};

const toString = (value: unknown, fallback = ""): string => {
  if (typeof value === "string") {
    return value.trim().length > 0 ? value : fallback;
  }

  if (typeof value === "number") {
    return String(value);
  }

  return fallback;
};

const toTrend = (delta: number | null): TrendDirection => {
  if (delta === null) {
    return "flat";
  }
  if (delta > 0) {
    return "up";
  }
  if (delta < 0) {
    return "down";
  }
  return "flat";
};

const deriveExposureLevel = (exposureScore: number | null): string => {
  if (exposureScore === null) {
    return "Unknown";
  }
  if (exposureScore < 35) {
    return "Low";
  }
  if (exposureScore < 70) {
    return "Medium";
  }
  return "High";
};

const parseDeviceDistribution = (value: unknown): DeviceExposureDistribution => {
  const defaults: DeviceExposureDistribution = {
    low: 0,
    medium: 0,
    high: 0
  };

  const record = asRecord(value);
  if (!record) {
    return defaults;
  }

  return {
    low: toNumber(record.low) ?? toNumber(record.Low) ?? 0,
    medium: toNumber(record.medium) ?? toNumber(record.Medium) ?? 0,
    high: toNumber(record.high) ?? toNumber(record.High) ?? 0
  };
};

const parseScoreHistory = (value: unknown): ScoreHistoryPoint[] => {
  const rows = pickArray(value);
  return rows
    .map((row): ScoreHistoryPoint | null => {
      const record = asRecord(row);
      if (!record) {
        return null;
      }

      const date =
        toString(record.date) ||
        toString(record.day) ||
        toString(record.timestamp) ||
        new Date().toISOString().slice(0, 10);

      const score =
        toNumber(record.score) ??
        toNumber(record.exposureScore) ??
        toNumber(record.value);

      if (score === null) {
        return null;
      }

      return {
        date,
        score
      };
    })
    .filter((item): item is ScoreHistoryPoint => item !== null);
};

const normalizeProgramInitiatives = (raw: unknown): ProgramInitiative[] => {
  const rows = pickArray(raw);
  return rows
    .map((row): ProgramInitiative | null => {
      const record = asRecord(row);
      if (!record) {
        return null;
      }

      const name =
        toString(record.name) ||
        toString(record.title) ||
        toString(record.initiativeName) ||
        toString(record.recommendationName) ||
        toString(record.category) ||
        toString(record.productName) ||
        "Unknown";

      const currentScorePct =
        toNumber(record.currentScorePct) ??
        toNumber(record.currentScore) ??
        toNumber(record.scorePct) ??
        toNumber(record.score) ??
        toNumber(record.severityScore) ??
        toNumber(record.currentPercentage);

      const targetScorePct =
        toNumber(record.targetScorePct) ??
        toNumber(record.targetScore) ??
        toNumber(record.target) ??
        99;

      const trendDeltaPct =
        toNumber(record.trendDeltaPct) ??
        toNumber(record.trendDelta) ??
        toNumber(record.delta) ??
        toNumber(record.change14Days) ??
        toNumber(record.exposureImpact) ??
        0;

      return {
        name,
        currentScorePct,
        targetScorePct,
        trendDeltaPct,
        trendDirection: toTrend(trendDeltaPct)
      };
    })
    .filter((item): item is ProgramInitiative => item !== null);
};

const normalizeTopInitiatives = (raw: unknown): TopInitiative[] => {
  const rows = pickArray(raw);
  return rows
    .map((row): TopInitiative | null => {
      const record = asRecord(row);
      if (!record) {
        return null;
      }

      const name =
        toString(record.name) ||
        toString(record.title) ||
        toString(record.initiativeName) ||
        toString(record.recommendationName) ||
        "Unknown";

      const scorePct =
        toNumber(record.scorePct) ??
        toNumber(record.currentScorePct) ??
        toNumber(record.score) ??
        toNumber(record.cvssV3) ??
        toNumber(record.severityScore) ??
        null;

      const trendDeltaPct =
        toNumber(record.trendDeltaPct) ??
        toNumber(record.trendDelta) ??
        toNumber(record.delta) ??
        toNumber(record.exposureImpact) ??
        0;

      return {
        name,
        scorePct,
        trendDeltaPct
      };
    })
    .filter((item): item is TopInitiative => item !== null);
};

const parseM365SecureScores = (raw: unknown): { current: number | null; max: number | null } => {
  const rows = pickArray(raw);
  const row = asRecord(rows[0]);

  if (!row) {
    return {
      current: null,
      max: null
    };
  }

  return {
    current: toNumber(row.currentScore),
    max: toNumber(row.maxScore)
  };
};

const parseCloudSecureScores = (raw: unknown): { current: number | null; target: number | null; pct: number | null } => {
  const rows = pickArray(raw);
  const row = asRecord(rows[0] ?? raw);

  if (!row) {
    return {
      current: null,
      target: null,
      pct: null
    };
  }

  const current =
    toNumber(row.currentScore) ??
    toNumber(row.score) ??
    toNumber(row.currentScorePct);

  const target =
    toNumber(row.targetScore) ??
    toNumber(row.target) ??
    toNumber(row.maxScore) ??
    99;

  const pct =
    toNumber(row.scorePct) ??
    (current !== null && target !== null && target > 0
      ? Number(((current / target) * 100).toFixed(2))
      : current);

  return {
    current,
    target,
    pct
  };
};

const normalizeVulnerabilityOverview = (raw: unknown): VulnerabilityOverview => {
  const record = asRecord(raw) ?? asRecord(pickArray(raw)[0]);
  if (!record) {
    return {
      exposureScore: null,
      exposureLevel: "Unknown",
      criticalVulnerabilities: 0,
      activeRecommendations: 0,
      deviceExposureDistribution: {
        low: 0,
        medium: 0,
        high: 0
      },
      scoreHistory: []
    };
  }

  const exposureScore =
    toNumber(record.exposureScore) ??
    toNumber(record.score) ??
    toNumber(record.currentExposureScore);

  const exposureLevel =
    toString(record.exposureLevel) ||
    toString(record.level) ||
    deriveExposureLevel(exposureScore);

  return {
    exposureScore,
    exposureLevel,
    criticalVulnerabilities:
      toNumber(record.criticalVulnerabilities) ??
      toNumber(record.criticalCount) ??
      0,
    activeRecommendations:
      toNumber(record.activeRecommendations) ??
      toNumber(record.recommendationCount) ??
      0,
    deviceExposureDistribution: parseDeviceDistribution(
      record.deviceExposureDistribution ?? record.distribution
    ),
    scoreHistory: parseScoreHistory(record.scoreHistory ?? record.history)
  };
};

export class NormalizeService {
  public normalize(defender: DefenderRawData, graph: GraphRawData): NormalizedDataset {
    const m365 = parseM365SecureScores(graph.secureScores);
    const cloud = parseCloudSecureScores(defender.cloudSecureScore);

    const secureScores: SecureScores = {
      m365CurrentScore: m365.current,
      m365MaxScore: m365.max,
      m365ScorePct:
        m365.current !== null && m365.max !== null && m365.max > 0
          ? Number(((m365.current / m365.max) * 100).toFixed(2))
          : null,
      cloudCurrentScore: cloud.current,
      cloudTargetScore: cloud.target,
      cloudScorePct: cloud.pct
    };

    return {
      programInitiatives: normalizeProgramInitiatives(defender.initiatives),
      topInitiatives: normalizeTopInitiatives(defender.topInitiatives),
      secureScores,
      vulnerabilityOverview: normalizeVulnerabilityOverview(defender.vulnerabilityOverview)
    };
  }
}
