export type TrendDirection = "up" | "down" | "flat";

export interface ProgramInitiative {
  name: string;
  currentScorePct: number | null;
  targetScorePct: number | null;
  trendDeltaPct: number | null;
  trendDirection: TrendDirection;
}

export interface TopInitiative {
  name: string;
  scorePct: number | null;
  trendDeltaPct: number | null;
}

export interface SecureScores {
  m365CurrentScore: number | null;
  m365MaxScore: number | null;
  m365ScorePct: number | null;
  cloudCurrentScore: number | null;
  cloudTargetScore: number | null;
  cloudScorePct: number | null;
}

export interface ScoreHistoryPoint {
  date: string;
  score: number;
}

export interface DeviceExposureDistribution {
  low: number;
  medium: number;
  high: number;
}

export interface VulnerabilityOverview {
  exposureScore: number | null;
  exposureLevel: string;
  criticalVulnerabilities: number;
  activeRecommendations: number;
  deviceExposureDistribution: DeviceExposureDistribution;
  scoreHistory: ScoreHistoryPoint[];
}

export type RecommendationPriority = "high" | "medium" | "low";

export interface RemediationRecommendation {
  id: string;
  source: string;
  title: string;
  description: string;
  priority: RecommendationPriority;
  relatedRiskArea: string;
  link?: string;
  snippet?: string;
  generatedAt: string;
}

export interface UnifiedSnapshot {
  collectedAt: string;
  programInitiatives: ProgramInitiative[];
  topInitiatives: TopInitiative[];
  secureScores: SecureScores;
  vulnerabilityOverview: VulnerabilityOverview;
  remediationRecommendations: RemediationRecommendation[];
  metadata: {
    tenantId: string;
    refreshCron: string;
    pipelineVersion: string;
  };
  raw: {
    defender: DefenderRawData;
    graph: GraphRawData;
  };
}

export interface DefenderRawData {
  initiatives: unknown;
  topInitiatives: unknown;
  vulnerabilityOverview: unknown;
  cloudSecureScore: unknown;
}

export interface GraphRawData {
  secureScores: unknown;
}
