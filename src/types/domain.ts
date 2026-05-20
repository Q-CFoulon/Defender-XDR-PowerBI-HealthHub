export type TrendDirection = "up" | "down" | "flat";

export type SourceHealthStatus = "unknown" | "healthy" | "degraded" | "failed" | "disabled";
export type RefreshHealthStatus = "never" | "success" | "partial" | "failed";

export interface SourceErrorDetail {
  source: "defender" | "graph" | "mcpBridge";
  endpoint: string;
  path: string;
  statusCode: number | null;
  message: string;
}

export interface SourceRuntimeStatus {
  status: SourceHealthStatus;
  errorCount: number;
  lastError: string | null;
  details: string[];
}

export interface IngestionStatusSnapshot {
  lastRefreshStatus: RefreshHealthStatus;
  lastRefreshTime: string | null;
  lastRefreshTrigger: string | null;
  lastRefreshError: string | null;
  sourceStatus: {
    defender: SourceRuntimeStatus;
    graph: SourceRuntimeStatus;
    mcpBridge: SourceRuntimeStatus;
  };
}

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

/** Tracks when each data section was last successfully populated with non-empty data. */
export interface DataFreshness {
  secureScores: string | null;
  cloudSecureScore: string | null;
  m365SecureScore: string | null;
  programInitiatives: string | null;
  topInitiatives: string | null;
  vulnerabilityOverview: string | null;
  remediationRecommendations: string | null;
}

export interface UnifiedSnapshot {
  collectedAt: string;
  programInitiatives: ProgramInitiative[];
  topInitiatives: TopInitiative[];
  secureScores: SecureScores;
  vulnerabilityOverview: VulnerabilityOverview;
  remediationRecommendations: RemediationRecommendation[];
  dataFreshness: DataFreshness;
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
  errors: SourceErrorDetail[];
}

export interface GraphRawData {
  secureScores: unknown;
  error: SourceErrorDetail | null;
}
