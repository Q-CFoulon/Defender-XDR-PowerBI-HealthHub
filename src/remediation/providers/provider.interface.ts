import type {
  ProgramInitiative,
  SecureScores,
  TopInitiative,
  VulnerabilityOverview
} from "../../types/domain";

export interface ProviderSignalContext {
  secureScores: SecureScores;
  vulnerabilityOverview: VulnerabilityOverview;
  topInitiatives: TopInitiative[];
  programInitiatives: ProgramInitiative[];
}

export interface LocalRecommendation {
  title: string;
  description: string;
  priority: "high" | "medium" | "low";
  relatedRiskArea: string;
  link: string;
  snippet?: string;
}

export interface LocalMcpProvider {
  readonly serverName: string;
  generate(context: ProviderSignalContext): LocalRecommendation[];
}
