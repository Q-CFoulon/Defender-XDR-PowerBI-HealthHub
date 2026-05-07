import crypto from "crypto";
import type {
  ProgramInitiative,
  RecommendationPriority,
  RemediationRecommendation,
  SecureScores,
  TopInitiative,
  VulnerabilityOverview
} from "../types/domain";
import {
  McpBridgeClient,
  type McpRecommendationCandidate
} from "./mcpBridgeClient";

interface RemediationInput {
  secureScores: SecureScores;
  vulnerabilityOverview: VulnerabilityOverview;
  topInitiatives: TopInitiative[];
  programInitiatives: ProgramInitiative[];
}

interface ProviderDefinition {
  source: string;
  server: string;
  capability: string;
  fallbackLink: string;
}

const PROVIDERS: ProviderDefinition[] = [
  {
    source: "Microsoft Learn MCP",
    server: "microsoft-learn-mcp",
    capability: "remediationGuidance",
    fallbackLink: "https://learn.microsoft.com/security"
  },
  {
    source: "Azure MCP",
    server: "azure-mcp",
    capability: "securityHardening",
    fallbackLink: "https://learn.microsoft.com/azure/security"
  },
  {
    source: "Microsoft Sentinel",
    server: "microsoft-sentinel",
    capability: "siemRemediation",
    fallbackLink: "https://learn.microsoft.com/azure/sentinel"
  },
  {
    source: "Security Copilot Snippets",
    server: "microsoft-security-copilot",
    capability: "snippetGeneration",
    fallbackLink: "https://learn.microsoft.com/security-copilot"
  },
  {
    source: "Fabric MCP",
    server: "fabric-mcp",
    capability: "securityDataModeling",
    fallbackLink: "https://learn.microsoft.com/fabric"
  },
  {
    source: "Defender Response MCP",
    server: "defender-response-mcp",
    capability: "responseActions",
    fallbackLink: "https://learn.microsoft.com/defender-xdr"
  }
];

const toPriority = (value: string | undefined): RecommendationPriority => {
  if (!value) {
    return "medium";
  }

  const normalized = value.trim().toLowerCase();
  if (normalized.includes("high") || normalized.includes("critical")) {
    return "high";
  }
  if (normalized.includes("low")) {
    return "low";
  }
  return "medium";
};

const buildSignalSummary = (input: RemediationInput): string => {
  const lowestProgramAreas = [...input.programInitiatives]
    .sort((a, b) => (a.currentScorePct ?? 0) - (b.currentScorePct ?? 0))
    .slice(0, 3)
    .map((item) => `${item.name}: ${item.currentScorePct ?? "n/a"}%`)
    .join("; ");

  const lowestTopInitiatives = [...input.topInitiatives]
    .sort((a, b) => (a.scorePct ?? 0) - (b.scorePct ?? 0))
    .slice(0, 3)
    .map((item) => `${item.name}: ${item.scorePct ?? "n/a"}%`)
    .join("; ");

  return [
    `M365 secure score percent: ${input.secureScores.m365ScorePct ?? "n/a"}`,
    `Cloud secure score percent: ${input.secureScores.cloudScorePct ?? "n/a"}`,
    `Exposure score: ${input.vulnerabilityOverview.exposureScore ?? "n/a"}`,
    `Critical vulnerabilities: ${input.vulnerabilityOverview.criticalVulnerabilities}`,
    `Active recommendations: ${input.vulnerabilityOverview.activeRecommendations}`,
    `Lowest program initiatives: ${lowestProgramAreas || "none"}`,
    `Lowest top initiatives: ${lowestTopInitiatives || "none"}`
  ].join(" | ");
};

const fallbackRecommendation = (
  provider: ProviderDefinition,
  input: RemediationInput,
  nowIso: string
): RemediationRecommendation => {
  const coverageGap =
    (input.secureScores.m365ScorePct !== null && input.secureScores.m365ScorePct < 80) ||
    (input.secureScores.cloudScorePct !== null && input.secureScores.cloudScorePct < 80);

  return {
    id: crypto.randomUUID(),
    source: provider.source,
    title: coverageGap
      ? "Increase secure score baseline coverage"
      : "Operationalize remediation runbooks",
    description: coverageGap
      ? "Focus first on recommendations that raise MFA enforcement, vulnerability patch compliance, and identity protection controls."
      : "Convert recurring recommendations into automated runbooks and track closure SLA by risk severity.",
    priority: coverageGap ? "high" : "medium",
    relatedRiskArea: "Secure Score",
    link: provider.fallbackLink,
    generatedAt: nowIso
  };
};

const mapCandidate = (
  provider: ProviderDefinition,
  candidate: McpRecommendationCandidate,
  nowIso: string
): RemediationRecommendation => ({
  id: crypto.randomUUID(),
  source: provider.source,
  title: candidate.title,
  description: candidate.description,
  priority: toPriority(candidate.priority),
  relatedRiskArea: candidate.relatedRiskArea ?? "Vulnerability Management",
  link: candidate.link,
  snippet: candidate.snippet,
  generatedAt: nowIso
});

export class RemediationService {
  public constructor(private readonly mcpBridgeClient: McpBridgeClient) {}

  public async generateRecommendations(
    input: RemediationInput
  ): Promise<RemediationRecommendation[]> {
    const nowIso = new Date().toISOString();
    const signalSummary = buildSignalSummary(input);

    const providerResults = await Promise.all(
      PROVIDERS.map(async (provider) => {
        const candidates = await this.mcpBridgeClient.requestRecommendations({
          server: provider.server,
          capability: provider.capability,
          query:
            "Generate prioritized remediation guidance with technical actions and expected risk reduction.",
          context: {
            signalSummary
          }
        });

        if (candidates.length === 0) {
          return [fallbackRecommendation(provider, input, nowIso)];
        }

        return candidates.slice(0, 3).map((candidate) => mapCandidate(provider, candidate, nowIso));
      })
    );

    return providerResults.flat();
  }
}
