import crypto from "crypto";
import type {
  ProgramInitiative,
  RecommendationPriority,
  RemediationRecommendation,
  SecureScores,
  SourceHealthStatus,
  TopInitiative,
  VulnerabilityOverview
} from "../types/domain";
import {
  McpBridgeClient,
  type McpBridgeCallResult,
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

interface ProviderResult {
  recommendations: RemediationRecommendation[];
  failed: boolean;
  errorMessage: string | null;
}

export interface RemediationDiagnostics {
  mcpBridge: {
    configured: boolean;
    totalProviders: number;
    succeededProviders: number;
    failedProviders: number;
    status: SourceHealthStatus;
    errors: string[];
  };
}

export interface RemediationResult {
  recommendations: RemediationRecommendation[];
  diagnostics: RemediationDiagnostics;
}

const PROVIDERS: ProviderDefinition[] = [
  {
    source: "Microsoft Learn MCP",
    server: "microsoft-learn-mcp",
    capability: "remediationGuidance",
    fallbackLink: "https://learn.microsoft.com/microsoft-365/security/defender/microsoft-secure-score-improvement-actions"
  },
  {
    source: "Azure MCP",
    server: "azure-mcp",
    capability: "securityHardening",
    fallbackLink: "https://learn.microsoft.com/azure/defender-for-cloud/secure-score-security-controls"
  },
  {
    source: "Microsoft Sentinel",
    server: "microsoft-sentinel",
    capability: "siemRemediation",
    fallbackLink: "https://learn.microsoft.com/azure/sentinel/detect-threats-built-in"
  },
  {
    source: "Security Copilot Snippets",
    server: "microsoft-security-copilot",
    capability: "snippetGeneration",
    fallbackLink: "https://learn.microsoft.com/security-copilot/microsoft-security-copilot"
  },
  {
    source: "Fabric MCP",
    server: "fabric-mcp",
    capability: "securityDataModeling",
    fallbackLink: "https://learn.microsoft.com/fabric/security/security-overview"
  },
  {
    source: "Defender Response MCP",
    server: "defender-response-mcp",
    capability: "responseActions",
    fallbackLink: "https://learn.microsoft.com/defender-endpoint/respond-machine-alerts"
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

interface FallbackTemplate {
  title: string;
  description: string;
  priority: RecommendationPriority;
  relatedRiskArea: string;
  link: string;
}

const buildFallbackTemplates = (input: RemediationInput): Map<string, FallbackTemplate> => {
  const m365Pct = input.secureScores.m365ScorePct;
  const cloudPct = input.secureScores.cloudScorePct;
  const exposureScore = input.vulnerabilityOverview.exposureScore;
  const critVulns = input.vulnerabilityOverview.criticalVulnerabilities;
  const hasLowM365 = m365Pct !== null && m365Pct < 80;
  const hasLowCloud = cloudPct !== null && cloudPct < 80;
  const hasHighExposure = exposureScore !== null && exposureScore >= 50;
  const hasCritVulns = critVulns > 0;

  const templates = new Map<string, FallbackTemplate>();

  // Microsoft Learn MCP — Conditional Access & identity hardening
  if (hasLowM365) {
    templates.set("Microsoft Learn MCP", {
      title: `Enforce Conditional Access policies to raise M365 score from ${m365Pct?.toFixed(0)}%`,
      description: `Current M365 Secure Score is ${m365Pct?.toFixed(1)}%. Deploy Conditional Access policies requiring MFA for all users, block legacy authentication, enforce compliant device access, and restrict sign-ins from risky locations. The ACE learning agent should track which policy gaps contribute the most to score deficit and refine recommendations as policies are adopted.`,
      priority: m365Pct !== null && m365Pct < 50 ? "high" : "medium",
      relatedRiskArea: "Conditional Access & Identity",
      link: "https://learn.microsoft.com/entra/identity/conditional-access/plan-conditional-access"
    });
  } else {
    templates.set("Microsoft Learn MCP", {
      title: "Review and maintain Secure Score improvement actions",
      description: "M365 Secure Score is at a healthy baseline. Review recently added improvement actions and ensure compliance policies remain enforced to prevent score regression.",
      priority: "low",
      relatedRiskArea: "M365 Secure Score",
      link: "https://learn.microsoft.com/microsoft-365/security/defender/microsoft-secure-score-improvement-actions"
    });
  }

  // Azure MCP — Cloud security posture
  if (hasLowCloud) {
    templates.set("Azure MCP", {
      title: `Strengthen cloud security posture (score: ${cloudPct?.toFixed(0)}%)`,
      description: `Cloud Secure Score is ${cloudPct?.toFixed(1)}%. Address Defender for Cloud recommendations: enable just-in-time VM access, enforce encryption at rest, restrict public network endpoints, and review security control baselines.`,
      priority: cloudPct !== null && cloudPct < 50 ? "high" : "medium",
      relatedRiskArea: "Cloud Secure Score",
      link: "https://learn.microsoft.com/azure/defender-for-cloud/secure-score-security-controls"
    });
  } else {
    templates.set("Azure MCP", {
      title: "Harden Azure network and identity controls",
      description: "Review Azure Security Benchmark controls for network isolation, private endpoints, and managed identity adoption. Ensure all storage accounts, databases, and key vaults deny public access.",
      priority: "medium",
      relatedRiskArea: "Cloud Security Posture",
      link: "https://learn.microsoft.com/azure/defender-for-cloud/recommendations-reference"
    });
  }

  // Microsoft Sentinel — Threat detection
  if (hasCritVulns || hasHighExposure) {
    templates.set("Microsoft Sentinel", {
      title: `Enable detection rules for ${critVulns} critical vulnerabilities`,
      description: `${critVulns} critical vulnerabilities detected with exposure score ${exposureScore}. Create Sentinel analytics rules to detect exploitation attempts against known vulnerable assets. Enable built-in threat detection templates for active CVEs.`,
      priority: "high",
      relatedRiskArea: "Threat Detection",
      link: "https://learn.microsoft.com/azure/sentinel/detect-threats-built-in"
    });
  } else {
    templates.set("Microsoft Sentinel", {
      title: "Review Sentinel analytics rule coverage",
      description: "Verify that analytics rules cover authentication anomalies, impossible travel, and suspicious process execution. Enable scheduled rules for the MITRE ATT&CK techniques most relevant to your environment.",
      priority: "medium",
      relatedRiskArea: "Threat Detection",
      link: "https://learn.microsoft.com/azure/sentinel/detect-threats-built-in"
    });
  }

  // Security Copilot — Incident response
  templates.set("Security Copilot Snippets", {
    title: hasHighExposure
      ? "Generate incident response playbooks for high-exposure assets"
      : "Build proactive threat-hunting queries with Security Copilot",
    description: hasHighExposure
      ? `Exposure score is ${exposureScore}. Use Security Copilot to generate incident triage playbooks, automate KQL queries for threat hunting, and create response actions for the most exposed device groups.`
      : "Use Security Copilot to generate KQL hunting queries for emerging threats, summarize complex alert chains, and draft response procedures for the top initiative areas.",
    priority: hasHighExposure ? "high" : "low",
    relatedRiskArea: hasHighExposure ? "Incident Response" : "Threat Hunting",
    link: hasHighExposure
      ? "https://learn.microsoft.com/security-copilot/respond-to-incidents"
      : "https://learn.microsoft.com/security-copilot/build-promptbooks"
  });

  // Fabric MCP — Security reporting
  templates.set("Fabric MCP", {
    title: "Build security posture reporting in Microsoft Fabric",
    description: hasLowM365 || hasLowCloud
      ? `Track score improvement trends across M365 (${m365Pct?.toFixed(0) ?? "N/A"}%) and Cloud (${cloudPct?.toFixed(0) ?? "N/A"}%). Create Fabric lakehouses to aggregate security telemetry, build Power BI dashboards with score baselines, and set alerting thresholds for score regression.`
      : "Create executive dashboards in Fabric combining Secure Score trends, vulnerability metrics, and remediation SLA tracking. Use DirectLake mode for real-time security posture visibility.",
    priority: "low",
    relatedRiskArea: "Security Reporting",
    link: "https://learn.microsoft.com/fabric/security/security-overview"
  });

  // Defender Response MCP — Automated response
  if (hasCritVulns) {
    templates.set("Defender Response MCP", {
      title: `Isolate and patch ${critVulns} critically vulnerable devices`,
      description: `${critVulns} critical vulnerabilities found across managed devices. Use Defender for Endpoint automated investigation to isolate compromised machines, deploy software updates via Intune, and restrict network access for unpatched endpoints.`,
      priority: "high",
      relatedRiskArea: "Vulnerability Remediation",
      link: "https://learn.microsoft.com/defender-endpoint/respond-machine-alerts"
    });
  } else {
    templates.set("Defender Response MCP", {
      title: "Configure automated investigation and response actions",
      description: "Set up Defender for Endpoint automated investigation policies. Configure response actions for malware detection, suspicious activities, and device compliance violations. Enable live response for rapid forensic analysis.",
      priority: "medium",
      relatedRiskArea: "Automated Response",
      link: "https://learn.microsoft.com/defender-endpoint/automated-investigations"
    });
  }

  return templates;
};

const fallbackRecommendation = (
  provider: ProviderDefinition,
  input: RemediationInput,
  nowIso: string
): RemediationRecommendation => {
  const templates = buildFallbackTemplates(input);
  const template = templates.get(provider.source);

  if (template) {
    return {
      id: crypto.randomUUID(),
      source: provider.source,
      title: template.title,
      description: template.description,
      priority: template.priority,
      relatedRiskArea: template.relatedRiskArea,
      link: template.link,
      generatedAt: nowIso
    };
  }

  return {
    id: crypto.randomUUID(),
    source: provider.source,
    title: "Review security posture and remediation priorities",
    description: "Assess current security posture against organizational baselines and prioritize remediation actions by risk severity.",
    priority: "medium",
    relatedRiskArea: "Security Posture",
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

const getBridgeStatus = (failedProviders: number): SourceHealthStatus => {
  if (failedProviders === 0) {
    return "healthy";
  }

  if (failedProviders === PROVIDERS.length) {
    return "failed";
  }

  return "degraded";
};

const toProviderResult = (
  provider: ProviderDefinition,
  bridgeResponse: McpBridgeCallResult,
  input: RemediationInput,
  nowIso: string
): ProviderResult => {
  if (bridgeResponse.candidates.length === 0) {
    return {
      recommendations: [fallbackRecommendation(provider, input, nowIso)],
      failed: bridgeResponse.errorMessage !== null,
      errorMessage:
        bridgeResponse.errorMessage !== null
          ? `${provider.source}: ${bridgeResponse.errorMessage}`
          : null
    };
  }

  return {
    recommendations: bridgeResponse.candidates
      .slice(0, 3)
      .map((candidate) => mapCandidate(provider, candidate, nowIso)),
    failed: false,
    errorMessage: null
  };
};

export class RemediationService {
  public constructor(private readonly mcpBridgeClient: McpBridgeClient) {}

  public async generateRecommendations(input: RemediationInput): Promise<RemediationResult> {
    const nowIso = new Date().toISOString();
    const signalSummary = buildSignalSummary(input);

    if (!this.mcpBridgeClient.isConfigured()) {
      return {
        recommendations: PROVIDERS.map((provider) =>
          fallbackRecommendation(provider, input, nowIso)
        ),
        diagnostics: {
          mcpBridge: {
            configured: false,
            totalProviders: PROVIDERS.length,
            succeededProviders: 0,
            failedProviders: 0,
            status: "disabled",
            errors: []
          }
        }
      };
    }

    const providerResults = await Promise.all<ProviderResult>(
      PROVIDERS.map(async (provider) => {
        const bridgeResponse = await this.mcpBridgeClient.requestRecommendations({
          server: provider.server,
          capability: provider.capability,
          query:
            "Generate prioritized remediation guidance with technical actions and expected risk reduction.",
          context: {
            signalSummary
          }
        });

        return toProviderResult(provider, bridgeResponse, input, nowIso);
      })
    );

    const errors = providerResults
      .map((result) => result.errorMessage)
      .filter((value): value is string => value !== null);
    const failedProviders = providerResults.filter((result) => result.failed).length;

    return {
      recommendations: providerResults.flatMap((result) => result.recommendations),
      diagnostics: {
        mcpBridge: {
          configured: true,
          totalProviders: PROVIDERS.length,
          succeededProviders: PROVIDERS.length - failedProviders,
          failedProviders,
          status: getBridgeStatus(failedProviders),
          errors
        }
      }
    };
  }
}
