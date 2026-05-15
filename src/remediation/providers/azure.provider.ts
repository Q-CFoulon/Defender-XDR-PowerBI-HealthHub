import type { LocalMcpProvider, LocalRecommendation, ProviderSignalContext } from "./provider.interface";

export class AzureProvider implements LocalMcpProvider {
  public readonly serverName = "azure-mcp";

  public generate(ctx: ProviderSignalContext): LocalRecommendation[] {
    const recs: LocalRecommendation[] = [];
    const cloud = ctx.secureScores.cloudScorePct;
    const lowestPrograms = [...ctx.programInitiatives]
      .sort((a, b) => (a.currentScorePct ?? 0) - (b.currentScorePct ?? 0))
      .slice(0, 3);

    if (cloud !== null && cloud < 50) {
      recs.push({
        title: `Critical: Cloud Secure Score at ${cloud.toFixed(0)}% — remediate Defender for Cloud controls`,
        description:
          "Enable Defender for Cloud foundational CSPM. Remediate the highest-impact security controls: enable just-in-time VM access, " +
          "enforce disk encryption, restrict public network access on storage accounts, and enable Microsoft Defender for Servers on all subscriptions.",
        priority: "high",
        relatedRiskArea: "Cloud Secure Score",
        link: "https://learn.microsoft.com/azure/defender-for-cloud/secure-score-security-controls"
      });
      recs.push({
        title: "Enforce Azure Policy for network isolation",
        description:
          "Deploy Azure Policy initiatives to deny public IP creation on VMs, require private endpoints for PaaS services, " +
          "and enforce NSG rules on all subnets. Use Deny effect for critical controls and Audit for monitoring.",
        priority: "high",
        relatedRiskArea: "Network Security",
        link: "https://learn.microsoft.com/azure/governance/policy/overview"
      });
    } else if (cloud !== null && cloud < 80) {
      recs.push({
        title: `Strengthen cloud security posture (score: ${cloud.toFixed(0)}%)`,
        description:
          `Cloud Secure Score is ${cloud.toFixed(1)}%. Address Defender for Cloud recommendations: ` +
          "enable just-in-time VM access, enforce encryption at rest, restrict public network endpoints, and review security control baselines.",
        priority: "medium",
        relatedRiskArea: "Cloud Secure Score",
        link: "https://learn.microsoft.com/azure/defender-for-cloud/secure-score-security-controls"
      });
    } else {
      recs.push({
        title: "Harden Azure network and identity controls",
        description:
          "Review Azure Security Benchmark controls for network isolation, private endpoints, and managed identity adoption. " +
          "Ensure all storage accounts, databases, and key vaults deny public access.",
        priority: "medium",
        relatedRiskArea: "Cloud Security Posture",
        link: "https://learn.microsoft.com/azure/defender-for-cloud/recommendations-reference"
      });
    }

    if (lowestPrograms.length > 0 && (lowestPrograms[0].currentScorePct ?? 100) < 60) {
      const names = lowestPrograms
        .filter((p) => (p.currentScorePct ?? 100) < 60)
        .map((p) => `${p.name} (${p.currentScorePct?.toFixed(0) ?? "N/A"}%)`)
        .join(", ");
      recs.push({
        title: "Address lowest-scoring program initiative areas",
        description:
          `The following initiative areas have scores below 60%: ${names}. ` +
          "Review the associated Defender for Cloud recommendations for each area and prioritize controls that close the largest point gaps.",
        priority: "medium",
        relatedRiskArea: "Program Initiatives",
        link: "https://learn.microsoft.com/azure/defender-for-cloud/security-policy-concept"
      });
    }

    return recs;
  }
}
