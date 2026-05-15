import type { LocalMcpProvider, LocalRecommendation, ProviderSignalContext } from "./provider.interface";

export class SecurityCopilotProvider implements LocalMcpProvider {
  public readonly serverName = "microsoft-security-copilot";

  public generate(ctx: ProviderSignalContext): LocalRecommendation[] {
    const recs: LocalRecommendation[] = [];
    const exposure = ctx.vulnerabilityOverview.exposureScore;
    const critVulns = ctx.vulnerabilityOverview.criticalVulnerabilities;
    const m365 = ctx.secureScores.m365ScorePct;

    if (exposure !== null && exposure >= 50) {
      recs.push({
        title: "Generate incident response playbooks for high-exposure assets",
        description:
          `Exposure score is ${exposure}. Use Security Copilot to generate incident triage playbooks covering: ` +
          "initial containment steps, forensic evidence collection, stakeholder notification templates, and recovery procedures. " +
          "Create promptbooks for the top 3 attack scenarios targeting your most exposed device groups.",
        priority: "high",
        relatedRiskArea: "Incident Response",
        link: "https://learn.microsoft.com/security-copilot/respond-to-incidents",
        snippet:
          "# Security Copilot Promptbook: High-Exposure Incident Triage\n" +
          "1. /AskDefender \"Show devices with exposure level High in the last 7 days\"\n" +
          "2. /AskDefender \"List active alerts on these devices grouped by MITRE technique\"\n" +
          "3. /Summarize \"Create an incident summary with timeline and affected assets\"\n" +
          "4. /Recommend \"Suggest containment actions based on the alert chain\""
      });
    }

    if (critVulns > 0) {
      recs.push({
        title: `Build threat-hunting queries for ${critVulns} critical CVEs`,
        description:
          "Use Security Copilot to generate KQL hunting queries that detect exploitation attempts against known critical vulnerabilities. " +
          "Create a promptbook that cross-references DeviceTvmSoftwareVulnerabilities with process execution and network connection events.",
        priority: "high",
        relatedRiskArea: "Threat Hunting",
        link: "https://learn.microsoft.com/security-copilot/build-promptbooks",
        snippet:
          "# Security Copilot prompt:\n" +
          "/AskDefender \"Find processes spawned on devices with critical unpatched CVEs in the last 48 hours. " +
          "Cross-reference with network connections to external IPs. Flag any that match known C2 patterns.\""
      });
    }

    if (m365 !== null && m365 < 80) {
      recs.push({
        title: "Generate Secure Score gap analysis with Security Copilot",
        description:
          `M365 Secure Score is ${m365.toFixed(1)}%. Use Security Copilot to analyze the gap between current score and 80% baseline: ` +
          "identify the top 10 improvement actions by point impact, generate implementation guides for each, and estimate effort vs. risk reduction.",
        priority: "medium",
        relatedRiskArea: "Secure Score Analysis",
        link: "https://learn.microsoft.com/security-copilot/microsoft-security-copilot"
      });
    } else {
      recs.push({
        title: "Build proactive threat-hunting queries with Security Copilot",
        description:
          "Use Security Copilot to generate KQL hunting queries for emerging threats, summarize complex alert chains, " +
          "and draft response procedures for the top initiative areas.",
        priority: "low",
        relatedRiskArea: "Threat Hunting",
        link: "https://learn.microsoft.com/security-copilot/build-promptbooks"
      });
    }

    return recs;
  }
}
