import type { LocalMcpProvider, LocalRecommendation, ProviderSignalContext } from "./provider.interface";

export class SentinelProvider implements LocalMcpProvider {
  public readonly serverName = "microsoft-sentinel";

  public generate(ctx: ProviderSignalContext): LocalRecommendation[] {
    const recs: LocalRecommendation[] = [];
    const critVulns = ctx.vulnerabilityOverview.criticalVulnerabilities;
    const exposure = ctx.vulnerabilityOverview.exposureScore;
    const activeRecs = ctx.vulnerabilityOverview.activeRecommendations;

    if (critVulns > 0) {
      recs.push({
        title: `Create analytics rules to detect exploitation of ${critVulns} critical vulnerabilities`,
        description:
          `${critVulns} critical vulnerabilities detected across managed endpoints. ` +
          "Create Sentinel scheduled analytics rules using CVE identifiers from Defender vulnerability data. " +
          "Map detections to MITRE ATT&CK techniques (Initial Access, Exploitation) and configure automated incident creation with severity High.",
        priority: "high",
        relatedRiskArea: "Threat Detection",
        link: "https://learn.microsoft.com/azure/sentinel/detect-threats-custom",
        snippet:
          `SecurityEvent\n| where TimeGenerated > ago(24h)\n` +
          `| where EventID in (4688, 4689)\n` +
          `| where Process has_any ("powershell", "cmd", "wscript")\n` +
          `| join kind=inner (\n` +
          `    DeviceTvmSoftwareVulnerabilities\n` +
          `    | where VulnerabilitySeverityLevel == "Critical"\n` +
          `) on DeviceId\n| project TimeGenerated, DeviceName, Process, CveId`
      });
    }

    if (exposure !== null && exposure >= 50) {
      recs.push({
        title: "Enable Sentinel fusion rules for high-exposure environment",
        description:
          `Environment exposure score is ${exposure}. Enable Microsoft Sentinel Fusion advanced multi-stage attack detection ` +
          "to correlate signals across identity, endpoint, and cloud. This detects lateral movement chains that target highly-exposed assets.",
        priority: "high",
        relatedRiskArea: "Advanced Threat Detection",
        link: "https://learn.microsoft.com/azure/sentinel/fusion"
      });
    } else {
      recs.push({
        title: "Review Sentinel analytics rule coverage for MITRE ATT&CK",
        description:
          "Verify that analytics rules cover authentication anomalies, impossible travel, suspicious process execution, and data exfiltration. " +
          "Enable scheduled rules for the MITRE ATT&CK techniques most relevant to your environment. Use the MITRE ATT&CK blade to identify coverage gaps.",
        priority: "medium",
        relatedRiskArea: "Threat Detection",
        link: "https://learn.microsoft.com/azure/sentinel/mitre-coverage"
      });
    }

    if (activeRecs > 5) {
      recs.push({
        title: `Monitor remediation progress for ${activeRecs} active recommendations`,
        description:
          `There are ${activeRecs} active security recommendations. Create a Sentinel workbook to track remediation velocity, ` +
          "alert when new critical recommendations appear, and report on mean-time-to-remediate by severity tier.",
        priority: "medium",
        relatedRiskArea: "Remediation Tracking",
        link: "https://learn.microsoft.com/azure/sentinel/monitor-your-data"
      });
    }

    return recs;
  }
}
