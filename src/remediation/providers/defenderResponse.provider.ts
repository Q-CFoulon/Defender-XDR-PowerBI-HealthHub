import type { LocalMcpProvider, LocalRecommendation, ProviderSignalContext } from "./provider.interface";

export class DefenderResponseProvider implements LocalMcpProvider {
  public readonly serverName = "defender-response-mcp";

  public generate(ctx: ProviderSignalContext): LocalRecommendation[] {
    const recs: LocalRecommendation[] = [];
    const critVulns = ctx.vulnerabilityOverview.criticalVulnerabilities;
    const exposure = ctx.vulnerabilityOverview.exposureScore;
    const deviceDist = ctx.vulnerabilityOverview.deviceExposureDistribution;

    if (critVulns > 0) {
      recs.push({
        title: `Isolate and patch ${critVulns} critically vulnerable devices`,
        description:
          `${critVulns} critical vulnerabilities found. Use Defender for Endpoint automated investigation to identify affected devices, ` +
          "isolate compromised machines from the network, deploy emergency software updates via Intune, and restrict network access for unpatched endpoints. " +
          "Set automated investigation to Full — automatically remediate for critical severity findings.",
        priority: "high",
        relatedRiskArea: "Vulnerability Remediation",
        link: "https://learn.microsoft.com/defender-endpoint/respond-machine-alerts"
      });
    }

    if (deviceDist.high > 0) {
      recs.push({
        title: `Remediate ${deviceDist.high} high-exposure devices`,
        description:
          `${deviceDist.high} devices are classified as high exposure` +
          (deviceDist.medium > 0 ? ` and ${deviceDist.medium} as medium exposure` : "") +
          ". Review the Defender Vulnerability Management dashboard, prioritize devices by business criticality, " +
          "and create remediation activities with defined SLA targets. Use device groups to apply targeted security baselines.",
        priority: "high",
        relatedRiskArea: "Device Exposure",
        link: "https://learn.microsoft.com/defender-vulnerability-management/tvm-remediation"
      });
    }

    if (exposure !== null && exposure >= 50) {
      recs.push({
        title: "Configure attack surface reduction rules for high-exposure environment",
        description:
          `Exposure score is ${exposure}. Enable Attack Surface Reduction (ASR) rules in block mode: ` +
          "block Office apps from creating child processes, block credential stealing from LSASS, block untrusted executables from USB, " +
          "and block process creations from PSExec and WMI commands. Test in audit mode first on a pilot device group.",
        priority: "high",
        relatedRiskArea: "Attack Surface Reduction",
        link: "https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference",
        snippet:
          "# Intune ASR Rule GUIDs for high-impact rules:\n" +
          "# Block Office from creating child processes: d4f940ab-401b-4efc-aadc-ad5f3c50688a\n" +
          "# Block credential stealing from LSASS: 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2\n" +
          "# Block executable from USB: b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4\n" +
          "# Block process creations from WMI: e6db77e5-3df2-4cf1-b95a-636979351e5b"
      });
    } else {
      recs.push({
        title: "Configure automated investigation and response policies",
        description:
          "Set up Defender for Endpoint automated investigation to Full remediation for high-severity alerts. " +
          "Configure response actions for malware detection, suspicious activities, and device compliance violations. " +
          "Enable live response capability for rapid forensic analysis of incidents.",
        priority: "medium",
        relatedRiskArea: "Automated Response",
        link: "https://learn.microsoft.com/defender-endpoint/automated-investigations"
      });
    }

    return recs;
  }
}
