import type { LocalMcpProvider, LocalRecommendation, ProviderSignalContext } from "./provider.interface";

export class FabricProvider implements LocalMcpProvider {
  public readonly serverName = "fabric-mcp";

  public generate(ctx: ProviderSignalContext): LocalRecommendation[] {
    const recs: LocalRecommendation[] = [];
    const m365 = ctx.secureScores.m365ScorePct;
    const cloud = ctx.secureScores.cloudScorePct;
    const hasScoreData = m365 !== null || cloud !== null;
    const hasInitiatives = ctx.programInitiatives.length > 0 || ctx.topInitiatives.length > 0;

    if (hasScoreData) {
      const scoreSummary = [
        m365 !== null ? `M365: ${m365.toFixed(0)}%` : null,
        cloud !== null ? `Cloud: ${cloud.toFixed(0)}%` : null
      ]
        .filter(Boolean)
        .join(", ");

      recs.push({
        title: "Build Secure Score trend dashboard in Microsoft Fabric",
        description:
          `Current scores: ${scoreSummary}. Create a Fabric lakehouse to ingest daily Secure Score snapshots from this Health Hub API. ` +
          "Build a Power BI DirectLake report with score trend lines, week-over-week delta tracking, and regression alerting. " +
          "Use Data Activator to trigger Teams notifications when scores drop below baseline thresholds.",
        priority: "medium",
        relatedRiskArea: "Security Reporting",
        link: "https://learn.microsoft.com/fabric/data-activator/data-activator-introduction"
      });
    }

    if (hasInitiatives) {
      recs.push({
        title: "Create initiative tracking pipeline in Fabric",
        description:
          "Build a Fabric data pipeline that ingests program initiative and top initiative data from the Health Hub API on a scheduled basis. " +
          "Model the data with star schema dimensions for initiative area, time, and target vs. actual score. " +
          "Create an executive report showing initiative completion velocity and projected target achievement dates.",
        priority: "low",
        relatedRiskArea: "Initiative Tracking",
        link: "https://learn.microsoft.com/fabric/data-factory/create-first-pipeline-with-sample-data"
      });
    }

    recs.push({
      title: "Configure Fabric workspace security and row-level access",
      description:
        "Ensure the security analytics workspace has proper RLS policies so that regional security teams see only their scope. " +
        "Enable audit logging, restrict data export to approved destinations, and configure sensitivity labels on the lakehouse.",
      priority: "low",
      relatedRiskArea: "Data Governance",
      link: "https://learn.microsoft.com/fabric/security/security-overview"
    });

    return recs;
  }
}
