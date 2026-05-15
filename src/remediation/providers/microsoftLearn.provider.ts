import type { LocalMcpProvider, LocalRecommendation, ProviderSignalContext } from "./provider.interface";

export class MicrosoftLearnProvider implements LocalMcpProvider {
  public readonly serverName = "microsoft-learn-mcp";

  public generate(ctx: ProviderSignalContext): LocalRecommendation[] {
    const recs: LocalRecommendation[] = [];
    const m365 = ctx.secureScores.m365ScorePct;

    if (m365 !== null && m365 < 50) {
      recs.push({
        title: `Critical: M365 Secure Score at ${m365.toFixed(0)}% — enforce Conditional Access baseline`,
        description:
          "Deploy a Conditional Access baseline requiring MFA for all users, blocking legacy authentication protocols, and enforcing compliant or Hybrid Azure AD joined devices. " +
          "Start with report-only mode, validate sign-in logs for 48 hours, then switch to enforced. " +
          "The ACE learning agent should track which policy gaps contribute the most to score deficit and refine recommendations as policies are adopted.",
        priority: "high",
        relatedRiskArea: "Conditional Access & Identity",
        link: "https://learn.microsoft.com/entra/identity/conditional-access/plan-conditional-access"
      });
      recs.push({
        title: "Enable Identity Protection risk-based policies",
        description:
          "Configure Entra ID Identity Protection to automatically block high-risk sign-ins and require password changes for high-risk users. " +
          "Set medium-risk sign-ins to require MFA. This addresses the identity attack surface that most impacts Secure Score.",
        priority: "high",
        relatedRiskArea: "Identity Protection",
        link: "https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies"
      });
    } else if (m365 !== null && m365 < 80) {
      recs.push({
        title: `Enforce Conditional Access policies to raise M365 score from ${m365.toFixed(0)}%`,
        description:
          `Current M365 Secure Score is ${m365.toFixed(1)}%. Deploy Conditional Access policies requiring MFA for all users, block legacy authentication, ` +
          "enforce compliant device access, and restrict sign-ins from risky locations. " +
          "The ACE learning agent should track which policy gaps contribute the most to score deficit and refine recommendations as policies are adopted.",
        priority: "medium",
        relatedRiskArea: "Conditional Access & Identity",
        link: "https://learn.microsoft.com/entra/identity/conditional-access/plan-conditional-access"
      });
      recs.push({
        title: "Enable Data Loss Prevention policies for Exchange and SharePoint",
        description:
          "Configure DLP policies to detect and protect sensitive information types (SSN, credit card, health records) in Exchange Online and SharePoint. " +
          "Apply policy tips to educate users and block external sharing of sensitive content.",
        priority: "medium",
        relatedRiskArea: "Data Protection",
        link: "https://learn.microsoft.com/purview/dlp-learn-about-dlp"
      });
    } else {
      recs.push({
        title: "Review and maintain Secure Score improvement actions",
        description:
          "M365 Secure Score is at a healthy baseline. Review recently added improvement actions, ensure compliance policies remain enforced, " +
          "and monitor for new recommendations added by Microsoft. The ACE learning agent should flag any score regressions immediately.",
        priority: "low",
        relatedRiskArea: "M365 Secure Score",
        link: "https://learn.microsoft.com/microsoft-365/security/defender/microsoft-secure-score-improvement-actions"
      });
    }

    return recs;
  }
}
