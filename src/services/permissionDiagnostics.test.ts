import { describe, it, expect } from "vitest";
import { analyzePermissions } from "./permissionDiagnostics.service";
import type { IngestionStatusSnapshot } from "../types/domain";

const healthy: IngestionStatusSnapshot = {
  lastRefreshStatus: "success",
  lastRefreshTime: "2026-05-14T00:00:00Z",
  lastRefreshTrigger: "cron",
  lastRefreshError: null,
  sourceStatus: {
    defender: { status: "healthy", errorCount: 0, lastError: null, details: [] },
    graph: { status: "healthy", errorCount: 0, lastError: null, details: [] },
    mcpBridge: { status: "healthy", errorCount: 0, lastError: null, details: [] }
  }
};

const allDefender403: IngestionStatusSnapshot = {
  lastRefreshStatus: "partial",
  lastRefreshTime: "2026-05-14T00:00:00Z",
  lastRefreshTrigger: "cron",
  lastRefreshError: "initiatives (403): Request failed with status code 403",
  sourceStatus: {
    defender: {
      status: "failed",
      errorCount: 4,
      lastError: "initiatives (403): Request failed with status code 403",
      details: [
        "initiatives (403): Request failed with status code 403",
        "topInitiatives (403): Request failed with status code 403",
        "vulnerabilityOverview (403): Request failed with status code 403",
        "cloudSecureScore (403): Request failed with status code 403"
      ]
    },
    graph: { status: "healthy", errorCount: 0, lastError: null, details: [] },
    mcpBridge: { status: "healthy", errorCount: 0, lastError: null, details: [] }
  }
};

const graph403: IngestionStatusSnapshot = {
  lastRefreshStatus: "partial",
  lastRefreshTime: "2026-05-14T00:00:00Z",
  lastRefreshTrigger: "cron",
  lastRefreshError: "secureScores (403): Request failed with status code 403",
  sourceStatus: {
    defender: { status: "healthy", errorCount: 0, lastError: null, details: [] },
    graph: {
      status: "failed",
      errorCount: 1,
      lastError: "secureScores (403): Request failed with status code 403",
      details: ["secureScores (403): Request failed with status code 403"]
    },
    mcpBridge: { status: "healthy", errorCount: 0, lastError: null, details: [] }
  }
};

describe("analyzePermissions", () => {
  it("reports healthy when no errors", () => {
    const report = analyzePermissions(healthy);
    expect(report.healthy).toBe(true);
    expect(report.missingGrants).toHaveLength(0);
    expect(report.otherErrors).toHaveLength(0);
    expect(report.summary).toContain("No missing permissions");
  });

  it("detects all Defender 403s and deduplicates Score.Read.All", () => {
    const report = analyzePermissions(allDefender403);
    expect(report.healthy).toBe(false);

    // Score.Read.All covers two endpoints but should appear once
    const scoreGrants = report.missingGrants.filter(
      (g) => g.likelyMissingPermission.permission === "Score.Read.All"
    );
    expect(scoreGrants).toHaveLength(1);

    // Should have 3 unique permissions: Score.Read.All, SecurityRecommendation.Read.All, Vulnerability.Read.All
    expect(report.missingGrants).toHaveLength(3);

    const permissions = report.missingGrants.map((g) => g.likelyMissingPermission.permission).sort();
    expect(permissions).toEqual(["Score.Read.All", "SecurityRecommendation.Read.All", "Vulnerability.Read.All"]);
  });

  it("detects Graph 403 as SecurityEvents.Read.All", () => {
    const report = analyzePermissions(graph403);
    expect(report.healthy).toBe(false);
    expect(report.missingGrants).toHaveLength(1);
    expect(report.missingGrants[0].likelyMissingPermission.api).toBe("Microsoft Graph");
    expect(report.missingGrants[0].likelyMissingPermission.permission).toBe("SecurityEvents.Read.All");
  });

  it("builds full permission status matrix", () => {
    const report = analyzePermissions(allDefender403);
    const matrix = report.allRequiredPermissions;

    // Should list all unique permissions
    expect(matrix.length).toBeGreaterThanOrEqual(4);

    const defenderScore = matrix.find(
      (p) => p.api === "WindowsDefenderATP" && p.permission === "Score.Read.All"
    );
    expect(defenderScore?.status).toBe("likely-missing");

    const graphPerm = matrix.find(
      (p) => p.api === "Microsoft Graph" && p.permission === "SecurityEvents.Read.All"
    );
    expect(graphPerm?.status).toBe("ok");
  });

  it("reports unknown status when no refresh has run", () => {
    const neverRefreshed: IngestionStatusSnapshot = {
      ...healthy,
      lastRefreshStatus: "never",
      lastRefreshTime: null
    };
    const report = analyzePermissions(neverRefreshed);
    expect(report.summary).toContain("No refresh has run yet");
  });
});
