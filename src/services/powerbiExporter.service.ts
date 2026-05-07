import { mkdir, writeFile } from "fs/promises";
import path from "path";
import axios from "axios";
import type { AppConfig } from "../config/env";
import { logger } from "../config/logger";
import type { UnifiedSnapshot } from "../types/domain";

export class PowerBiExporterService {
  public constructor(private readonly config: AppConfig) {}

  private async writeTable(tableName: string, payload: unknown): Promise<void> {
    const targetPath = path.join(this.config.dataDirectory, `${tableName}.json`);
    await writeFile(targetPath, JSON.stringify(payload, null, 2), "utf-8");
  }

  private async pushSummary(snapshot: UnifiedSnapshot): Promise<void> {
    if (!this.config.powerBiPushDatasetUrl) {
      return;
    }

    const headers: Record<string, string> = {
      "Content-Type": "application/json"
    };

    if (this.config.powerBiPushBearerToken.trim().length > 0) {
      headers.Authorization = `Bearer ${this.config.powerBiPushBearerToken}`;
    }

    try {
      await axios.post(
        this.config.powerBiPushDatasetUrl,
        {
          rows: [
            {
              collectedAt: snapshot.collectedAt,
              m365ScorePct: snapshot.secureScores.m365ScorePct,
              cloudScorePct: snapshot.secureScores.cloudScorePct,
              exposureScore: snapshot.vulnerabilityOverview.exposureScore,
              criticalVulnerabilities: snapshot.vulnerabilityOverview.criticalVulnerabilities,
              activeRecommendations: snapshot.vulnerabilityOverview.activeRecommendations,
              remediationRecommendationCount: snapshot.remediationRecommendations.length
            }
          ]
        },
        {
          headers,
          timeout: 30_000
        }
      );
    } catch (error) {
      logger.warn({ error }, "Power BI push endpoint call failed");
    }
  }

  public async exportSnapshot(snapshot: UnifiedSnapshot): Promise<void> {
    await mkdir(this.config.dataDirectory, { recursive: true });

    await Promise.all([
      this.writeTable("full-snapshot", snapshot),
      this.writeTable("program-initiatives", snapshot.programInitiatives),
      this.writeTable("top-initiatives", snapshot.topInitiatives),
      this.writeTable("secure-scores", snapshot.secureScores),
      this.writeTable("vulnerability-overview", snapshot.vulnerabilityOverview),
      this.writeTable("remediation-recommendations", snapshot.remediationRecommendations)
    ]);

    await this.pushSummary(snapshot);
  }
}
