import type { AppConfig } from "../config/env";
import { logger } from "../config/logger";
import { DefenderClient } from "../clients/defenderClient";
import { GraphClient } from "../clients/graphClient";
import { RemediationService } from "../remediation/remediation.service";
import type { UnifiedSnapshot } from "../types/domain";
import { NormalizeService } from "./normalize.service";
import { PowerBiExporterService } from "./powerbiExporter.service";
import { SnapshotStoreService } from "./snapshotStore.service";

export class PipelineService {
  private latestSnapshot: UnifiedSnapshot | null = null;

  public constructor(
    private readonly config: AppConfig,
    private readonly defenderClient: DefenderClient,
    private readonly graphClient: GraphClient,
    private readonly normalizeService: NormalizeService,
    private readonly remediationService: RemediationService,
    private readonly snapshotStore: SnapshotStoreService,
    private readonly powerBiExporter: PowerBiExporterService
  ) {}

  public async hydrateFromDisk(): Promise<void> {
    this.latestSnapshot = await this.snapshotStore.loadLatest();
  }

  public getLatestSnapshot(): UnifiedSnapshot | null {
    return this.latestSnapshot;
  }

  public async refresh(trigger: string): Promise<UnifiedSnapshot> {
    logger.info({ trigger }, "Starting Defender XDR data refresh");

    const [defenderRaw, graphRaw] = await Promise.all([
      this.defenderClient.collectRawData(),
      this.graphClient.collectRawData()
    ]);

    const normalized = this.normalizeService.normalize(defenderRaw, graphRaw);
    const remediationRecommendations = await this.remediationService.generateRecommendations({
      secureScores: normalized.secureScores,
      vulnerabilityOverview: normalized.vulnerabilityOverview,
      topInitiatives: normalized.topInitiatives,
      programInitiatives: normalized.programInitiatives
    });

    const snapshot: UnifiedSnapshot = {
      collectedAt: new Date().toISOString(),
      ...normalized,
      remediationRecommendations,
      metadata: {
        tenantId: this.config.tenantId,
        refreshCron: this.config.refreshCron,
        pipelineVersion: "1.0.0"
      },
      raw: {
        defender: defenderRaw,
        graph: graphRaw
      }
    };

    await this.snapshotStore.save(snapshot);
    await this.powerBiExporter.exportSnapshot(snapshot);

    this.latestSnapshot = snapshot;

    logger.info(
      {
        collectedAt: snapshot.collectedAt,
        recommendationCount: snapshot.remediationRecommendations.length
      },
      "Defender XDR data refresh completed"
    );

    return snapshot;
  }
}
