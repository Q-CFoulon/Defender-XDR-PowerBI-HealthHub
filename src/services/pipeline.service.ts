import type { AppConfig } from "../config/env";
import { logger } from "../config/logger";
import { metrics, startTimer } from "../middleware/metrics";
import { DefenderClient } from "../clients/defenderClient";
import { GraphClient } from "../clients/graphClient";
import {
  RemediationService,
  type RemediationDiagnostics
} from "../remediation/remediation.service";
import type {
  DefenderRawData,
  GraphRawData,
  IngestionStatusSnapshot,
  RefreshHealthStatus,
  SourceErrorDetail,
  SourceHealthStatus,
  SourceRuntimeStatus,
  UnifiedSnapshot
} from "../types/domain";
import { NormalizeService } from "./normalize.service";
import { PowerBiExporterService } from "./powerbiExporter.service";
import { SnapshotStoreService } from "./snapshotStore.service";

const EMPTY_SOURCE_STATUS = (): SourceRuntimeStatus => ({
  status: "unknown",
  errorCount: 0,
  lastError: null,
  details: []
});

const toSourceRuntimeStatus = (
  status: SourceHealthStatus,
  details: string[]
): SourceRuntimeStatus => ({
  status,
  errorCount: details.length,
  lastError: details[0] ?? null,
  details
});

const formatSourceError = (error: SourceErrorDetail): string => {
  const statusText = error.statusCode !== null ? ` (${error.statusCode})` : "";
  return `${error.endpoint}${statusText}: ${error.message}`;
};

const toRefreshStatus = (
  sourceStatus: IngestionStatusSnapshot["sourceStatus"]
): RefreshHealthStatus => {
  // Only core data sources (defender + graph) determine overall refresh status.
  // MCP Bridge is supplemental — failures are visible in sourceStatus but
  // do not degrade the overall status since local fallbacks are used.
  const coreStatuses = [
    sourceStatus.defender.status,
    sourceStatus.graph.status
  ];

  const hasIssues = coreStatuses.some((status) => status === "degraded" || status === "failed");
  return hasIssues ? "partial" : "success";
};

export class PipelineService {
  private latestSnapshot: UnifiedSnapshot | null = null;
  private refreshInProgress = false;
  private ingestionStatus: IngestionStatusSnapshot = {
    lastRefreshStatus: "never",
    lastRefreshTime: null,
    lastRefreshTrigger: null,
    lastRefreshError: null,
    sourceStatus: {
      defender: EMPTY_SOURCE_STATUS(),
      graph: EMPTY_SOURCE_STATUS(),
      mcpBridge: EMPTY_SOURCE_STATUS()
    }
  };

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

    if (this.latestSnapshot && this.ingestionStatus.lastRefreshStatus === "never") {
      this.ingestionStatus = {
        ...this.ingestionStatus,
        lastRefreshStatus: "success",
        lastRefreshTime: this.latestSnapshot.collectedAt,
        lastRefreshTrigger: "hydrate-from-disk",
        lastRefreshError: null
      };
    }
  }

  public getLatestSnapshot(): UnifiedSnapshot | null {
    return this.latestSnapshot;
  }

  public getIngestionStatus(): IngestionStatusSnapshot {
    return this.ingestionStatus;
  }

  public isRefreshing(): boolean {
    return this.refreshInProgress;
  }

  private buildIngestionStatus(
    trigger: string,
    collectedAt: string,
    defenderRaw: DefenderRawData,
    graphRaw: GraphRawData,
    remediationDiagnostics: RemediationDiagnostics
  ): IngestionStatusSnapshot {
    const defenderDetails = defenderRaw.errors.map((error) => formatSourceError(error));
    const graphDetails = graphRaw.error ? [formatSourceError(graphRaw.error)] : [];
    const mcpDetails = remediationDiagnostics.mcpBridge.errors;

    const defenderStatus: SourceHealthStatus =
      defenderDetails.length === 0
        ? "healthy"
        : defenderDetails.length >= 4
          ? "failed"
          : "degraded";
    const graphStatus: SourceHealthStatus =
      graphDetails.length === 0 ? "healthy" : "failed";
    const mcpStatus = remediationDiagnostics.mcpBridge.status;

    const sourceStatus: IngestionStatusSnapshot["sourceStatus"] = {
      defender: toSourceRuntimeStatus(defenderStatus, defenderDetails),
      graph: toSourceRuntimeStatus(graphStatus, graphDetails),
      mcpBridge: toSourceRuntimeStatus(mcpStatus, mcpDetails)
    };

    const coreDetails = [...defenderDetails, ...graphDetails];

    return {
      lastRefreshStatus: toRefreshStatus(sourceStatus),
      lastRefreshTime: collectedAt,
      lastRefreshTrigger: trigger,
      lastRefreshError: coreDetails[0] ?? null,
      sourceStatus
    };
  }

  public async refresh(trigger: string): Promise<UnifiedSnapshot> {
    if (this.refreshInProgress) {
      logger.warn({ trigger }, "Refresh already in progress; skipping");
      if (this.latestSnapshot) {
        return this.latestSnapshot;
      }
      throw new Error("Refresh already in progress and no previous snapshot available");
    }

    this.refreshInProgress = true;
    metrics.refreshCount.increment();
    const elapsed = startTimer();
    logger.info({ trigger }, "Starting Defender XDR data refresh");

    try {
      const [defenderRaw, graphRaw] = await Promise.all([
        this.defenderClient.collectRawData(),
        this.graphClient.collectRawData()
      ]);

      const normalized = this.normalizeService.normalize(defenderRaw, graphRaw);
      const remediationResult = await this.remediationService.generateRecommendations({
        secureScores: normalized.secureScores,
        vulnerabilityOverview: normalized.vulnerabilityOverview,
        topInitiatives: normalized.topInitiatives,
        programInitiatives: normalized.programInitiatives
      });

      const snapshot: UnifiedSnapshot = {
        collectedAt: new Date().toISOString(),
        ...normalized,
        remediationRecommendations: remediationResult.recommendations,
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
      this.ingestionStatus = this.buildIngestionStatus(
        trigger,
        snapshot.collectedAt,
        defenderRaw,
        graphRaw,
        remediationResult.diagnostics
      );

      logger.info(
        {
          collectedAt: snapshot.collectedAt,
          recommendationCount: snapshot.remediationRecommendations.length,
          refreshStatus: this.ingestionStatus.lastRefreshStatus,
          durationMs: elapsed()
        },
        "Defender XDR data refresh completed"
      );

      metrics.refreshDuration.observe(elapsed());

      return snapshot;
    } catch (error) {
      this.ingestionStatus = {
        ...this.ingestionStatus,
        lastRefreshStatus: "failed",
        lastRefreshTime: new Date().toISOString(),
        lastRefreshTrigger: trigger,
        lastRefreshError: error instanceof Error ? error.message : "Unknown error"
      };

      throw error;
    } finally {
      this.refreshInProgress = false;
      if (this.ingestionStatus.lastRefreshStatus === "failed") {
        metrics.refreshFailures.increment();
      }
    }
  }
}
