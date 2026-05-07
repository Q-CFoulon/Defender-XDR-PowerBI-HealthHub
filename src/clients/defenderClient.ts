import axios from "axios";
import type { AppConfig } from "../config/env";
import { logger } from "../config/logger";
import type { DefenderRawData } from "../types/domain";
import { OAuthClient } from "./oauthClient";

export class DefenderClient {
  public constructor(
    private readonly config: AppConfig,
    private readonly oauthClient: OAuthClient
  ) {}

  private async callEndpoint(path: string): Promise<unknown> {
    const accessToken = await this.oauthClient.getAccessToken(this.config.defenderScope);
    const requestUrl = new URL(path, this.config.defenderApiBaseUrl).toString();

    const response = await axios.get(requestUrl, {
      headers: {
        Authorization: `Bearer ${accessToken}`
      },
      timeout: 30_000
    });

    return response.data;
  }

  private async safeCall(path: string, endpointName: string): Promise<unknown> {
    try {
      return await this.callEndpoint(path);
    } catch (error) {
      logger.warn(
        {
          endpointName,
          path,
          errorMessage: error instanceof Error ? error.message : "Unknown error"
        },
        "Defender API call failed; keeping pipeline alive with empty data"
      );
      return null;
    }
  }

  public async collectRawData(): Promise<DefenderRawData> {
    const [initiatives, topInitiatives, vulnerabilityOverview, cloudSecureScore] = await Promise.all([
      this.safeCall(this.config.defenderInitiativesPath, "initiatives"),
      this.safeCall(this.config.defenderTopInitiativesPath, "topInitiatives"),
      this.safeCall(this.config.defenderVulnerabilityOverviewPath, "vulnerabilityOverview"),
      this.safeCall(this.config.defenderCloudScorePath, "cloudSecureScore")
    ]);

    return {
      initiatives,
      topInitiatives,
      vulnerabilityOverview,
      cloudSecureScore
    };
  }
}
