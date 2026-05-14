import axios from "axios";
import type { AppConfig } from "../config/env";
import { logger } from "../config/logger";
import type { DefenderRawData, SourceErrorDetail } from "../types/domain";
import { OAuthClient } from "./oauthClient";

const toSourceError = (path: string, endpointName: string, error: unknown): SourceErrorDetail => {
  if (axios.isAxiosError(error)) {
    return {
      source: "defender",
      endpoint: endpointName,
      path,
      statusCode: error.response?.status ?? null,
      message: error.message
    };
  }

  return {
    source: "defender",
    endpoint: endpointName,
    path,
    statusCode: null,
    message: error instanceof Error ? error.message : "Unknown error"
  };
};

const buildRequestUrl = (baseUrl: string, endpointPath: string): string => {
  const normalizedBase = baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`;
  const normalizedPath = endpointPath.replace(/^\/+/, "");
  return new URL(normalizedPath, normalizedBase).toString();
};

export class DefenderClient {
  public constructor(
    private readonly config: AppConfig,
    private readonly oauthClient: OAuthClient
  ) {}

  private async callEndpoint(path: string): Promise<unknown> {
    const accessToken = await this.oauthClient.getAccessToken(this.config.defenderScope);
    const requestUrl = buildRequestUrl(this.config.defenderApiBaseUrl, path);

    const response = await axios.get(requestUrl, {
      headers: {
        Authorization: `Bearer ${accessToken}`
      },
      timeout: 30_000
    });

    return response.data;
  }

  private async safeCall(path: string, endpointName: string, errors: SourceErrorDetail[]): Promise<unknown> {
    try {
      return await this.callEndpoint(path);
    } catch (error) {
      const sourceError = toSourceError(path, endpointName, error);
      errors.push(sourceError);

      logger.warn(
        {
          endpointName,
          path,
          statusCode: sourceError.statusCode,
          errorMessage: sourceError.message
        },
        "Defender API call failed; keeping pipeline alive with empty data"
      );
      return null;
    }
  }

  public async collectRawData(): Promise<DefenderRawData> {
    const errors: SourceErrorDetail[] = [];

    const [initiatives, topInitiatives, vulnerabilityOverview, cloudSecureScore] = await Promise.all([
      this.safeCall(this.config.defenderInitiativesPath, "initiatives", errors),
      this.safeCall(this.config.defenderTopInitiativesPath, "topInitiatives", errors),
      this.safeCall(this.config.defenderVulnerabilityOverviewPath, "vulnerabilityOverview", errors),
      this.safeCall(this.config.defenderCloudScorePath, "cloudSecureScore", errors)
    ]);

    return {
      initiatives,
      topInitiatives,
      vulnerabilityOverview,
      cloudSecureScore,
      errors
    };
  }
}
