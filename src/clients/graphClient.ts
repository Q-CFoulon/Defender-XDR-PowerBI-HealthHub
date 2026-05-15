import axios from "axios";
import type { AppConfig } from "../config/env";
import { logger } from "../config/logger";
import { withRetry } from "../middleware/retry";
import type { GraphRawData, SourceErrorDetail } from "../types/domain";
import { OAuthClient } from "./oauthClient";

const toSourceError = (path: string, error: unknown): SourceErrorDetail => {
  if (axios.isAxiosError(error)) {
    return {
      source: "graph",
      endpoint: "secureScores",
      path,
      statusCode: error.response?.status ?? null,
      message: error.message
    };
  }

  return {
    source: "graph",
    endpoint: "secureScores",
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

export class GraphClient {
  public constructor(
    private readonly config: AppConfig,
    private readonly oauthClient: OAuthClient
  ) {}

  private async callEndpoint(path: string): Promise<unknown> {
    return withRetry(async () => {
      const accessToken = await this.oauthClient.getAccessToken(this.config.graphScope);
      const requestUrl = buildRequestUrl(this.config.graphApiBaseUrl, path);

      const response = await axios.get(requestUrl, {
        headers: {
          Authorization: `Bearer ${accessToken}`
        },
        timeout: 30_000
      });

      return response.data;
    }, `graph:${path}`);
  }

  public async collectRawData(): Promise<GraphRawData> {
    try {
      const secureScores = await this.callEndpoint(this.config.graphSecureScoresPath);
      return { secureScores, error: null };
    } catch (error) {
      const sourceError = toSourceError(this.config.graphSecureScoresPath, error);

      logger.warn(
        {
          path: sourceError.path,
          statusCode: sourceError.statusCode,
          errorMessage: sourceError.message
        },
        "Graph Secure Score call failed; using empty payload"
      );
      return { secureScores: null, error: sourceError };
    }
  }
}
