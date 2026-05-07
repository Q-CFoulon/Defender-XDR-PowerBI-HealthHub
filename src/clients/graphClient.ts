import axios from "axios";
import type { AppConfig } from "../config/env";
import { logger } from "../config/logger";
import type { GraphRawData } from "../types/domain";
import { OAuthClient } from "./oauthClient";

export class GraphClient {
  public constructor(
    private readonly config: AppConfig,
    private readonly oauthClient: OAuthClient
  ) {}

  private async callEndpoint(path: string): Promise<unknown> {
    const accessToken = await this.oauthClient.getAccessToken(this.config.graphScope);
    const requestUrl = new URL(path, this.config.graphApiBaseUrl).toString();

    const response = await axios.get(requestUrl, {
      headers: {
        Authorization: `Bearer ${accessToken}`
      },
      timeout: 30_000
    });

    return response.data;
  }

  public async collectRawData(): Promise<GraphRawData> {
    try {
      const secureScores = await this.callEndpoint(this.config.graphSecureScoresPath);
      return { secureScores };
    } catch (error) {
      logger.warn(
        {
          errorMessage: error instanceof Error ? error.message : "Unknown error"
        },
        "Graph Secure Score call failed; using empty payload"
      );
      return { secureScores: null };
    }
  }
}
