import axios from "axios";
import type { AppConfig } from "../config/env";

interface CachedToken {
  accessToken: string;
  expiresAt: number;
}

export class OAuthClient {
  private readonly tokenCache = new Map<string, CachedToken>();

  public constructor(private readonly config: AppConfig) {}

  public async getAccessToken(scope: string): Promise<string> {
    const cached = this.tokenCache.get(scope);
    if (cached && Date.now() < cached.expiresAt - 60_000) {
      return cached.accessToken;
    }

    const tokenUrl = `https://login.microsoftonline.com/${this.config.tenantId}/oauth2/v2.0/token`;
    const body = new URLSearchParams({
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      scope,
      grant_type: "client_credentials"
    });

    let accessToken: string | undefined;
    let expiresIn = 3600;

    try {
      const response = await axios.post(tokenUrl, body.toString(), {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        timeout: 20_000
      });

      accessToken = response.data?.access_token as string | undefined;
      const expiresInRaw = response.data?.expires_in as number | string | undefined;
      expiresIn = Number(expiresInRaw ?? 3600);
    } catch (error) {
      if (axios.isAxiosError(error)) {
        const status = error.response?.status;
        throw new Error(
          `OAuth token acquisition failed for scope ${scope}${
            status ? ` (status ${status})` : ""
          }`
        );
      }
      throw new Error(`OAuth token acquisition failed for scope ${scope}`);
    }

    if (!accessToken) {
      throw new Error(`OAuth token acquisition failed for scope ${scope}`);
    }

    this.tokenCache.set(scope, {
      accessToken,
      expiresAt: Date.now() + expiresIn * 1_000
    });

    return accessToken;
  }
}
