import axios from "axios";
import type { AppConfig } from "../config/env";
import { logger } from "../config/logger";

export interface McpBridgeRequest {
  server: string;
  capability: string;
  query: string;
  context: Record<string, unknown>;
}

export interface McpRecommendationCandidate {
  title: string;
  description: string;
  priority?: string;
  relatedRiskArea?: string;
  link?: string;
  snippet?: string;
}

const asRecord = (value: unknown): Record<string, unknown> | null => {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
};

const pickRecommendations = (payload: unknown): unknown[] => {
  if (Array.isArray(payload)) {
    return payload;
  }

  const record = asRecord(payload);
  if (!record) {
    return [];
  }

  const keys = ["recommendations", "items", "data", "result", "results"];
  for (const key of keys) {
    if (Array.isArray(record[key])) {
      return record[key] as unknown[];
    }
  }

  return [];
};

const toCandidate = (value: unknown): McpRecommendationCandidate | null => {
  const record = asRecord(value);
  if (!record) {
    return null;
  }

  const title = typeof record.title === "string" ? record.title : undefined;
  const description = typeof record.description === "string" ? record.description : undefined;

  if (!title || !description) {
    return null;
  }

  return {
    title,
    description,
    priority: typeof record.priority === "string" ? record.priority : undefined,
    relatedRiskArea: typeof record.relatedRiskArea === "string" ? record.relatedRiskArea : undefined,
    link: typeof record.link === "string" ? record.link : undefined,
    snippet: typeof record.snippet === "string" ? record.snippet : undefined
  };
};

export class McpBridgeClient {
  public constructor(private readonly config: AppConfig) {}

  public isConfigured(): boolean {
    return this.config.mcpBridgeUrl.trim().length > 0;
  }

  public async requestRecommendations(request: McpBridgeRequest): Promise<McpRecommendationCandidate[]> {
    if (!this.isConfigured()) {
      return [];
    }

    const endpoint = new URL("/invoke", this.config.mcpBridgeUrl).toString();
    const headers: Record<string, string> = {
      "Content-Type": "application/json"
    };

    if (this.config.mcpBridgeApiKey.trim().length > 0) {
      headers.Authorization = `Bearer ${this.config.mcpBridgeApiKey}`;
    }

    try {
      const response = await axios.post(
        endpoint,
        {
          server: request.server,
          capability: request.capability,
          query: request.query,
          context: request.context
        },
        {
          headers,
          timeout: 45_000
        }
      );

      return pickRecommendations(response.data)
        .map((item) => toCandidate(item))
        .filter((item): item is McpRecommendationCandidate => item !== null);
    } catch (error) {
      logger.warn(
        {
          server: request.server,
          capability: request.capability,
          error
        },
        "MCP bridge call failed; skipping provider"
      );
      return [];
    }
  }
}
