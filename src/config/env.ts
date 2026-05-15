import path from "path";
import dotenv from "dotenv";

const appBaseDirectoryFromEnv = process.env.APP_BASE_DIR;
const appBaseDirectory =
  appBaseDirectoryFromEnv && appBaseDirectoryFromEnv.trim().length > 0
    ? path.resolve(appBaseDirectoryFromEnv)
    : path.resolve(__dirname, "..", "..");

dotenv.config({
  path: path.join(appBaseDirectory, ".env.local")
});

dotenv.config({
  path: path.join(appBaseDirectory, ".env")
});

const requiredEnv = (name: string): string => {
  const value = process.env[name];
  if (!value || value.trim().length === 0) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
};

const optionalEnv = (name: string, fallback: string): string => {
  const value = process.env[name];
  if (!value || value.trim().length === 0) {
    return fallback;
  }
  return value;
};

const toNumber = (value: string, fallback: number): number => {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
};

export interface AppConfig {
  appPort: number;
  nodeEnv: string;
  refreshCron: string;
  adminApiKey: string;
  corsAllowedOrigins: string;
  tenantId: string;
  clientId: string;
  clientSecret: string;
  defenderApiBaseUrl: string;
  defenderScope: string;
  defenderInitiativesPath: string;
  defenderTopInitiativesPath: string;
  defenderVulnerabilityOverviewPath: string;
  defenderCloudScorePath: string;
  graphApiBaseUrl: string;
  graphScope: string;
  graphSecureScoresPath: string;
  mcpBridgeUrl: string;
  mcpBridgeApiKey: string;
  powerBiPushDatasetUrl: string;
  powerBiPushBearerToken: string;
  dataDirectory: string;
}

export const config: AppConfig = {
  appPort: toNumber(optionalEnv("APP_PORT", "4010"), 4010),
  nodeEnv: optionalEnv("NODE_ENV", "development"),
  refreshCron: optionalEnv("REFRESH_CRON", "0 */30 * * * *"),
  adminApiKey: optionalEnv("ADMIN_API_KEY", ""),
  corsAllowedOrigins: optionalEnv("CORS_ALLOWED_ORIGINS", ""),
  tenantId: requiredEnv("TENANT_ID"),
  clientId: requiredEnv("CLIENT_ID"),
  clientSecret: requiredEnv("CLIENT_SECRET"),
  defenderApiBaseUrl: optionalEnv("DEFENDER_API_BASE_URL", "https://api.security.microsoft.com"),
  defenderScope: optionalEnv("DEFENDER_SCOPE", "https://api.security.microsoft.com/.default"),
  defenderInitiativesPath: optionalEnv("DEFENDER_INITIATIVES_PATH", "/api/recommendations"),
  defenderTopInitiativesPath: optionalEnv("DEFENDER_TOP_INITIATIVES_PATH", "/api/vulnerabilities?$top=10"),
  defenderVulnerabilityOverviewPath: optionalEnv("DEFENDER_VULNERABILITY_OVERVIEW_PATH", "/api/exposureScore"),
  defenderCloudScorePath: optionalEnv("DEFENDER_CLOUD_SCORE_PATH", "/api/configurationScore"),
  graphApiBaseUrl: optionalEnv("GRAPH_API_BASE_URL", "https://graph.microsoft.com/v1.0"),
  graphScope: optionalEnv("GRAPH_SCOPE", "https://graph.microsoft.com/.default"),
  graphSecureScoresPath: optionalEnv("GRAPH_SECURE_SCORES_PATH", "/security/secureScores?$top=1"),
  mcpBridgeUrl: optionalEnv("MCP_BRIDGE_URL", ""),
  mcpBridgeApiKey: optionalEnv("MCP_BRIDGE_API_KEY", ""),
  powerBiPushDatasetUrl: optionalEnv("POWERBI_PUSH_DATASET_URL", ""),
  powerBiPushBearerToken: optionalEnv("POWERBI_PUSH_BEARER_TOKEN", ""),
  dataDirectory: path.resolve(optionalEnv("DATA_DIRECTORY", path.join(appBaseDirectory, "data")))
};
