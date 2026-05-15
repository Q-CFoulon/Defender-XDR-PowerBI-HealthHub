import type { LocalMcpProvider } from "./provider.interface";
import { MicrosoftLearnProvider } from "./microsoftLearn.provider";
import { AzureProvider } from "./azure.provider";
import { SentinelProvider } from "./sentinel.provider";
import { SecurityCopilotProvider } from "./securityCopilot.provider";
import { FabricProvider } from "./fabric.provider";
import { DefenderResponseProvider } from "./defenderResponse.provider";

export type { LocalMcpProvider, LocalRecommendation, ProviderSignalContext } from "./provider.interface";

const ALL_PROVIDERS: LocalMcpProvider[] = [
  new MicrosoftLearnProvider(),
  new AzureProvider(),
  new SentinelProvider(),
  new SecurityCopilotProvider(),
  new FabricProvider(),
  new DefenderResponseProvider()
];

const PROVIDER_MAP = new Map<string, LocalMcpProvider>(
  ALL_PROVIDERS.map((p) => [p.serverName, p])
);

export const getLocalProvider = (serverName: string): LocalMcpProvider | undefined =>
  PROVIDER_MAP.get(serverName);

export const getAllLocalProviders = (): readonly LocalMcpProvider[] => ALL_PROVIDERS;
