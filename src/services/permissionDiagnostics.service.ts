import type {
  IngestionStatusSnapshot,
  SourceErrorDetail
} from "../types/domain";

/**
 * Maps each Defender/Graph endpoint to the API permission required.
 * Used by the diagnostics service to tell operators exactly which
 * grants are missing when a 403 is returned.
 */

interface PermissionMapping {
  source: "defender" | "graph";
  endpoint: string;
  pathPattern: string;
  api: string;
  permission: string;
  description: string;
  docUrl: string;
}

const PERMISSION_MAP: PermissionMapping[] = [
  {
    source: "defender",
    endpoint: "vulnerabilityOverview",
    pathPattern: "/api/exposureScore",
    api: "WindowsDefenderATP",
    permission: "Score.Read.All",
    description: "Read Threat and Vulnerability Management score",
    docUrl: "https://learn.microsoft.com/defender-endpoint/api/get-exposure-score"
  },
  {
    source: "defender",
    endpoint: "cloudSecureScore",
    pathPattern: "/api/configurationScore",
    api: "WindowsDefenderATP",
    permission: "Score.Read.All",
    description: "Read device secure score (configuration score)",
    docUrl: "https://learn.microsoft.com/defender-endpoint/api/get-device-secure-score"
  },
  {
    source: "defender",
    endpoint: "initiatives",
    pathPattern: "/api/recommendations",
    api: "WindowsDefenderATP",
    permission: "SecurityRecommendation.Read.All",
    description: "Read security recommendations",
    docUrl: "https://learn.microsoft.com/defender-endpoint/api/get-all-recommendations"
  },
  {
    source: "defender",
    endpoint: "topInitiatives",
    pathPattern: "/api/vulnerabilities",
    api: "WindowsDefenderATP",
    permission: "Vulnerability.Read.All",
    description: "Read vulnerability information",
    docUrl: "https://learn.microsoft.com/defender-endpoint/api/get-all-vulnerabilities"
  },
  {
    source: "graph",
    endpoint: "secureScores",
    pathPattern: "/security/secureScores",
    api: "Microsoft Graph",
    permission: "SecurityEvents.Read.All",
    description: "Read secure score data via Graph Security API",
    docUrl: "https://learn.microsoft.com/graph/api/securescore-get"
  }
];

export interface PermissionDiagnostic {
  endpoint: string;
  path: string;
  statusCode: number | null;
  errorMessage: string;
  likelyMissingPermission: {
    api: string;
    permission: string;
    description: string;
    docUrl: string;
  };
  fix: string;
}

export interface PermissionDiagnosticsReport {
  timestamp: string;
  healthy: boolean;
  summary: string;
  missingGrants: PermissionDiagnostic[];
  otherErrors: Array<{
    source: string;
    endpoint: string;
    path: string;
    statusCode: number | null;
    message: string;
  }>;
  allRequiredPermissions: Array<{
    api: string;
    permission: string;
    description: string;
    status: "ok" | "likely-missing" | "unknown";
  }>;
}

const findMapping = (error: SourceErrorDetail): PermissionMapping | undefined => {
  return PERMISSION_MAP.find(
    (m) =>
      m.source === error.source &&
      (m.endpoint === error.endpoint || error.path.includes(m.pathPattern))
  );
};

const is403 = (error: SourceErrorDetail): boolean => error.statusCode === 403;

export const analyzePermissions = (
  ingestionStatus: IngestionStatusSnapshot
): PermissionDiagnosticsReport => {
  const allErrors: SourceErrorDetail[] = [];

  // Collect errors from each source
  const { defender, graph } = ingestionStatus.sourceStatus;

  for (const detail of defender.details) {
    const parsed = parseDetailString(detail, "defender");
    if (parsed) allErrors.push(parsed);
  }

  for (const detail of graph.details) {
    const parsed = parseDetailString(detail, "graph");
    if (parsed) allErrors.push(parsed);
  }

  const missingGrants: PermissionDiagnostic[] = [];
  const otherErrors: PermissionDiagnosticsReport["otherErrors"] = [];

  for (const error of allErrors) {
    const mapping = findMapping(error);

    if (is403(error) && mapping) {
      // Deduplicate by permission (Score.Read.All covers two endpoints)
      const alreadyListed = missingGrants.some(
        (g) =>
          g.likelyMissingPermission.api === mapping.api &&
          g.likelyMissingPermission.permission === mapping.permission
      );
      if (!alreadyListed) {
        missingGrants.push({
          endpoint: error.endpoint,
          path: error.path,
          statusCode: error.statusCode,
          errorMessage: error.message,
          likelyMissingPermission: {
            api: mapping.api,
            permission: mapping.permission,
            description: mapping.description,
            docUrl: mapping.docUrl
          },
          fix: `Grant '${mapping.permission}' (Application) on '${mapping.api}' and click 'Grant admin consent' in Entra ID > App registrations > API permissions.`
        });
      }
    } else if (is403(error)) {
      // 403 but no mapping — generic permission issue
      missingGrants.push({
        endpoint: error.endpoint,
        path: error.path,
        statusCode: 403,
        errorMessage: error.message,
        likelyMissingPermission: {
          api: error.source === "defender" ? "WindowsDefenderATP" : "Microsoft Graph",
          permission: "Unknown — check API docs",
          description: "Unrecognized endpoint; verify required permissions in documentation",
          docUrl:
            error.source === "defender"
              ? "https://learn.microsoft.com/defender-endpoint/api/exposed-apis-list"
              : "https://learn.microsoft.com/graph/permissions-reference"
        },
        fix: "Check the API documentation for the required application permission, add it to the app registration, and grant admin consent."
      });
    } else {
      otherErrors.push({
        source: error.source,
        endpoint: error.endpoint,
        path: error.path,
        statusCode: error.statusCode,
        message: error.message
      });
    }
  }

  // Build full permission status matrix
  const missingPermKeys = new Set(
    missingGrants.map(
      (g) => `${g.likelyMissingPermission.api}:${g.likelyMissingPermission.permission}`
    )
  );

  const allRequiredPermissions = dedupePermissions(PERMISSION_MAP).map((m) => {
    const key = `${m.api}:${m.permission}`;
    const hasError = allErrors.some((e) => {
      const mapping = findMapping(e);
      return mapping && `${mapping.api}:${mapping.permission}` === key;
    });

    let status: "ok" | "likely-missing" | "unknown";
    if (missingPermKeys.has(key)) {
      status = "likely-missing";
    } else if (!hasError && ingestionStatus.lastRefreshStatus !== "never") {
      status = "ok";
    } else {
      status = "unknown";
    }

    return {
      api: m.api,
      permission: m.permission,
      description: m.description,
      status
    };
  });

  const healthy = missingGrants.length === 0 && otherErrors.length === 0;

  let summary: string;
  if (ingestionStatus.lastRefreshStatus === "never") {
    summary = "No refresh has run yet. Trigger a refresh to diagnose permission issues.";
  } else if (healthy) {
    summary = "All API endpoints responded successfully. No missing permissions detected.";
  } else if (missingGrants.length > 0 && otherErrors.length === 0) {
    const perms = missingGrants
      .map((g) => `${g.likelyMissingPermission.api} → ${g.likelyMissingPermission.permission}`)
      .join(", ");
    summary = `${missingGrants.length} permission grant(s) likely missing: ${perms}. Grant admin consent in Entra ID.`;
  } else {
    summary = `${missingGrants.length} permission issue(s) and ${otherErrors.length} other error(s) detected. See details below.`;
  }

  return {
    timestamp: new Date().toISOString(),
    healthy,
    summary,
    missingGrants,
    otherErrors,
    allRequiredPermissions
  };
};

/**
 * Parse the formatted error detail string back into a SourceErrorDetail.
 * Format: "endpointName (statusCode): message" or "endpointName: message"
 */
function parseDetailString(
  detail: string,
  source: "defender" | "graph"
): SourceErrorDetail | null {
  const match = detail.match(/^(\S+?)(?:\s*\((\d+)\))?\s*:\s*(.+)$/);
  if (!match) return null;

  return {
    source,
    endpoint: match[1],
    path: match[1],
    statusCode: match[2] ? parseInt(match[2], 10) : null,
    message: match[3]
  };
}

function dedupePermissions(
  mappings: PermissionMapping[]
): Array<{ api: string; permission: string; description: string }> {
  const seen = new Set<string>();
  const result: Array<{ api: string; permission: string; description: string }> = [];
  for (const m of mappings) {
    const key = `${m.api}:${m.permission}`;
    if (!seen.has(key)) {
      seen.add(key);
      result.push({ api: m.api, permission: m.permission, description: m.description });
    }
  }
  return result;
}
