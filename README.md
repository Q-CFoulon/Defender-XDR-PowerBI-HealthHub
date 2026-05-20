# Defender XDR Power BI Health Hub

Standalone service that centralizes Microsoft Defender XDR Vulnerability Management, Microsoft Secure Score, and Cloud Secure Score data into a Power BI-ready API and export pipeline.

## Application Purpose

This repository exists to give customers a single IT security health dashboard source that:

- Collects exposure and vulnerability-related metrics from Microsoft Defender APIs.
- Collects M365 Secure Score data from Microsoft Graph.
- Normalizes all upstream payloads to a stable reporting contract.
- Enriches each refresh with remediation recommendations from MCP-backed sources:
  - Microsoft Learn MCP
  - Azure MCP
  - Microsoft Sentinel
  - Microsoft Security Copilot snippets
  - Fabric MCP
  - Defender Response MCP
- Publishes data for Power BI import/refresh and optional push-dataset integration.

## Core Functions

1. Authentication and token lifecycle management using Entra app credentials.
2. Scheduled ingestion (cron) and manual on-demand refresh.
3. Data normalization across different API payload shapes.
4. Recommendation enrichment from MCP bridge providers.
5. Snapshot persistence and JSON table exports.
6. REST endpoints for Power BI and monitoring.

## Repository Layout

- src/clients: OAuth, Defender API, and Graph API clients
- src/services: Normalization, pipeline orchestration, snapshot store, Power BI export
- src/remediation: MCP bridge client and recommendation aggregator
- src/routes: Health and Power BI endpoints
- scripts: PowerShell automation for Windows service and Entra enterprise app registration
- powerbi: Power Query starter script
- data: Generated snapshots and exported JSON tables

## Required Permissions

The service uses application permissions (client credentials flow). Grant only what you need.

### Microsoft Graph (Secure Score)

- API: Microsoft Graph
- Permission type: Application
- Required permission: SecurityEvents.Read.All
- Why: Reads secure score data via Graph Security API

Reference: [Get secureScore (Microsoft Graph)](https://learn.microsoft.com/graph/api/securescore-get)

### Microsoft Defender for Endpoint and Defender XDR APIs

The service calls these Defender for Endpoint REST APIs on `https://api.security.microsoft.com`:

| Endpoint | Path | Permission |
| --- | --- | --- |
| Exposure Score | `GET /api/exposureScore` | Score.Read.All |
| Device Secure Score | `GET /api/configurationScore` | Score.Read.All |
| Security Recommendations | `GET /api/recommendations` | SecurityRecommendation.Read.All |
| Vulnerabilities | `GET /api/vulnerabilities` | Vulnerability.Read.All |

Required application permissions on the **WindowsDefenderATP** resource:

- **Score.Read.All** — Read Threat and Vulnerability Management score (exposure score and device secure score)
- **Vulnerability.Read.All** — Read Threat and Vulnerability Management vulnerability information
- **SecurityRecommendation.Read.All** — Read Threat and Vulnerability Management security recommendation information
- **Machine.ReadWrite.All** — Read and write all machine information (used by MCP remediation bridge when active)

Reference examples:

- [Exposure Score API](https://learn.microsoft.com/defender-endpoint/api/get-exposure-score)
- [Device Secure Score API](https://learn.microsoft.com/defender-endpoint/api/get-device-secure-score)
- [Recommendations API](https://learn.microsoft.com/defender-endpoint/api/get-all-recommendations)
- [Vulnerabilities API](https://learn.microsoft.com/defender-endpoint/api/get-all-vulnerabilities)
- [Supported API list](https://learn.microsoft.com/defender-endpoint/api/exposed-apis-list)
- [Defender XDR API access model](https://learn.microsoft.com/defender-xdr/api-access)

Important:

- These APIs require Microsoft Defender for Endpoint Plan 1 or Plan 2 licensing.
- Validate final least-privilege permissions in a pre-production tenant before production rollout.

### Optional Power BI Push Dataset Permissions

Required only if POWERBI_PUSH_DATASET_URL is used:

- Service principal allowed for Power BI APIs in tenant settings.
- Workspace role for the service principal (typically Member or Contributor).
- API token/scopes capable of adding rows to the target push dataset.

### Role Needed to Grant Consent

In most customer tenants, one of the following roles is needed to grant admin consent:

- Global Administrator
- Privileged Role Administrator
- Cloud Application Administrator (depending on policy)

### Permissions Needed to Run Registration Script

The registration script uses Microsoft Graph PowerShell and requests delegated scopes:

- Application.ReadWrite.All
- AppRoleAssignment.ReadWrite.All
- Directory.Read.All

Run it with a tenant admin account that can create app registrations and grant app role assignments.

## Customer Deployment Guide

### 1) Prepare the customer tenant

Fastest end-to-end option (enterprise app registration + Windows service install):

```powershell
npm run deploy:client
```

Equivalent script with flags:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Deploy-HealthHubClient.ps1 -AppDisplayName "CustomerA Defender Health Hub" -ForceServiceReinstall
```

Option A (recommended): automate app registration and enterprise application creation.

```powershell
npm run entra:register
```

Optional parameters:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Register-HealthHubEnterpriseApp.ps1 -DisplayName "CustomerA Defender Health Hub" -SecretValidityMonths 18 -OutputEnvFilePath .\customer-a.env
```

Option B: create the app registration manually.

1. Register an Entra application.
2. Create a client secret or certificate.
3. Add required API permissions listed above.
4. Grant admin consent.
5. Record:
   - Tenant ID
   - Client ID
   - Client secret (or certificate settings if you extend auth)

### 2) Prepare host environment

Minimum host requirements:

- Node.js 18.18+
- Outbound HTTPS access to:
  - login.microsoftonline.com
  - graph.microsoft.com
  - api.security.microsoft.com
  - MCP bridge endpoint (if used)
  - Power BI endpoint (if push dataset is used)

### 3) Configure application

1. Copy environment file:

```powershell
Copy-Item .env.example .env.local
```

For scripts that default to `.env` (for example Windows service install), either copy `.env.local` to `.env` on that machine only, or pass an explicit environment file path to the script.

1. Set at minimum:

- TENANT_ID
- CLIENT_ID
- CLIENT_SECRET

Service-related optional variables:

- APP_BASE_DIR (auto-set by service wrapper)
- DATA_DIRECTORY (auto-set by service wrapper)

1. Configure optional integrations as needed:

- MCP_BRIDGE_URL and MCP_BRIDGE_API_KEY (leave MCP_BRIDGE_URL empty to disable bridge calls)
- POWERBI_PUSH_DATASET_URL and POWERBI_PUSH_BEARER_TOKEN

### 4) Install and validate

```powershell
npm install
npm run type-check
npm run build
npm run refresh:once
```

Expected result: a new snapshot is generated in data/ and refresh completes without fatal errors.

### 5) Run in customer environment

Development mode:

```powershell
npm run dev
```

The dashboard is available at `http://localhost:4010/dashboard` (the root URL redirects here automatically).

Production mode:

```powershell
npm run build
npm start
```

Recommended production hosting options:

- Windows Server as native Windows Service via provided PowerShell installer
- Linux VM with systemd
- Container platform (Docker host, AKS, ACA) using Dockerfile and docker-compose.yml

Windows service install (elevated PowerShell):

```powershell
npm run service:install
```

Advanced install example:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Install-HealthHubWindowsService.ps1 -EnvironmentFilePath .\.env -InstallPath "C:\ProgramData\Defender-XDR-PowerBI-HealthHub" -ForceReinstall
```

Windows service uninstall:

```powershell
npm run service:uninstall
```

Skip enterprise app registration and only reinstall service with existing .env:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Deploy-HealthHubClient.ps1 -SkipEnterpriseAppRegistration -ForceServiceReinstall
```

What the service installer configures for resilience:

- WinSW service wrapper with automatic restart on failure
- Delayed auto-start on server boot
- Rolling service logs in install_path\\logs
- Health probe validation against /api/health after installation

Container deployment example:

```powershell
docker compose up -d --build
docker compose ps
```

Stop container deployment:

```powershell
docker compose down
```

### 6) Connect Power BI

Use powerbi/power-query-sample.m and map tables:

- ProgramInitiatives
- TopInitiatives
- SecureScores
- VulnerabilityOverview
- RemediationRecommendations

Primary API base URL: `http://your-server-or-ip:4010/api/powerbi`

## API Endpoints

Power BI endpoints:

- GET /api/powerbi/ingestion-status
- GET /api/powerbi/overview
- GET /api/powerbi/program-initiatives
- GET /api/powerbi/top-initiatives
- GET /api/powerbi/secure-scores
- GET /api/powerbi/vulnerability-overview
- GET /api/powerbi/remediation-recommendations
- GET /api/powerbi/full-snapshot

Operational endpoints:

- GET / — Redirects to /dashboard
- GET /dashboard — Full dashboard (browser UI, admin auth)
- GET /admin — Admin dashboard (browser UI, admin auth)
- GET /api/health
- GET /api/metrics — Observability metrics (admin auth)
- GET /api/diagnostics/permissions — Permission grant diagnostics (admin auth)
- POST /api/admin/refresh

## Known Issues / Pending Actions

| Issue | Status | Action Required |
| --- | --- | --- |
| Defender API returns 403 on all 4 endpoints | **Pending** | A Global Admin or Privileged Role Administrator must grant admin consent for the WindowsDefenderATP permissions (`Score.Read.All`, `SecurityRecommendation.Read.All`, `Vulnerability.Read.All`, `Machine.ReadWrite.All`). Run `.\scripts\Grant-DefenderPermissions.ps1 -ClientId "aea214c1-aef3-4d9b-b6a5-cf6b157cb089"` or grant consent via Azure Portal (Entra ID > App registrations > API permissions > Grant admin consent). See the **403 troubleshooting** section below for full diagnosis steps. |
| MCP Bridge disabled | **By design** | `MCP_BRIDGE_URL` is empty. Set it to a running MCP bridge endpoint when available. Fallback recommendations are generated automatically. |

## Troubleshooting Runbook

## Symptom: OAuth token errors (400 or 401)

Checks:

1. Verify TENANT_ID, CLIENT_ID, CLIENT_SECRET values.
2. Confirm client secret is not expired.
3. Confirm API permissions are granted and admin consented.
4. Confirm token scope values in .env are correct.

## Symptom: 403 or 404 from Defender or Graph APIs

This is the most common deployment issue. A **403** means the app registration can obtain a token, but one or more API permissions have not been admin-consented.

### Self-service diagnostics endpoint

The service includes a built-in permission diagnostics endpoint that inspects the latest refresh errors and maps each 403 to the exact missing permission:

```text
GET /api/diagnostics/permissions
```

(Requires admin API key when `ADMIN_API_KEY` is set.)

Sample output when grants are missing:

```json
{
  "healthy": false,
  "summary": "3 permission grant(s) likely missing: WindowsDefenderATP → Score.Read.All, WindowsDefenderATP → SecurityRecommendation.Read.All, Microsoft Graph → SecurityEvents.Read.All. Grant admin consent in Entra ID.",
  "missingGrants": [
    {
      "endpoint": "vulnerabilityOverview",
      "statusCode": 403,
      "likelyMissingPermission": {
        "api": "WindowsDefenderATP",
        "permission": "Score.Read.All"
      },
      "fix": "Grant 'Score.Read.All' (Application) on 'WindowsDefenderATP' and click 'Grant admin consent' in Entra ID > App registrations > API permissions."
    }
  ],
  "allRequiredPermissions": [
    { "api": "WindowsDefenderATP", "permission": "Score.Read.All", "status": "likely-missing" },
    { "api": "WindowsDefenderATP", "permission": "SecurityRecommendation.Read.All", "status": "ok" },
    { "api": "WindowsDefenderATP", "permission": "Vulnerability.Read.All", "status": "ok" },
    { "api": "Microsoft Graph", "permission": "SecurityEvents.Read.All", "status": "ok" }
  ]
}
```

### Full permission matrix

| API | Permission | Endpoints | Type |
| --- | --- | --- | --- |
| WindowsDefenderATP | Score.Read.All | /api/exposureScore, /api/configurationScore | Application |
| WindowsDefenderATP | SecurityRecommendation.Read.All | /api/recommendations | Application |
| WindowsDefenderATP | Vulnerability.Read.All | /api/vulnerabilities | Application |
| WindowsDefenderATP | Machine.ReadWrite.All | MCP remediation bridge (optional) | Application |
| Microsoft Graph | SecurityEvents.Read.All | /security/secureScores | Application |

All permissions require **admin consent** from a Global Administrator, Privileged Role Administrator, or Cloud Application Administrator.

### Quick diagnosis

Run this on any machine with Node.js to decode the token and check granted roles:

```powershell
node -e "
const axios = require('axios');
require('dotenv').config({ path: '.env.local' });
(async () => {
  const r = await axios.post(
    'https://login.microsoftonline.com/' + process.env.TENANT_ID + '/oauth2/v2.0/token',
    new URLSearchParams({ client_id: process.env.CLIENT_ID, client_secret: process.env.CLIENT_SECRET, scope: 'https://api.security.microsoft.com/.default', grant_type: 'client_credentials' }).toString(),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }}
  );
  const payload = JSON.parse(Buffer.from(r.data.access_token.split('.')[1], 'base64url').toString());
  console.log('Audience:', payload.aud);
  console.log('Roles:', payload.roles || '** NONE — admin consent missing **');
})();
"
```

Expected healthy output:

```text
Audience: https://api.security.microsoft.com
Roles: [ 'Score.Read.All', 'Vulnerability.Read.All', 'SecurityRecommendation.Read.All', 'Machine.ReadWrite.All' ]
```

For Graph permissions, change the scope to `https://graph.microsoft.com/.default` and check for `SecurityEvents.Read.All`:

```powershell
node -e "
const axios = require('axios');
require('dotenv').config({ path: '.env.local' });
(async () => {
  const r = await axios.post(
    'https://login.microsoftonline.com/' + process.env.TENANT_ID + '/oauth2/v2.0/token',
    new URLSearchParams({ client_id: process.env.CLIENT_ID, client_secret: process.env.CLIENT_SECRET, scope: 'https://graph.microsoft.com/.default', grant_type: 'client_credentials' }).toString(),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }}
  );
  const payload = JSON.parse(Buffer.from(r.data.access_token.split('.')[1], 'base64url').toString());
  console.log('Audience:', payload.aud);
  console.log('Roles:', payload.roles || '** NONE — admin consent missing **');
})();
"
```

Expected healthy output:

```text
Audience: https://graph.microsoft.com
Roles: [ 'SecurityEvents.Read.All' ]
```

If `Roles` shows `undefined` or is missing permissions, admin consent is needed.

### Fix: Grant admin consent for Defender permissions

Option A — Use the included script (recommended):

```powershell
.\scripts\Grant-DefenderPermissions.ps1 -ClientId "your-client-id-here"
```

Option B — Grant consent via Azure Portal:

1. Go to **Entra ID → App registrations → your app → API permissions**.
2. Confirm these WindowsDefenderATP permissions are listed:
   - `Score.Read.All`
   - `SecurityRecommendation.Read.All`
   - `Vulnerability.Read.All`
   - `Machine.ReadWrite.All`
3. Confirm this Microsoft Graph permission is listed:
   - `SecurityEvents.Read.All`
4. Click **Grant admin consent for [tenant]**.
5. Wait 1–2 minutes for propagation.

Option C — Re-run the full registration script (creates a new secret):

```powershell
.\scripts\Register-HealthHubEnterpriseApp.ps1
```

### After granting consent

1. Wait 1–2 minutes for Entra permission propagation.
2. Trigger a manual refresh: open `/admin` and click **Refresh Now**, or `POST /api/admin/refresh`.
3. Check the Errors page — Defender errors should clear.

### Additional checks

1. Validate customer licensing supports Defender for Endpoint (Plan 1 or Plan 2 required).
2. Confirm endpoint paths are valid for the tenant and service plan.
3. Call `GET /api/powerbi/ingestion-status` and inspect `sourceStatus.defender` for remaining failures.

## Symptom: No data in Power BI visuals

Checks:

1. Call GET /api/health and verify hasSnapshot is true.
2. Call GET /api/powerbi/ingestion-status and inspect lastRefreshStatus and sourceStatus.
3. Call GET /api/powerbi/full-snapshot and inspect payload.
4. Confirm Power BI query points to the right host and port.
5. Trigger POST /api/admin/refresh and retry Power BI refresh.

## Symptom: Missing remediation recommendations from MCP sources

Checks:

1. If using external MCP bridge, verify MCP_BRIDGE_URL is reachable from the host.
2. If bridge is not required, set MCP_BRIDGE_URL empty to suppress bridge connection warnings.
3. Verify MCP_BRIDGE_API_KEY is valid when bridge auth is enabled.
4. Verify MCP bridge supports expected servers/capabilities.
5. If unreachable, fallback recommendations are generated by design.

## Symptom: Scheduler not running

Checks:

1. Validate REFRESH_CRON expression format.
2. Review startup logs for cron validation errors.
3. Verify service process stays alive in production host.

## Symptom: Windows service fails to start

Checks:

1. Verify Node.js is installed and available in PATH for LocalSystem context.
2. Verify .env contains valid TENANT_ID, CLIENT_ID, CLIENT_SECRET.
3. Review WinSW logs under install_path\\logs.
4. Re-run installer with -ForceReinstall to refresh binaries and wrapper config.

## Symptom: Enterprise app registration script errors

Checks:

1. Ensure Microsoft Graph PowerShell modules can be installed from PSGallery.
2. Ensure signed-in account has privileges to create apps and grant app role assignments.
3. If consent assignment is blocked by policy, run script with -SkipAdminConsent and perform consent separately.

## Operational Best Practices

- Store secrets in a secure vault and inject at runtime.
- Rotate client secrets regularly.
- Use a dedicated Entra app per customer tenant.
- Run refresh in intervals aligned with API rate limits.
- Alert on API health endpoint failures.
- Back up or export data/ snapshots if historical analysis is required.

## Support Checklist

When opening a support case, include:

1. Timestamp of the issue (UTC)
2. Endpoint called
3. HTTP status code and error message
4. Sanitized logs around the failure window
5. Current .env keys list (without secret values)
6. Output from:

```powershell
Invoke-RestMethod http://localhost:4010/api/health
Invoke-RestMethod http://localhost:4010/api/powerbi/ingestion-status
Invoke-RestMethod http://localhost:4010/api/powerbi/overview
```

## PowerShell Script Inventory

- scripts/Deploy-HealthHubClient.ps1: One-command orchestration for enterprise app registration + service install
- scripts/Register-HealthHubEnterpriseApp.ps1: Creates/updates app registration, service principal, permissions, consent, and emits .env values
- scripts/Install-HealthHubWindowsService.ps1: Builds app, installs WinSW wrapper, configures restart policy, starts service
- scripts/Uninstall-HealthHubWindowsService.ps1: Removes service and optionally deletes install directory

## Create and Publish This as a New Git Repository

This folder is initialized as an independent git repository.

To publish to GitHub:

```powershell
git add .
git commit -m "Initial commit: Defender XDR Power BI Health Hub"
git remote add origin <your-new-repo-url>
git push -u origin main
```

## Notes

- The pipeline is designed to survive partial source failures and still produce a snapshot.
- Error logs are sanitized to avoid leaking secrets.
- This repository is separate from BP-API-integration.
