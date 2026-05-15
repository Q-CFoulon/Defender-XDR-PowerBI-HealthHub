<#
.SYNOPSIS
    Grants admin consent for the Defender for Endpoint (WindowsDefenderATP) and
    Microsoft Graph API permissions required by the Defender XDR Power BI Health Hub.

.DESCRIPTION
    This script resolves the 403 Forbidden errors from the Defender API and Graph API
    by granting app role assignments on the WindowsDefenderATP and Microsoft Graph
    resource service principals.

    Defender roles:
      - Score.Read.All               - /api/exposureScore, /api/configurationScore
      - SecurityRecommendation.Read.All - /api/recommendations
      - Vulnerability.Read.All       - /api/vulnerabilities
      - Machine.ReadWrite.All        - MCP remediation bridge (optional)

    Graph roles:
      - SecurityEvents.Read.All      - /security/secureScores

    Run this script as a Global Administrator or Privileged Role Administrator.

.PARAMETER ClientId
    The Application (client) ID of the Health Hub app registration.

.PARAMETER TenantId
    The Azure AD tenant ID (optional; inferred from Graph context if omitted).

.PARAMETER UseDeviceCode
    Use device code flow for authentication (useful for headless terminals).

.EXAMPLE
    .\Grant-DefenderPermissions.ps1 -ClientId "aea214c1-aef3-4d9b-b6a5-cf6b157cb089"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ClientId,

    [string]$TenantId = "",

    [switch]$UseDeviceCode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Install-RequiredModule {
    param([Parameter(Mandatory = $true)][string]$ModuleName)
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        Write-Host "Installing module: $ModuleName"
        Install-Module -Name $ModuleName -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module -Name $ModuleName -ErrorAction Stop
}

Install-RequiredModule -ModuleName Microsoft.Graph.Authentication
Install-RequiredModule -ModuleName Microsoft.Graph.Applications

$connectParams = @{
    Scopes = @(
        "Application.Read.All",
        "AppRoleAssignment.ReadWrite.All"
    )
}
if ($TenantId) { $connectParams.TenantId = $TenantId }
if ($UseDeviceCode) { $connectParams.UseDeviceCode = $true }

Write-Host "Connecting to Microsoft Graph..."
Connect-MgGraph @connectParams | Out-Null

$graphContext = Get-MgContext
if (-not $graphContext) { throw "Unable to establish Microsoft Graph context." }
Write-Host "Connected to tenant: $($graphContext.TenantId)"

# Locate the app's service principal
$appSp = Get-MgServicePrincipal -Filter "appId eq '$ClientId'" | Select-Object -First 1
if (-not $appSp) { throw "Service principal not found for client ID: $ClientId. Run Register-HealthHubEnterpriseApp.ps1 first." }
Write-Host "Found service principal: $($appSp.DisplayName) ($($appSp.Id))"

Write-Host ""
Write-Host "=== Defender API (WindowsDefenderATP) ==="

# Locate the WindowsDefenderATP resource service principal
$defenderSp = Get-MgServicePrincipal -Filter "appId eq 'fc780465-2017-40d4-a0c5-307022471b92'" | Select-Object -First 1
if (-not $defenderSp) {
    $defenderSp = Get-MgServicePrincipal -Filter "displayName eq 'WindowsDefenderATP'" | Select-Object -First 1
}
if (-not $defenderSp) { throw "WindowsDefenderATP service principal not found in this tenant. Ensure Defender for Endpoint is provisioned." }
Write-Host "Found Defender resource: $($defenderSp.DisplayName) ($($defenderSp.Id))"

# Required permissions
$requiredPermissions = @(
    "Score.Read.All",
    "SecurityRecommendation.Read.All",
    "Vulnerability.Read.All",
    "Machine.ReadWrite.All"
)

# Get existing assignments
$existingAssignments = @(Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $appSp.Id -All)

$defenderGrantedCount = 0
$defenderSkippedCount = 0

foreach ($permValue in $requiredPermissions) {
    $role = $defenderSp.AppRoles |
        Where-Object { $_.Value -eq $permValue -and $_.IsEnabled -eq $true -and ($_.AllowedMemberTypes -contains "Application") } |
        Select-Object -First 1

    if (-not $role) {
        Write-Warning "Permission '$permValue' not found on WindowsDefenderATP. Skipping."
        continue
    }

    $alreadyGranted = $existingAssignments |
        Where-Object { $_.ResourceId -eq $defenderSp.Id -and $_.AppRoleId -eq $role.Id } |
        Select-Object -First 1

    if ($alreadyGranted) {
        Write-Host "  [SKIP] $permValue - already granted"
        $defenderSkippedCount++
        continue
    }

    $params = @{
        ServicePrincipalId = $appSp.Id
        PrincipalId        = $appSp.Id
        ResourceId         = $defenderSp.Id
        AppRoleId          = $role.Id
    }

    New-MgServicePrincipalAppRoleAssignment @params | Out-Null
    Write-Host "  [GRANT] $permValue - admin consent granted"
    $defenderGrantedCount++
}

Write-Host ""
Write-Host "Defender: Granted: $defenderGrantedCount, Already present: $defenderSkippedCount"

# ── Microsoft Graph Permissions ──────────────────────────────────────────────
Write-Host ""
Write-Host "=== Microsoft Graph ==="

$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" | Select-Object -First 1
if (-not $graphSp) { throw "Microsoft Graph service principal not found in this tenant." }
Write-Host "Found Graph resource: $($graphSp.DisplayName) ($($graphSp.Id))"

$graphPermissions = @(
    "SecurityEvents.Read.All"
)

# Refresh existing assignments (may have been updated above)
$existingAssignments = @(Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $appSp.Id -All)

$graphGrantedCount = 0
$graphSkippedCount = 0

foreach ($permValue in $graphPermissions) {
    $role = $graphSp.AppRoles |
        Where-Object { $_.Value -eq $permValue -and $_.IsEnabled -eq $true -and ($_.AllowedMemberTypes -contains "Application") } |
        Select-Object -First 1

    if (-not $role) {
        Write-Warning "Permission '$permValue' not found on Microsoft Graph. Skipping."
        continue
    }

    $alreadyGranted = $existingAssignments |
        Where-Object { $_.ResourceId -eq $graphSp.Id -and $_.AppRoleId -eq $role.Id } |
        Select-Object -First 1

    if ($alreadyGranted) {
        Write-Host "  [SKIP] $permValue - already granted"
        $graphSkippedCount++
        continue
    }

    $params = @{
        ServicePrincipalId = $appSp.Id
        PrincipalId        = $appSp.Id
        ResourceId         = $graphSp.Id
        AppRoleId          = $role.Id
    }

    New-MgServicePrincipalAppRoleAssignment @params | Out-Null
    Write-Host "  [GRANT] $permValue - admin consent granted"
    $graphGrantedCount++
}

Write-Host ""
Write-Host "Graph: Granted: $graphGrantedCount, Already present: $graphSkippedCount"
Write-Host ""
Write-Host "Done."
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Wait 1-2 minutes for permission propagation."
Write-Host "  2. Restart the Health Hub service (or trigger a manual refresh)."
Write-Host "  3. Check GET /admin -> Errors page - Defender errors should clear."
