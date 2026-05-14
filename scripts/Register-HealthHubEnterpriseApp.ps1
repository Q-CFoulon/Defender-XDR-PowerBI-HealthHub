[CmdletBinding()]
param(
    [string]$DisplayName = "Defender XDR Power BI Health Hub",
    [string]$TenantId = "",
    [int]$SecretValidityMonths = 12,
    [switch]$SkipAdminConsent,
    [switch]$UseDeviceCode,
    [string]$OutputEnvFilePath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($SecretValidityMonths -lt 1) {
    throw "SecretValidityMonths must be at least 1."
}

function Ensure-Module {
    param([Parameter(Mandatory = $true)][string]$ModuleName)

    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        Write-Host "Installing PowerShell module: $ModuleName"
        Install-Module -Name $ModuleName -Scope CurrentUser -Force -AllowClobber
    }

    Import-Module -Name $ModuleName -ErrorAction Stop
}

function Get-FirstOrNull {
    param([object]$Collection)

    if ($null -eq $Collection) {
        return $null
    }

    if ($Collection -is [System.Array]) {
        if ($Collection.Count -eq 0) {
            return $null
        }
        return $Collection[0]
    }

    return $Collection
}

function Resolve-AppRole {
    param(
        [Parameter(Mandatory = $true)][object]$ResourceServicePrincipal,
        [Parameter(Mandatory = $true)][string]$PermissionValue
    )

    $role = $ResourceServicePrincipal.AppRoles |
        Where-Object {
            $_.Value -eq $PermissionValue -and
            $_.IsEnabled -eq $true -and
            ($_.AllowedMemberTypes -contains "Application")
        } |
        Select-Object -First 1

    if (-not $role) {
        throw "Permission '$PermissionValue' was not found on resource '$($ResourceServicePrincipal.DisplayName)'."
    }

    return $role
}

Ensure-Module -ModuleName Microsoft.Graph.Authentication
Ensure-Module -ModuleName Microsoft.Graph.Applications

$connectParams = @{
    Scopes = @(
        "Application.ReadWrite.All",
        "AppRoleAssignment.ReadWrite.All",
        "Directory.Read.All"
    )
}

if ($TenantId) {
    $connectParams.TenantId = $TenantId
}

if ($UseDeviceCode) {
    $connectParams.UseDeviceCode = $true
}

Write-Host "Connecting to Microsoft Graph..."
Connect-MgGraph @connectParams | Out-Null
Select-MgProfile -Name "v1.0"

$graphContext = Get-MgContext
if (-not $graphContext) {
    throw "Unable to establish Microsoft Graph context."
}

$resolvedTenantId = $graphContext.TenantId
if (-not $resolvedTenantId) {
    throw "Unable to resolve tenant ID from Microsoft Graph context."
}

$displayNameEscaped = $DisplayName.Replace("'", "''")
$existingApplication = Get-FirstOrNull (Get-MgApplication -Filter "displayName eq '$displayNameEscaped'")

if ($existingApplication) {
    $application = $existingApplication
    Write-Host "Using existing app registration: $($application.DisplayName)"
}
else {
    $application = New-MgApplication -DisplayName $DisplayName -SignInAudience "AzureADMyOrg"
    Write-Host "Created app registration: $($application.DisplayName)"
}

$appServicePrincipal = Get-FirstOrNull (Get-MgServicePrincipal -Filter "appId eq '$($application.AppId)'")
if (-not $appServicePrincipal) {
    $appServicePrincipal = New-MgServicePrincipal -AppId $application.AppId
    Write-Host "Created enterprise application (service principal)."
}
else {
    Write-Host "Using existing enterprise application (service principal)."
}

$graphResourceSp = Get-FirstOrNull (Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'")
if (-not $graphResourceSp) {
    throw "Unable to locate Microsoft Graph resource service principal."
}

$defenderResourceSp = Get-FirstOrNull (Get-MgServicePrincipal -Filter "appId eq 'fc780465-2017-40d4-a0c5-307022471b92'")
if (-not $defenderResourceSp) {
    $defenderResourceSp = Get-FirstOrNull (Get-MgServicePrincipal -Filter "displayName eq 'WindowsDefenderATP'")
}
if (-not $defenderResourceSp) {
    throw "Unable to locate Microsoft Defender resource service principal."
}

$graphPermissions = @("SecurityEvents.Read.All")
$defenderPermissions = @(
    "Vulnerability.Read.All",
    "SecurityRecommendation.Read.All",
    "Score.Read.All",
    "Machine.ReadWrite.All"
)

$graphRoles = @($graphPermissions | ForEach-Object { Resolve-AppRole -ResourceServicePrincipal $graphResourceSp -PermissionValue $_ })
$defenderRoles = @($defenderPermissions | ForEach-Object { Resolve-AppRole -ResourceServicePrincipal $defenderResourceSp -PermissionValue $_ })

$requiredResourceAccess = @(
    @{
        ResourceAppId = $graphResourceSp.AppId
        ResourceAccess = @($graphRoles | ForEach-Object {
            @{
                Id = $_.Id
                Type = "Role"
            }
        })
    },
    @{
        ResourceAppId = $defenderResourceSp.AppId
        ResourceAccess = @($defenderRoles | ForEach-Object {
            @{
                Id = $_.Id
                Type = "Role"
            }
        })
    }
)

Update-MgApplication -ApplicationId $application.Id -RequiredResourceAccess $requiredResourceAccess | Out-Null
Write-Host "Updated required API permissions on app registration."

if (-not $SkipAdminConsent) {
    $existingAssignments = @(Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $appServicePrincipal.Id -All)

    $allAssignments = @(
        @{ ResourceSp = $graphResourceSp; Roles = $graphRoles },
        @{ ResourceSp = $defenderResourceSp; Roles = $defenderRoles }
    )

    foreach ($assignment in $allAssignments) {
        foreach ($role in $assignment.Roles) {
            $alreadyAssigned = $existingAssignments | Where-Object {
                $_.ResourceId -eq $assignment.ResourceSp.Id -and $_.AppRoleId -eq $role.Id
            } | Select-Object -First 1

            if (-not $alreadyAssigned) {
                $assignmentParams = @{
                    ServicePrincipalId = $appServicePrincipal.Id
                    PrincipalId = $appServicePrincipal.Id
                    ResourceId = $assignment.ResourceSp.Id
                    AppRoleId = $role.Id
                }

                New-MgServicePrincipalAppRoleAssignment @assignmentParams | Out-Null

                Write-Host "Granted app role '$($role.Value)' on '$($assignment.ResourceSp.DisplayName)'."
            }
            else {
                Write-Host "App role '$($role.Value)' is already granted."
            }
        }
    }
}
else {
    Write-Warning "SkipAdminConsent was specified. Ensure tenant admin grants consent before running production workloads."
}

$secretDisplayName = "healthhub-secret-$(Get-Date -Format 'yyyyMMddHHmmss')"
$secretEndDateUtc = (Get-Date).ToUniversalTime().AddMonths($SecretValidityMonths)
$secretCredential = Add-MgApplicationPassword -ApplicationId $application.Id -PasswordCredential @{
    DisplayName = $secretDisplayName
    EndDateTime = $secretEndDateUtc
}

$clientSecret = $secretCredential.SecretText
if (-not $clientSecret) {
    throw "Failed to create client secret."
}

$envSnippet = @"
APP_PORT=4010
NODE_ENV=production
REFRESH_CRON=0 */30 * * * *

TENANT_ID=$resolvedTenantId
CLIENT_ID=$($application.AppId)
CLIENT_SECRET=$clientSecret

DEFENDER_API_BASE_URL=https://api.security.microsoft.com
DEFENDER_SCOPE=https://api.security.microsoft.com/.default
DEFENDER_INITIATIVES_PATH=/api/recommendations
DEFENDER_TOP_INITIATIVES_PATH=/api/vulnerabilities?`$top=10
DEFENDER_VULNERABILITY_OVERVIEW_PATH=/api/exposureScore
DEFENDER_CLOUD_SCORE_PATH=/api/configurationScore

GRAPH_API_BASE_URL=https://graph.microsoft.com/v1.0
GRAPH_SCOPE=https://graph.microsoft.com/.default
GRAPH_SECURE_SCORES_PATH=/security/secureScores?$top=1
"@

Write-Host ""
Write-Host "Enterprise application registration completed."
Write-Host "TenantId: $resolvedTenantId"
Write-Host "ClientId: $($application.AppId)"
Write-Host "Secret display name: $secretDisplayName"
Write-Host "Secret expiry (UTC): $($secretEndDateUtc.ToString('u'))"
Write-Host ""
Write-Host "Copy the following values into your .env file:"
Write-Host $envSnippet

if ($OutputEnvFilePath) {
    Set-Content -Path $OutputEnvFilePath -Value $envSnippet -Encoding UTF8
    Write-Host "Saved environment snippet to: $OutputEnvFilePath"
}

Disconnect-MgGraph | Out-Null
