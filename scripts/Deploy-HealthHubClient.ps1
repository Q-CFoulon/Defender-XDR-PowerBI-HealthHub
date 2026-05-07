[CmdletBinding()]
param(
    [string]$EnvironmentFilePath = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..")).Path ".env"),
    [string]$AppDisplayName = "Defender XDR Power BI Health Hub",
    [switch]$SkipEnterpriseAppRegistration,
    [switch]$SkipAdminConsent,
    [switch]$UseDeviceCode,
    [switch]$SkipServiceInstall,
    [switch]$ForceServiceReinstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptRoot = $PSScriptRoot
$repoRoot = (Resolve-Path (Join-Path $scriptRoot "..")).Path
$registerScript = Join-Path $scriptRoot "Register-HealthHubEnterpriseApp.ps1"
$installScript = Join-Path $scriptRoot "Install-HealthHubWindowsService.ps1"

if (-not (Test-Path -Path $registerScript)) {
    throw "Missing script: $registerScript"
}
if (-not (Test-Path -Path $installScript)) {
    throw "Missing script: $installScript"
}

if (-not $SkipEnterpriseAppRegistration) {
    Write-Host "Registering enterprise application and writing environment file..."

    $registerParams = @{
        DisplayName = $AppDisplayName
        OutputEnvFilePath = $EnvironmentFilePath
    }

    if ($SkipAdminConsent) {
        $registerParams.SkipAdminConsent = $true
    }
    if ($UseDeviceCode) {
        $registerParams.UseDeviceCode = $true
    }

    & $registerScript @registerParams
}

if (-not (Test-Path -Path $EnvironmentFilePath)) {
    throw "Environment file not found: $EnvironmentFilePath"
}

if (-not $SkipServiceInstall) {
    Write-Host "Installing or updating Windows service..."

    $installParams = @{
        SourcePath = $repoRoot
        EnvironmentFilePath = $EnvironmentFilePath
    }

    if ($ForceServiceReinstall) {
        $installParams.ForceReinstall = $true
    }

    & $installScript @installParams
}

Write-Host "Deployment workflow completed."
Write-Host "Health check endpoint: http://localhost:4010/api/health"
