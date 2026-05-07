[CmdletBinding()]
param(
    [string]$ServiceName = "DefenderXdrPowerBiHealthHub",
    [string]$InstallPath = "C:\ProgramData\Defender-XDR-PowerBI-HealthHub",
    [switch]$RemoveInstallPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    throw "This script must run in an elevated PowerShell session (Run as Administrator)."
}

$winswExePath = Join-Path $InstallPath "$ServiceName.exe"
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if ($service) {
    if (Test-Path -Path $winswExePath) {
        try {
            & $winswExePath stop | Out-Null
        }
        catch {
            Write-Verbose "Service stop attempt failed or service already stopped."
        }

        & $winswExePath uninstall | Out-Null
    }
    else {
        if ($service.Status -ne "Stopped") {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        }

        & sc.exe delete $ServiceName | Out-Null
    }

    Write-Host "Service removed: $ServiceName"
}
else {
    Write-Host "Service was not found: $ServiceName"
}

if ($RemoveInstallPath -and (Test-Path -Path $InstallPath)) {
    Remove-Item -Path $InstallPath -Recurse -Force
    Write-Host "Install path removed: $InstallPath"
}
