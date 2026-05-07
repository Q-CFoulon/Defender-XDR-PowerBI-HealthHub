[CmdletBinding()]
param(
    [string]$ServiceName = "DefenderXdrPowerBiHealthHub",
    [string]$DisplayName = "Defender XDR Power BI Health Hub",
    [string]$Description = "Collects Defender XDR and Secure Score data for Power BI dashboards.",
    [string]$SourcePath = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
    [string]$InstallPath = "C:\ProgramData\Defender-XDR-PowerBI-HealthHub",
    [string]$EnvironmentFilePath = "",
    [string]$WinswVersion = "v3.0.0",
    [switch]$ForceReinstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-CommandOrThrow {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $false)][string[]]$Arguments = @(),
        [Parameter(Mandatory = $false)][string]$WorkingDirectory = ""
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    if ($WorkingDirectory) {
        $psi.WorkingDirectory = $WorkingDirectory
    }

    foreach ($argument in $Arguments) {
        [void]$psi.ArgumentList.Add($argument)
    }

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    [void]$process.Start()

    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()

    $process.WaitForExit()

    if ($stdout) {
        Write-Host $stdout.TrimEnd()
    }
    if ($stderr) {
        Write-Host $stderr.TrimEnd()
    }

    if ($process.ExitCode -ne 0) {
        throw "Command failed with exit code $($process.ExitCode): $FilePath $($Arguments -join ' ')"
    }
}

if (-not (Test-IsAdministrator)) {
    throw "This script must run in an elevated PowerShell session (Run as Administrator)."
}

if (-not (Test-Path -Path $SourcePath)) {
    throw "SourcePath does not exist: $SourcePath"
}

$nodeCommand = Get-Command node -ErrorAction SilentlyContinue
$npmCommand = Get-Command npm -ErrorAction SilentlyContinue
if (-not $nodeCommand) {
    throw "Node.js was not found in PATH. Install Node.js 18.18+ and retry."
}
if (-not $npmCommand) {
    throw "npm was not found in PATH. Install Node.js 18.18+ and retry."
}

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service -and -not $ForceReinstall) {
    throw "Service '$ServiceName' already exists. Re-run with -ForceReinstall to replace it."
}

if ($service -and $ForceReinstall) {
    Write-Host "Existing service detected. Removing current service before reinstall."
    $existingWinswPath = Join-Path $InstallPath "$ServiceName.exe"

    if (Test-Path -Path $existingWinswPath) {
        try {
            & $existingWinswPath stop | Out-Null
        }
        catch {
            Write-Verbose "Existing service stop attempt failed or service already stopped."
        }

        & $existingWinswPath uninstall | Out-Null
    }
    else {
        if ($service.Status -ne "Stopped") {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        }
        & sc.exe delete $ServiceName | Out-Null
    }

    Start-Sleep -Seconds 2
}

Write-Host "Building application in source path: $SourcePath"
Invoke-CommandOrThrow -FilePath $npmCommand.Source -Arguments @("ci") -WorkingDirectory $SourcePath
Invoke-CommandOrThrow -FilePath $npmCommand.Source -Arguments @("run", "build") -WorkingDirectory $SourcePath

if (Test-Path -Path $InstallPath) {
    if ($ForceReinstall) {
        Write-Host "Force reinstall enabled. Existing install path will be refreshed: $InstallPath"
    }
}
else {
    New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
}

$stagingPath = Join-Path $env:TEMP "$ServiceName-stage"
if (Test-Path -Path $stagingPath) {
    Remove-Item -Path $stagingPath -Recurse -Force
}
New-Item -Path $stagingPath -ItemType Directory -Force | Out-Null

$copyItems = @(
    "dist",
    "powerbi",
    "package.json",
    "package-lock.json",
    ".env.example"
)

foreach ($item in $copyItems) {
    $sourceItem = Join-Path $SourcePath $item
    if (Test-Path -Path $sourceItem) {
        Copy-Item -Path $sourceItem -Destination $stagingPath -Recurse -Force
    }
}

foreach ($item in $copyItems) {
    $targetItem = Join-Path $InstallPath $item
    if (Test-Path -Path $targetItem) {
        Remove-Item -Path $targetItem -Recurse -Force
    }
}

Copy-Item -Path (Join-Path $stagingPath "*") -Destination $InstallPath -Recurse -Force

$envSource = ""
if ($EnvironmentFilePath -and (Test-Path -Path $EnvironmentFilePath)) {
    $envSource = (Resolve-Path $EnvironmentFilePath).Path
}
elseif (Test-Path -Path (Join-Path $SourcePath ".env")) {
    $envSource = (Join-Path $SourcePath ".env")
}

if ($envSource) {
    Copy-Item -Path $envSource -Destination (Join-Path $InstallPath ".env") -Force
}
elseif (-not (Test-Path -Path (Join-Path $InstallPath ".env"))) {
    Copy-Item -Path (Join-Path $InstallPath ".env.example") -Destination (Join-Path $InstallPath ".env") -Force
    Write-Warning "No environment file was supplied. .env was created from .env.example. Update credentials before starting production usage."
}

$dataPath = Join-Path $InstallPath "data"
$logsPath = Join-Path $InstallPath "logs"
New-Item -Path $dataPath -ItemType Directory -Force | Out-Null
New-Item -Path $logsPath -ItemType Directory -Force | Out-Null

Write-Host "Installing runtime dependencies in install path: $InstallPath"
Invoke-CommandOrThrow -FilePath $npmCommand.Source -Arguments @("ci", "--omit=dev") -WorkingDirectory $InstallPath

$winswExePath = Join-Path $InstallPath "$ServiceName.exe"
$winswConfigPath = Join-Path $InstallPath "$ServiceName.xml"
$winswDownloadUrl = "https://github.com/winsw/winsw/releases/download/$WinswVersion/WinSW-x64.exe"

if (-not (Test-Path -Path $winswExePath)) {
    Write-Host "Downloading WinSW from $winswDownloadUrl"
    Invoke-WebRequest -Uri $winswDownloadUrl -OutFile $winswExePath
}

$escapedNodePath = $nodeCommand.Source
$serviceXml = @"
<service>
  <id>$ServiceName</id>
  <name>$DisplayName</name>
  <description>$Description</description>
  <executable>$escapedNodePath</executable>
  <arguments>dist\index.js</arguments>
  <workingdirectory>%BASE%</workingdirectory>
  <startmode>Automatic</startmode>
  <stoptimeout>30 sec</stoptimeout>
  <resetfailure>1 hour</resetfailure>
  <onfailure action="restart" delay="10 sec" />
  <onfailure action="restart" delay="30 sec" />
  <onfailure action="restart" delay="60 sec" />
  <env name="APP_BASE_DIR" value="%BASE%" />
  <env name="DATA_DIRECTORY" value="%BASE%\\data" />
  <logpath>%BASE%\\logs</logpath>
  <log mode="roll-by-time">
    <pattern>yyyyMMdd</pattern>
  </log>
</service>
"@

Set-Content -Path $winswConfigPath -Value $serviceXml -Encoding UTF8

Write-Host "Installing and starting Windows service: $ServiceName"
& $winswExePath install | Out-Null
& sc.exe config $ServiceName start= delayed-auto | Out-Null
& $winswExePath start | Out-Null

$healthUrl = "http://localhost:4010/api/health"
$healthSuccess = $false

for ($attempt = 1; $attempt -le 15; $attempt++) {
    try {
        $response = Invoke-RestMethod -Method Get -Uri $healthUrl -TimeoutSec 5
        if ($response.status -eq "ok") {
            $healthSuccess = $true
            break
        }
    }
    catch {
        Start-Sleep -Seconds 2
    }
}

if ($healthSuccess) {
    Write-Host "Service installation complete. Health endpoint is responding at $healthUrl"
}
else {
    Write-Warning "Service installed but health endpoint did not respond within expected time window."
    Write-Warning "Review logs under: $logsPath"
}

Write-Host "Installed service name: $ServiceName"
Write-Host "Install path: $InstallPath"
Write-Host "Log path: $logsPath"
