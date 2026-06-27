<#
.SYNOPSIS
    Launches Windows Sandbox (Containers-DisposableClientVM) and builds + smoke-tests
    the TrackerAppService Windows service inside the disposable VM.

.DESCRIPTION
    Run this on a Windows host (Windows 10/11 Pro/Enterprise/Education) that has the
    "Windows Sandbox" optional feature enabled. It maps the repository into the sandbox,
    then runs sandbox\build-and-test.ps1 inside the sandbox to install the build
    toolchain, restore, build, and install/start/stop the service as a smoke test.

    Build output and logs are written back to the mapped (host) repo folder so they
    survive after the disposable sandbox is closed:
      - TrackerAppService\bin\<Configuration>\
      - sandbox\logs\

.PARAMETER Configuration
    MSBuild configuration to build. Debug (default) or Release.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\sandbox\Run-InWindowsSandbox.ps1
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug'
)

$ErrorActionPreference = 'Stop'

# Repo root is the parent of this script's folder (sandbox\).
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot  = Split-Path -Parent $scriptDir
Write-Host "Repository root (host): $repoRoot"

# Verify the Windows Sandbox feature is enabled.
$feature = Get-WindowsOptionalFeature -Online -FeatureName 'Containers-DisposableClientVM' -ErrorAction SilentlyContinue
if (-not $feature -or $feature.State -ne 'Enabled') {
    Write-Warning "Windows Sandbox (Containers-DisposableClientVM) is not enabled on this host."
    Write-Host   "Enable it from an elevated PowerShell, then reboot:"
    Write-Host   "    Enable-WindowsOptionalFeature -Online -FeatureName 'Containers-DisposableClientVM' -All"
    throw "Windows Sandbox feature 'Containers-DisposableClientVM' is not enabled."
}

$sandboxExe = Join-Path $env:WINDIR 'System32\WindowsSandbox.exe'
if (-not (Test-Path $sandboxExe)) {
    throw "WindowsSandbox.exe not found at '$sandboxExe'."
}

# Path the repo will be mapped to inside the sandbox.
$sandboxRepo = 'C:\app-usage'
$logonCommand = 'powershell.exe -ExecutionPolicy Bypass -NoProfile -File ' +
                "`"$sandboxRepo\sandbox\build-and-test.ps1`" -Configuration $Configuration"

# Generate a .wsb config pointing at this repo (host paths must be absolute).
$wsb = @"
<Configuration>
  <VGpu>Disable</VGpu>
  <Networking>Enable</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$repoRoot</HostFolder>
      <SandboxFolder>$sandboxRepo</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>$logonCommand</Command>
  </LogonCommand>
</Configuration>
"@

$wsbPath = Join-Path $env:TEMP 'AppUsage.generated.wsb'
$wsb | Set-Content -Path $wsbPath -Encoding UTF8

Write-Host "Generated sandbox config: $wsbPath"
Write-Host "Build configuration      : $Configuration"
Write-Host "Launching Windows Sandbox (build + smoke test runs automatically on logon)..."

Start-Process -FilePath $sandboxExe -ArgumentList "`"$wsbPath`""

Write-Host ""
Write-Host "Inside the sandbox the build/test runs automatically. When it finishes, check:"
Write-Host "    $repoRoot\sandbox\logs\   (transcript log, persists on the host)"
Write-Host "    $repoRoot\TrackerAppService\bin\$Configuration\   (build output)"
