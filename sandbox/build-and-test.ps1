<#
.SYNOPSIS
    Runs INSIDE Windows Sandbox: installs the build toolchain, restores, builds, and
    smoke-tests the TrackerAppService Windows service.

.DESCRIPTION
    Invoked automatically by sandbox\Run-InWindowsSandbox.ps1 via the sandbox
    <LogonCommand>. The repository is expected to be mapped to C:\app-usage.

    Steps:
      1. Install Chocolatey.
      2. Install VS 2022 Build Tools (managed desktop workload + Windows SDK) and the
         .NET Framework 4.8 dev pack (provides the 4.7.2 targeting pack + MSBuild).
      3. Restore NuGet packages and build TrackerAppService.csproj with MSBuild.
      4. Install the built Windows service, start it, capture EventLog + AppUsage.log,
         then stop and remove it.

    A transcript is written to C:\app-usage\sandbox\logs\ (mapped back to the host).
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug'
)

$ErrorActionPreference = 'Stop'

$repo    = 'C:\app-usage'
$proj    = Join-Path $repo 'TrackerAppService\TrackerAppService.csproj'
$logDir  = Join-Path $repo 'sandbox\logs'
$serviceName = 'TrackerAppService'

New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$transcript = Join-Path $logDir ("build-and-test-{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))
Start-Transcript -Path $transcript -Force

function Write-Step([string]$message) {
    Write-Host ""
    Write-Host "==== $message ====" -ForegroundColor Cyan
}

$buildOk = $false

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    if (-not (Test-Path $proj)) {
        throw "Project not found at '$proj'. Is the repo mapped to C:\app-usage?"
    }

    Write-Step "Install Chocolatey"
    if (-not (Get-Command choco.exe -ErrorAction SilentlyContinue)) {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        Invoke-Expression ((New-Object Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        $env:Path += ";$env:ALLUSERSPROFILE\chocolatey\bin"
    }

    Write-Step "Install build toolchain (VS Build Tools + .NET Framework dev pack)"
    choco install -y --no-progress visualstudio2022buildtools
    choco install -y --no-progress visualstudio2022-workload-manageddesktopbuildtools `
        --package-parameters "--add Microsoft.VisualStudio.Component.Windows11SDK.22621"
    choco install -y --no-progress netfx-4.8-devpack

    Write-Step "Locate MSBuild"
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vswhere)) { throw "vswhere.exe not found; VS Build Tools install may have failed." }
    $msbuild = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild `
        -find 'MSBuild\**\Bin\MSBuild.exe' | Select-Object -First 1
    if (-not $msbuild) { throw "MSBuild.exe not found after installing Build Tools." }
    Write-Host "MSBuild: $msbuild"

    Write-Step "NuGet restore"
    & $msbuild $proj -t:Restore -p:Configuration=$Configuration
    if ($LASTEXITCODE -ne 0) { throw "Restore failed (exit $LASTEXITCODE)." }

    Write-Step "Build ($Configuration)"
    & $msbuild $proj -p:Configuration=$Configuration -m -nologo
    if ($LASTEXITCODE -ne 0) { throw "Build failed (exit $LASTEXITCODE)." }

    $outDir = Join-Path $repo "TrackerAppService\bin\$Configuration"
    $exe    = Join-Path $outDir 'TrackerAppService.exe'
    if (-not (Test-Path $exe)) { throw "Build output not found: $exe" }
    $buildOk = $true
    Write-Host "BUILD SUCCEEDED: $exe" -ForegroundColor Green

    Write-Step "Install + start Windows service (smoke test)"
    if (Get-Service $serviceName -ErrorAction SilentlyContinue) {
        Stop-Service $serviceName -ErrorAction SilentlyContinue
        & sc.exe delete $serviceName | Out-Host
        Start-Sleep -Seconds 2
    }
    New-Service -Name $serviceName -BinaryPathName "`"$exe`"" -StartupType Manual | Out-Host
    try {
        Start-Service $serviceName
        Start-Sleep -Seconds 25
        $svc = Get-Service $serviceName
        Write-Host "Service status: $($svc.Status)"

        Write-Step "Application EventLog (source: $serviceName)"
        Get-EventLog -LogName Application -Source $serviceName -Newest 25 -ErrorAction SilentlyContinue |
            Format-Table TimeGenerated, EntryType, Message -AutoSize -Wrap | Out-Host

        $appLog = Join-Path $outDir 'AppUsage.log'
        if (Test-Path $appLog) {
            Write-Step "AppUsage.log (tail)"
            Get-Content $appLog -Tail 40 | Out-Host
        }
    }
    finally {
        Stop-Service $serviceName -ErrorAction SilentlyContinue
        & sc.exe delete $serviceName | Out-Host
    }

    Write-Host ""
    Write-Host "SMOKE TEST COMPLETE" -ForegroundColor Green
}
catch {
    Write-Host ""
    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace
}
finally {
    Write-Host ""
    Write-Host ("Build succeeded: {0}" -f $buildOk)
    Write-Host "Transcript: $transcript (also visible on the host under sandbox\logs\)"
    Stop-Transcript
    Write-Host "Press Enter to close the sandbox..."
    [void](Read-Host)
}
