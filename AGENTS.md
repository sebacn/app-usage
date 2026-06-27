# AGENTS.md

## Cursor Cloud specific instructions

### What this project is

`TrackerAppService` is a **Windows-only .NET Framework 4.7.2 Windows Service**
(`OutputType=WinExe`, `TargetFrameworkVersion=v4.7.2`) that tracks/limits how long
Windows applications are used. `SetupAppTracker` is a Visual Studio setup project
(`.vdproj`) that packages the service into an installer. The single solution is
`TrackerAppService/TrackerAppService.sln`.

### Important: it cannot be built or run on the Linux Cloud Agent VM

The service depends on a large set of Windows-only technologies that have no Linux
equivalent, so a full build/run is **not possible** in the Cloud Agent environment:

- **COM interop** — `NetFwTypeLib` (`COMReference` in the `.csproj`, Windows Firewall
  `HNetCfg.FwPolicy2`). `dotnet build` fails here first with
  `MSB4216: ... ResolveComReference task ... runtime "NET" and architecture "x86"`.
- **WinRT** — `Microsoft.Windows.SDK.Contracts` (`Windows.UI.Xaml`, `Windows.Media.*`,
  `Windows.Security.*`, `Windows.Services.Maps`, `Windows.UI.Composition`, etc.).
- **Windows Service host** — `System.ServiceProcess` (`ServiceBase.Run`, SCM).
- **WMI / DPAPI / EventLog** — `System.Management`, `ProtectedData`
  (`DataProtectionScope.LocalMachine`), `EventLog`.
- **`System.Web`, `System.Windows.Forms`**, PowerShell notifications
  (`msgNotify.ps1`), and extensive P/Invoke to `user32`, `dwmapi`, `kernel32`,
  `advapi32`, `userenv`.

To actually build, run, install, or debug the service you need **Windows** with
Visual Studio (or MSBuild + the .NET Framework 4.7.2 developer pack). On Windows it
runs as a service (`sc`/`InstallUtil` via the `SetupAppTracker` installer) and exposes
an embedded Watson web server plus a named pipe (`TrackerAppService.pipe`).

### Build + test in Windows Sandbox (on a Windows host)

The supported way to build and smoke-test the service end to end is a disposable
**Windows Sandbox** (`Containers-DisposableClientVM`). This must be run on a **Windows
10/11 Pro/Enterprise/Education host** with the Windows Sandbox feature enabled — it is
**not runnable from the Linux Cloud Agent VM** (no Windows host / nested virtualization).

Tooling lives in `sandbox/`:

- `sandbox/Run-InWindowsSandbox.ps1` — host-side entry point. Generates a `.wsb`
  pointing at the repo, then launches Windows Sandbox. Usage (from the repo root):
  `powershell -ExecutionPolicy Bypass -File .\sandbox\Run-InWindowsSandbox.ps1`
  (optional `-Configuration Release`).
- `sandbox/build-and-test.ps1` — runs inside the sandbox (invoked automatically by the
  sandbox `<LogonCommand>`): installs Chocolatey + VS 2022 Build Tools (managed desktop
  workload + Windows SDK) + the .NET Framework 4.8 dev pack, then restores, builds with
  MSBuild, and installs/starts/stops the service capturing EventLog + `AppUsage.log`.
- `sandbox/AppUsage.wsb` — a `.wsb` template (edit `HostFolder`); the launcher above is
  preferred since it fills the host path in automatically.

Enable the feature once (elevated, then reboot):
`Enable-WindowsOptionalFeature -Online -FeatureName 'Containers-DisposableClientVM' -All`

Notes / gotchas:
- The repo is mapped read-write to `C:\app-usage` in the sandbox, so build output
  (`TrackerAppService\bin\<cfg>\`) and a transcript (`sandbox\logs\`) persist on the
  host after the disposable sandbox closes.
- The sandbox is ephemeral: the toolchain (VS Build Tools, several GB) is reinstalled
  on every launch, so a run takes a while. For faster iteration, build on a persistent
  Windows machine/VM with Build Tools preinstalled instead of a fresh sandbox each time.

### What does work on Linux (for code-level work only)

The .NET 8 SDK is installed at `~/.dotnet` (on `PATH`/`DOTNET_ROOT` via `~/.bashrc`),
which is enough to **restore NuGet packages** for code navigation/inspection:

- ✅ `dotnet restore TrackerAppService/TrackerAppService.csproj`
- ❌ `dotnet build TrackerAppService/TrackerAppService.csproj` (fails on `ResolveComReference`; would also fail on WinRT/WMI/DPAPI/ServiceProcess)

Mono (`/usr/bin/mono`, `xbuild`) and `nuget.exe` are also present, but Ubuntu's Mono
ships no MSBuild, so it cannot restore the `PackageReference` style project.

There is no test project and no lint configuration in the repo. There is nothing to
run as a server/app on Linux. Treat Cloud Agent work here as **read/edit + restore for
IntelliSense-level analysis only**; verify any build/run on a Windows machine.
