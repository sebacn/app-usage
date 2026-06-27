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
