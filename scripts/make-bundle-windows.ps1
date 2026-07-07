# SPDX-License-Identifier: MIT
#
# Stage a self-contained zip that a target Windows machine can extract and
# run without needing the source tree. Windows counterpart to
# scripts/make-bundle.sh / make-bundle-ios.sh (both followed for the
# staging/versioning/README conventions).
#
#   powershell -File scripts/make-bundle-windows.ps1              -> dist/polar-wg-windows-YYYYMMDD-<sha>.zip
#   powershell -File scripts/make-bundle-windows.ps1 -Version v1.2.3  -> dist/polar-wg-windows-v1.2.3.zip
#
# On the target:
#   Expand-Archive polar-wg-windows-<ver>.zip
#   cd polar-wg-windows-<ver>
#   .\scripts\wg-tray.bat            (or scripts\start-client.bat for the plain CLI)

param(
    [string]$Version,
    [switch]$Rebuild
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$BuildWin = Join-Path $RepoRoot "build\win"
$Dist     = Join-Path $RepoRoot "dist"

if (-not $Version) {
    $sha = try { (git -C $RepoRoot rev-parse --short=8 HEAD 2>$null) } catch { $null }
    if (-not $sha) { $sha = "nogit" }
    $Version = "$(Get-Date -Format 'yyyyMMdd')-$sha"
}

$Name  = "polar-wg-windows-$Version"
$Stage = Join-Path $Dist $Name

# ── build only if missing ────────────────────────────────────────────────────
# Does NOT force a rebuild when the binaries already exist: wg_windows_tun.exe
# may be a live, running tunnel (locked for writing), and packaging must not
# require stopping it. Pass -Rebuild to force a fresh build (will fail loudly
# if the exe is locked by a running process, same as any other build).
$RequiredFiles = @(
    "wg_windows_tun.exe",
    "wg_windows_keygen.exe",
    "wintun.dll"
)
$missing = $RequiredFiles | Where-Object { -not (Test-Path (Join-Path $BuildWin $_)) }
if ($Rebuild -or ($missing | Where-Object { $_ -ne "wintun.dll" })) {
    Write-Host "==> Building (build-windows.ps1 -Test)"
    & (Join-Path $PSScriptRoot "build-windows.ps1") -Test | Out-Null
} else {
    Write-Host "==> Using existing binaries in $BuildWin (pass -Rebuild to force a fresh build)"
}

foreach ($f in $RequiredFiles) {
    $p = Join-Path $BuildWin $f
    if (-not (Test-Path $p)) {
        throw "missing $p -- wintun.dll must be downloaded from https://www.wintun.net and placed in build\win\ first (amd64\wintun.dll from the zip); the exes come from build-windows.ps1"
    }
}

# ── stage ────────────────────────────────────────────────────────────────────
Write-Host "==> Staging $Stage"
if (Test-Path $Stage) { Remove-Item $Stage -Recurse -Force }
# Mirrors the dev-tree layout (build\win\, scripts\) rather than a cleaner
# bin\ convention: join-windows.ps1 / wg-tray.ps1 / start-client.bat all
# hardcode "..\build\win\<exe>" relative to the scripts folder, and
# reworking every script's path logic just for bundle layout isn't worth
# it -- matching the layout they already expect means zero script changes.
New-Item -ItemType Directory -Force -Path "$Stage\build\win", "$Stage\scripts" | Out-Null

Copy-Item (Join-Path $BuildWin "wg_windows_tun.exe")    "$Stage\build\win\"
Copy-Item (Join-Path $BuildWin "wg_windows_keygen.exe") "$Stage\build\win\"
Copy-Item (Join-Path $BuildWin "wintun.dll")            "$Stage\build\win\"

$ScriptFiles = @(
    "join-windows.ps1",
    "wgctl-agent-windows.ps1",
    "install-agent-task.ps1",
    "wg-tray.ps1",
    "wg-tray.bat",
    "start-client.bat"
)
foreach ($f in $ScriptFiles) {
    Copy-Item (Join-Path $PSScriptRoot $f) "$Stage\scripts\"
}

# Version stamp, same convention as the macOS/iOS bundles (agent_ver in the
# /v1/register payload); nothing on Windows reads this back yet, but keeping
# the same shape costs nothing and matches every other platform's bundle.
Set-Content -Path "$Stage\VERSION" -Value $Version -NoNewline

# Top-level README so the target user sees instructions without browsing.
$gitRev = try { (git -C $RepoRoot rev-parse HEAD 2>$null) } catch { $null }
if (-not $gitRev) { $gitRev = "no-git" }
$readme = @"
polar-wg-windows $Version - portable WireGuard CLI bundle for Windows

Requires: Windows 10/11 x64, admin rights (to create the Wintun network
adapter). build\win\wintun.dll is the official signed driver from wintun.net,
redistributed here under its binary license (consumed only via its
published header API).

First-time setup (target machine):
  1. Get a join token from your control plane operator.
  2. .\scripts\join-windows.ps1 -Token <your-token>
     Registers this device and writes config\<iface>.conf.
  3. .\scripts\wg-tray.bat
     Starts the system tray manager (self-elevates once via UAC).
     Right-click the tray icon -> Connect.

Or, plain CLI instead of the tray:
  .\scripts\start-client.bat

Uninstall: just delete this folder. wg-tray's Exit / Ctrl+C on the CLI
tears down the adapter first; nothing is installed system-wide beyond
the Wintun driver service itself (shared with any other Wintun-based app,
e.g. the official WireGuard client -- not removed by deleting this folder).

Build info:
  built on:   $(Get-Date)
  source rev: $gitRev
"@
Set-Content -Path "$Stage\README.txt" -Value $readme

# ── zip + checksum ───────────────────────────────────────────────────────────
Write-Host "==> Zipping"
$ZipPath = Join-Path $Dist "$Name.zip"
if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }
Compress-Archive -Path $Stage -DestinationPath $ZipPath

$hash = Get-FileHash -Path $ZipPath -Algorithm SHA256
$hash.Hash | Set-Content -Path "$ZipPath.sha256" -NoNewline

Remove-Item $Stage -Recurse -Force

Write-Host ""
Write-Host "  $ZipPath"
Write-Host "  size:   $([Math]::Round((Get-Item $ZipPath).Length / 1MB, 2)) MB"
Write-Host "  sha256: $($hash.Hash)"
