# SPDX-License-Identifier: MIT
#
# Build the WireGuard protocol core (libwg equivalent) on Windows with
# MSVC, and run the 27-test KAT suite against it.
#
# This covers src/wg_noise.c, wg_cookie.c, wg_crypto.c, wg_crypto_impl.c,
# allowedips.c, wg_session.c, and curve25519_portable.c (the pure-C X25519
# fallback used here instead of the CryptoKit bridge, since there's no
# Swift/CryptoKit on Windows), packaged into build/win/libwg.lib.
#
# Also builds src/wg_windows_tun.c — a Wintun-backed CLI tunnel host that
# drives wg_session.c's I/O-free API (the Windows counterpart to
# PacketTunnelProvider.swift / wg_jni.c), producing wg_windows_tun.exe.
# This does NOT port src/wg_core.c (the POSIX utun+select() reference
# client) — see src/windows_stubs/ for the header shims libwg depends on
# (Windows counterpart to src/macos_stubs/), and src/windows_stubs/wintun.h
# for the Wintun API surface. Running wg_windows_tun.exe needs wintun.dll
# (from wintun.net) next to the exe and admin elevation — neither is
# required just to build it.
#
# Usage:
#   powershell -File scripts/build-windows.ps1
#   powershell -File scripts/build-windows.ps1 -Test    # also run crypto_vector_test.exe

param(
    [switch]$Test
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$Src      = Join-Path $RepoRoot "src"
$Stubs    = Join-Path $RepoRoot "src\windows_stubs"
$OutDir   = Join-Path $RepoRoot "build\win"

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# Locate vcvars64.bat via vswhere if available, else fall back to the
# most common VS2022 install paths.
function Find-VcVars64 {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($vsPath) {
            $candidate = Join-Path $vsPath "VC\Auxiliary\Build\vcvars64.bat"
            if (Test-Path $candidate) { return $candidate }
        }
    }
    foreach ($edition in "Community", "Professional", "Enterprise", "BuildTools") {
        $candidate = "${env:ProgramFiles}\Microsoft Visual Studio\2022\$edition\VC\Auxiliary\Build\vcvars64.bat"
        if (Test-Path $candidate) { return $candidate }
    }
    throw "Could not locate vcvars64.bat — install the 'Desktop development with C++' workload."
}

$VcVars = Find-VcVars64
Write-Host "Using vcvars64.bat: $VcVars"

# SRCS mirrors the Makefile's libwg.a source list, plus curve25519_portable.c
# standing in for crypto_bridge.swift (no Swift toolchain on Windows).
$Srcs = @(
    "wg_noise.c",
    "wg_cookie.c",
    "wg_crypto.c",
    "wg_crypto_impl.c",
    "allowedips.c",
    "wg_session.c",
    "curve25519_portable.c"
)

$CommonArgs = "/nologo /c /std:c11 /DCOMPAT_NEED_BLAKE2S /I `"$Stubs`" /I `"$Src`""

$Objs = @()
foreach ($s in $Srcs) {
    $srcPath = Join-Path $Src $s
    $objPath = Join-Path $OutDir ($s -replace '\.c$', '.obj')
    Write-Host "  CC  $s"
    $cmd = "`"$VcVars`" >nul && cl $CommonArgs `"$srcPath`" /Fo:`"$objPath`""
    cmd /c $cmd
    if ($LASTEXITCODE -ne 0) { throw "Compile failed: $s" }
    $Objs += $objPath
}

$LibPath = Join-Path $OutDir "libwg.lib"
Write-Host "  LIB $LibPath"
$objList = ($Objs | ForEach-Object { "`"$_`"" }) -join ' '
cmd /c "`"$VcVars`" >nul && lib /nologo /OUT:`"$LibPath`" $objList"
if ($LASTEXITCODE -ne 0) { throw "Static-lib packaging failed" }

Write-Host ""
Write-Host "Built $LibPath"

# wg_windows_tun.exe: Wintun-backed CLI tunnel host on top of libwg.lib.
$TunObj = Join-Path $OutDir "wg_windows_tun.obj"
$TunExe = Join-Path $OutDir "wg_windows_tun.exe"
Write-Host "  CC  wg_windows_tun.c"
cmd /c "`"$VcVars`" >nul && cl $CommonArgs `"$Src\wg_windows_tun.c`" /Fo:`"$TunObj`""
if ($LASTEXITCODE -ne 0) { throw "Compile failed: wg_windows_tun.c" }
Write-Host "  LINK wg_windows_tun.exe"
cmd /c "`"$VcVars`" >nul && link /nologo `"$TunObj`" `"$LibPath`" ws2_32.lib iphlpapi.lib /OUT:`"$TunExe`""
if ($LASTEXITCODE -ne 0) { throw "Link failed: wg_windows_tun.exe" }
Write-Host "Built $TunExe"

# wg_windows_keygen.exe: genkey/pubkey/genpsk, used by scripts/join-windows.ps1.
$KeygenObj = Join-Path $OutDir "wg_windows_keygen.obj"
$KeygenExe = Join-Path $OutDir "wg_windows_keygen.exe"
Write-Host "  CC  wg_windows_keygen.c"
cmd /c "`"$VcVars`" >nul && cl $CommonArgs `"$Src\wg_windows_keygen.c`" /Fo:`"$KeygenObj`""
if ($LASTEXITCODE -ne 0) { throw "Compile failed: wg_windows_keygen.c" }
Write-Host "  LINK wg_windows_keygen.exe"
cmd /c "`"$VcVars`" >nul && link /nologo `"$KeygenObj`" `"$LibPath`" /OUT:`"$KeygenExe`""
if ($LASTEXITCODE -ne 0) { throw "Link failed: wg_windows_keygen.exe" }
Write-Host "Built $KeygenExe"
Write-Host "  (needs wintun.dll from https://www.wintun.net next to the exe, and admin elevation, to actually run)"

if ($Test) {
    $TestObj = Join-Path $OutDir "crypto_vector_test.obj"
    $TestExe = Join-Path $OutDir "crypto_vector_test.exe"
    Write-Host "  CC  crypto_vector_test.c"
    cmd /c "`"$VcVars`" >nul && cl $CommonArgs `"$Src\crypto_vector_test.c`" /Fo:`"$TestObj`""
    if ($LASTEXITCODE -ne 0) { throw "Compile failed: crypto_vector_test.c" }
    Write-Host "  LINK crypto_vector_test.exe"
    cmd /c "`"$VcVars`" >nul && link /nologo `"$TestObj`" `"$LibPath`" ws2_32.lib /OUT:`"$TestExe`""
    if ($LASTEXITCODE -ne 0) { throw "Link failed: crypto_vector_test.exe" }
    Write-Host ""
    & $TestExe
    if ($LASTEXITCODE -ne 0) { throw "crypto_vector_test.exe reported failures" }
}
