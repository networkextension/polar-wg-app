# SPDX-License-Identifier: MIT
#
# join-windows.ps1 — onboard a Windows host into the mesh.
#
# Windows peer to scripts/join.sh (macOS) / scripts/join-linux.sh. The
# control-plane HTTP protocol is identical — see doc/JOIN_PROTOCOL.md and
# the live install script served at <server>/v1/install — only the host
# integration differs:
#
#   macOS join.sh             Windows join-windows.ps1
#   ────────────────────      ─────────────────────────────────────
#   wgctl genkey/pubkey    →  wg_windows_keygen.exe genkey/pubkey
#   scutil / ifconfig      →  $env:COMPUTERNAME / Get-NetIPAddress
#   /etc/wireguard/*.conf  →  -OutDir\<iface>.conf (default: repo config\)
#   /etc/wgctl/*.json      →  -OutDir\<iface>.json
#   launchd bootstrap      →  NOT done here — run wg_windows_tun.exe
#                              elevated against the rendered conf yourself
#
# There is no bundle download step: this repo already builds its own
# Windows binaries (build-windows.ps1), so we skip straight to keygen +
# register + render, matching the "core first" incremental approach used
# for the rest of the Windows port.
#
# Usage:
#   powershell -File scripts/join-windows.ps1 -Token polar_wg_xxxxxxxx
#
# Optional params: -Server, -Hostname, -Site, -HostId, -Iface, -Listen, -OutDir

param(
    [Parameter(Mandatory = $true)]
    [string]$Token,

    [string]$Server = "https://wg.4950.store:2443",
    [string]$Hostname,
    [string]$Site = "",
    [string]$HostId = "",
    [string]$Iface = "wgc0",
    [int]$Listen = 51820,
    [string]$OutDir
)

$ErrorActionPreference = "Stop"

$RepoRoot  = Split-Path -Parent $PSScriptRoot
$KeygenExe = Join-Path $RepoRoot "build\win\wg_windows_keygen.exe"
if (-not (Test-Path $KeygenExe)) {
    throw "wg_windows_keygen.exe not found at $KeygenExe — run scripts\build-windows.ps1 first"
}
if (-not $OutDir) { $OutDir = Join-Path $RepoRoot "config" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$Server = $Server.TrimEnd('/')

# Token prefix sanity (mirror of join.sh / join-linux.sh) — this is a
# best-effort local check; the server is the final arbiter.
if ($Token -notlike "polar_wg_*") {
    Write-Warning "token does not start with polar_wg_ — proceeding anyway, server will be the final arbiter"
}

# ── 1. generate keypair ─────────────────────────────────────────────────────
Write-Host "==> generating Curve25519 keypair"
$Priv = & $KeygenExe genkey
$Pub  = & $KeygenExe pubkey $Priv
if (-not $Priv -or -not $Pub) { throw "keygen failed" }

# ── 2. collect facts ─────────────────────────────────────────────────────────
$HostnameReport = if ($Hostname) { $Hostname } else { $env:COMPUTERNAME }

$Arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { "amd64" }
    "ARM64" { "arm64" }
    "x86"   { "386" }
    default { $env:PROCESSOR_ARCHITECTURE.ToLower() }
}

$GitSha = try {
    (git -C $RepoRoot rev-parse --short HEAD 2>$null)
} catch { $null }
$AgentVer = "wg-windows-port-$(if ($GitSha) { $GitSha } else { 'dev' })"

Write-Host "==> collecting LAN interfaces"
$LanAddrs = @()
Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {
    $ip = $_.IPAddress
    if ($ip.StartsWith("127.") -or $ip.StartsWith("169.254.")) { return }
    if ($_.PrefixOrigin -eq "WellKnown") { return }  # skip loopback-ish autoconf
    $LanAddrs += [ordered]@{
        iface = $_.InterfaceAlias
        cidr  = "$ip/$($_.PrefixLength)"
    }
}

# ── 3. register ──────────────────────────────────────────────────────────────
Write-Host "==> registering with control plane $Server"

$body = [ordered]@{
    token     = $Token
    pubkey    = $Pub
    hostname  = $HostnameReport
    os        = "windows"
    arch      = $Arch
    agent_ver = $AgentVer
    lan_addrs = $LanAddrs
    wg_listen = $Listen
    site_slug = $Site
}
if ($HostId) { $body["host_id"] = $HostId }

$json = $body | ConvertTo-Json -Depth 5 -Compress

try {
    $resp = Invoke-RestMethod -Uri "$Server/v1/register" -Method Post `
        -ContentType "application/json" -Body $json -TimeoutSec 60
} catch {
    $errBody = $null
    if ($_.Exception.Response) {
        try {
            $stream = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($stream)
            $errBody = $reader.ReadToEnd()
        } catch {}
    }
    Write-Error "register failed: $($_.Exception.Message)"
    if ($errBody) { Write-Error "response body: $errBody" }
    throw
}

# ── 4. render <iface>.conf + <iface>.json ───────────────────────────────────
$ConfPath  = Join-Path $OutDir "$Iface.conf"
$StatePath = Join-Path $OutDir "$Iface.json"

Write-Host "==> rendering $ConfPath"
$lines = @(
    "[Interface]"
    "PrivateKey = $Priv"
    "Address    = $($resp.device_ip)/32"
    "ListenPort = $Listen"
    ""
)
foreach ($p in $resp.peers) {
    $aips = New-Object System.Collections.Generic.List[string]
    if ($p.wg_ip) { $aips.Add("$($p.wg_ip)/32") }
    if ($p.allowed_extra) { $p.allowed_extra | ForEach-Object { $aips.Add($_) } }
    $keepalive = if ($resp.keepalive_sec) { $resp.keepalive_sec } else { 25 }
    $lines += @(
        "[Peer]"
        "PublicKey  = $($p.pubkey)"
        "Endpoint   = $($p.endpoint)"
        "AllowedIPs = $($aips -join ', ')"
        "PersistentKeepalive = $keepalive"
        ""
    )
}
[System.IO.File]::WriteAllLines($ConfPath, $lines)

$state = [ordered]@{
    server         = $Server
    device_id      = $resp.device_id
    token          = $Token
    token_expires  = $resp.token_expires
    wg_ip          = $resp.device_ip
    site_id        = $resp.site_id
    role           = $resp.role
    iface          = $Iface
    wg_listen      = $Listen
}
$state | ConvertTo-Json -Depth 5 | Set-Content -Path $StatePath -Encoding utf8

# ── 5. summary ───────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  joined mesh"
Write-Host "    device_ip: $($resp.device_ip)"
Write-Host "    role:      $($resp.role)"
Write-Host "    iface:     $Iface"
Write-Host "    server:    $Server"
Write-Host "    conf:      $ConfPath"
Write-Host "    state:     $StatePath"
Write-Host ""
Write-Host "  To bring the tunnel up (needs wintun.dll from wintun.net next to the"
Write-Host "  exe, and an elevated/admin shell):"
Write-Host "    build\win\wg_windows_tun.exe `"$ConfPath`""
