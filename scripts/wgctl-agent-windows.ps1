# SPDX-License-Identifier: MIT
#
# wgctl-agent-windows.ps1 — periodic device-side status reporter.
#
# Windows counterpart to scripts/wgctl-agent.sh (macOS/Linux). Scoped
# down from that script's full feature set (no long-poll, no wgctl-show
# stats/status roster — there's no query API into a running
# wg_windows_tun.exe yet, so heartbeats go out with lan_addrs only,
# which the protocol marks optional-but-useful for "is device alive").
# Each invocation, for every config\*.json state file:
#
#   1. POST /v1/heartbeat   (best-effort; lets admin UI show last-seen)
#   2. GET  /v1/peers       (plain poll, not long-poll — see below)
#   3. If the peer list changed, rewrite config\<iface>.conf
#      NOTE: this does NOT restart wg_windows_tun.exe. There's no
#      hot-reload wired into it yet, so a changed conf needs a manual
#      restart to take effect — same limitation as today, just not
#      hidden. This avoids an elevated restart firing unattended on a
#      timer when nobody's around to click the UAC prompt.
#   4. If the server returns 401 for an invalid/expired token: log and
#      leave the state alone (unlike wgctl-agent.sh, this does NOT
#      auto-delete local state — losing config silently on a Windows
#      dev box is more disruptive than on a managed macOS/Linux fleet
#      box; a human should decide whether to re-join).
#
# Fail-soft: any request failure just logs and leaves existing state
# alone; nothing here can take the (already-running) tunnel down.
#
# Meant to be invoked periodically by Task Scheduler — see
# scripts/install-agent-task.ps1 to register it. Needs NO elevation:
# heartbeat/peers are plain HTTPS calls, unlike adapter creation.
#
# Usage:
#   powershell -File scripts/wgctl-agent-windows.ps1 [-ConfigDir <dir>]

param(
    [string]$ConfigDir
)

$RepoRoot = Split-Path -Parent $PSScriptRoot
if (-not $ConfigDir) { $ConfigDir = Join-Path $RepoRoot "config" }
$LogPath = Join-Path $ConfigDir "wgctl-agent.log"

function Write-AgentLog {
    param([string]$Message)
    $line = "$(Get-Date -AsUTC -Format 'yyyy-MM-ddTHH:mm:ssZ') $Message"
    Add-Content -Path $LogPath -Value $line
}

if (-not (Test-Path $ConfigDir)) {
    Write-AgentLog "no config dir at $ConfigDir; nothing to do"
    return
}

$stateFiles = Get-ChildItem -Path $ConfigDir -Filter "*.json" -ErrorAction SilentlyContinue
if (-not $stateFiles) {
    Write-AgentLog "no state files in $ConfigDir; nothing to do"
    return
}

# LAN facts — same collection as join-windows.ps1, used to detect roam.
$LanAddrs = @()
Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {
    $ip = $_.IPAddress
    if ($ip.StartsWith("127.") -or $ip.StartsWith("169.254.")) { return }
    if ($_.PrefixOrigin -eq "WellKnown") { return }
    $LanAddrs += [ordered]@{
        iface = $_.InterfaceAlias
        cidr  = "$ip/$($_.PrefixLength)"
    }
}

foreach ($stateFile in $stateFiles) {
    $iface = $stateFile.BaseName
    try {
        $state = Get-Content $stateFile.FullName -Raw | ConvertFrom-Json
    } catch {
        Write-AgentLog "[$iface] unreadable state file, skipping: $($_.Exception.Message)"
        continue
    }

    $server   = ($state.server) -replace '/$', ''
    $deviceId = $state.device_id
    $token    = $state.token
    if (-not $server -or -not $deviceId -or -not $token) {
        Write-AgentLog "[$iface] state missing server/device_id/token, skipping"
        continue
    }

    # ── 1. heartbeat ─────────────────────────────────────────────────────
    $hbBody = @{
        device_id  = $deviceId
        lan_addrs  = $LanAddrs
    } | ConvertTo-Json -Depth 5 -Compress

    $hbStatus = $null
    $hbBodyBack = $null
    try {
        Invoke-RestMethod -Uri "$server/v1/heartbeat" -Method Post `
            -Headers @{ Authorization = "Bearer $token"; "X-Device-Id" = $deviceId } `
            -ContentType "application/json" -Body $hbBody -TimeoutSec 10 | Out-Null
        $hbStatus = 200
    } catch {
        if ($_.Exception.Response) {
            $hbStatus = [int]$_.Exception.Response.StatusCode
            try {
                $stream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($stream)
                $hbBodyBack = $reader.ReadToEnd()
            } catch {}
        }
        Write-AgentLog "[$iface] heartbeat failed: $($_.Exception.Message)"
    }

    if ($hbStatus -eq 401) {
        Write-AgentLog "[$iface] heartbeat 401 (token invalid/expired): $hbBodyBack -- leaving local state as-is, re-join manually if needed"
    }

    # ── 2. peer refresh (plain poll — no long-poll in this first pass) ──
    $peersResp = $null
    try {
        $peersResp = Invoke-RestMethod -Uri "$server/v1/peers" -Method Get `
            -Headers @{ Authorization = "Bearer $token"; "X-Device-Id" = $deviceId } `
            -TimeoutSec 15
    } catch {
        Write-AgentLog "[$iface] peers fetch failed: $($_.Exception.Message)"
        continue
    }

    # ── 3. rewrite conf if changed ───────────────────────────────────────
    $confPath = Join-Path $ConfigDir "$iface.conf"
    if (-not (Test-Path $confPath)) {
        Write-AgentLog "[$iface] no existing conf at $confPath, skipping render"
        continue
    }
    $existingLines = Get-Content $confPath
    $privLine = $existingLines | Where-Object { $_ -match '^PrivateKey' } | Select-Object -First 1
    $listenLine = $existingLines | Where-Object { $_ -match '^ListenPort' } | Select-Object -First 1
    if (-not $privLine) {
        Write-AgentLog "[$iface] existing conf has no PrivateKey line, refusing to rewrite"
        continue
    }

    $newLines = @(
        "[Interface]"
        $privLine
        "Address    = $($peersResp.device_ip)/32"
        $(if ($listenLine) { $listenLine } else { "ListenPort = 51820" })
        ""
    )
    $keepalive = if ($peersResp.keepalive_sec) { $peersResp.keepalive_sec } else { 25 }
    foreach ($p in $peersResp.peers) {
        $aips = New-Object System.Collections.Generic.List[string]
        if ($p.wg_ip) { $aips.Add("$($p.wg_ip)/32") }
        if ($p.allowed_extra) { $p.allowed_extra | ForEach-Object { $aips.Add($_) } }
        $newLines += @(
            "[Peer]"
            "PublicKey  = $($p.pubkey)"
            "Endpoint   = $($p.endpoint)"
            "AllowedIPs = $($aips -join ', ')"
            "PersistentKeepalive = $keepalive"
            ""
        )
    }

    $oldContent = ($existingLines -join "`n").Trim()
    $newContent = ($newLines -join "`n").Trim()
    if ($oldContent -ne $newContent) {
        [System.IO.File]::WriteAllLines($confPath, $newLines)
        Write-AgentLog "[$iface] peer list changed, rewrote $confPath -- restart wg_windows_tun.exe to pick it up"
    } else {
        Write-AgentLog "[$iface] tick ok: heartbeat=$hbStatus peers=unchanged ($($peersResp.peers.Count) peer(s))"
    }
}
