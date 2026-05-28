#!/bin/bash
# wgctl-agent — periodic device-side reconciler.
#
# Multi-iface design: state lives in /etc/wgctl/<iface>.json (one file
# per mesh membership). Each iface gets independent heartbeat + peer
# refresh; revoking one token only takes that iface down, the rest
# keep running.
#
# Invoked by launchd every refresh_sec seconds (default 60). Per
# iface, each run:
#   1. POST /v1/heartbeat   (best-effort; lets admin UI show last-seen)
#   2. GET  /v1/peers       (or /v1/hub/peers if role==hub)
#   3. Render a fresh /etc/wireguard/<iface>.conf from the response
#   4. If conf changed, launchctl kickstart -k to pick up new peers
#   5. If server returns 401 invalid_device_token: self-evict THIS iface
#      (bootout + delete conf + delete state; don't touch siblings)
#
# Fail-soft: a bad server response leaves the existing conf alone;
# wg_core keeps running with the last good peer list. Only an explicit
# auth-rejected response triggers eviction.
#
# Run: /usr/local/sbin/wgctl-agent
# Logs: /var/log/wgctl-agent.log

set -u

STATE_DIR=/etc/wgctl
LOG=/var/log/wgctl-agent.log

log() {
    printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$LOG"
}

die() {
    log "ERROR $*"
    exit 1
}

[[ $EUID -eq 0 ]] || die "must run as root"

# ── host-level facts (same for every iface this tick; see doc/hub-status.md) ──
HOST_OS=$(uname -s | tr '[:upper:]' '[:lower:]')   # darwin / linux / freebsd
case "$(uname -m)" in
    x86_64|amd64)  HOST_ARCH=amd64 ;;
    arm64|aarch64) HOST_ARCH=arm64 ;;
    *)             HOST_ARCH=$(uname -m) ;;
esac
# Host uptime in seconds (best-effort; emitted as null when unknown).
if [[ -r /proc/uptime ]]; then
    HOST_UPTIME=$(cut -d. -f1 /proc/uptime)        # Linux
else
    _boot=$(sysctl -n kern.boottime 2>/dev/null | sed -n 's/.*sec = \([0-9]*\).*/\1/p')
    [[ -n "$_boot" ]] && HOST_UPTIME=$(( $(date +%s) - _boot )) || HOST_UPTIME=""
fi
# Agent version: bundle leaves it here at install; "unknown" otherwise.
AGENT_VER=$(cat /usr/local/share/wg-mac/VERSION 2>/dev/null | head -1)
[[ -n "$AGENT_VER" ]] || AGENT_VER="unknown"

# Migration: old single-file layout /etc/wgctl/config.json gets
# renamed to /etc/wgctl/<iface>.json (iface from inside, default wgc0).
if [[ -f "$STATE_DIR/config.json" ]]; then
    legacy_iface=$(python3 -c "
import json,sys
try:
    print(json.load(open('$STATE_DIR/config.json')).get('iface','wgc0'))
except Exception:
    print('wgc0')
")
    if [[ ! -f "$STATE_DIR/$legacy_iface.json" ]]; then
        mv "$STATE_DIR/config.json" "$STATE_DIR/$legacy_iface.json"
        log "migrated config.json -> $legacy_iface.json"
    else
        rm -f "$STATE_DIR/config.json"
    fi
fi

# Defensive route reconcile — runs unconditionally each tick (called both
# from the no-state-files early-exit and after process_iface). wg_core
# installs AllowedIPs routes at startup, but macOS occasionally flushes
# utun routes (sleep/wake, primary-iface flip). Idempotent: existing
# routes are left alone, missing or stale ones are re-installed.
# Decoupled from /etc/wgctl/*.json so a hub bootstrapped manually (no
# register flow, no state file) still gets this coverage.
reconcile_routes() {
    shopt -s nullglob
    for conf in /etc/wireguard/*.conf; do
        local iface; iface=$(basename "$conf" .conf)
        local hook="/etc/wireguard/$iface.postup"
        [[ -x "$hook" ]] || continue
        "$hook" "$iface" "$conf" >>"$LOG" 2>&1 || true
    done
}

# Walk every state file. /etc/wgctl/<iface>.json is the canonical form.
shopt -s nullglob
state_files=("$STATE_DIR"/*.json)
if [[ ${#state_files[@]} -eq 0 ]]; then
    # No mesh memberships → skip heartbeat/peer-refresh, but still run
    # the route reconcile pass: a host can be on a wg iface without
    # going through /v1/register (manually-configured hub, legacy
    # install). Reconcile is cheap and noop-on-good-state.
    log "no state files in $STATE_DIR; route-reconcile only"
    reconcile_routes
    exit 0
fi

# --- per-iface reconcile loop ---
process_iface() {
    local STATE="$1"
    local IFACE
    IFACE=$(basename "$STATE" .json)

    read -r SERVER DEVICE_ID TOKEN ROLE WG_LISTEN <<< "$(python3 - <<PY "$STATE"
import json, sys
c = json.load(open(sys.argv[1]))
print(c.get("server","").rstrip("/"),
      c.get("device_id",""),
      c.get("token",""),
      c.get("role","device"),
      c.get("wg_listen", 1632))
PY
)"

    if [[ -z "$SERVER" || -z "$DEVICE_ID" || -z "$TOKEN" ]]; then
        log "[$IFACE] state missing server/device_id/token; skipping"
        return
    fi

    # ----- wg stats + per-peer status for heartbeat (doc/hub-status.md) -----
    # One pass over `wgctl show <iface>` builds both the legacy aggregate
    # `stats` and the v2 `status` block (per-peer roster). For a hub this
    # roster is the authoritative "who's online" view of the whole mesh.
    local SHOW STATUS_JSON
    SHOW=""
    [[ -x /usr/local/bin/wgctl ]] && SHOW=$(/usr/local/bin/wgctl show "$IFACE" 2>/dev/null)
    STATUS_JSON=$(SHOW="$SHOW" ROLE="$ROLE" IFACE="$IFACE" WG_LISTEN="$WG_LISTEN" \
                  HOST_OS="$HOST_OS" HOST_ARCH="$HOST_ARCH" \
                  HOST_UPTIME="$HOST_UPTIME" AGENT_VER="$AGENT_VER" \
                  python3 - <<'PY'
import os, re, json
show = os.environ.get("SHOW", "")
UNIT = {'B':1, 'KiB':1024, 'MiB':1024**2, 'GiB':1024**3, 'TiB':1024**4}
def toB(n, u): return int(float(n) * UNIT.get(u, 1))

peers, cur = [], None
for raw in show.splitlines():
    s = raw.strip()
    m = re.match(r'peer:\s+(\S+)', s)
    if m:
        cur = {"pubkey": m.group(1), "wg_ip": None, "endpoint": None,
               "last_handshake_sec": None, "rx_bytes": 0, "tx_bytes": 0,
               "online": False}
        peers.append(cur); continue
    if cur is None:
        continue
    m = re.match(r'endpoint:\s+(\S+)', s)
    if m: cur["endpoint"] = m.group(1); continue
    m = re.match(r'allowed ips:\s+(.+)', s)
    if m: cur["wg_ip"] = m.group(1).split(',')[0].strip().split('/')[0]; continue
    m = re.match(r'latest handshake:\s+(.+) ago', s)
    if m:
        sec = 0
        for val, unit in re.findall(r'(\d+)\s+(day|hour|minute|second)', m.group(1)):
            sec += {'day':86400,'hour':3600,'minute':60,'second':1}[unit] * int(val)
        cur["last_handshake_sec"] = sec; continue
    m = re.match(r'transfer:\s+([0-9.]+)\s+(\w+)\s+received,\s+([0-9.]+)\s+(\w+)\s+sent', s)
    if m:
        cur["rx_bytes"] = toB(m.group(1), m.group(2))
        cur["tx_bytes"] = toB(m.group(3), m.group(4)); continue

for p in peers:
    h = p["last_handshake_sec"]
    p["online"] = h is not None and h < 180

ages = [p["last_handshake_sec"] for p in peers if p["last_handshake_sec"] is not None]
stats = {"rx_bytes": sum(p["rx_bytes"] for p in peers),
         "tx_bytes": sum(p["tx_bytes"] for p in peers),
         "last_handshake_sec": min(ages) if ages else 0}
up = os.environ.get("HOST_UPTIME", "")
status = {"schema": 1,
          "role": os.environ.get("ROLE", "device"),
          "os": os.environ.get("HOST_OS", ""),
          "arch": os.environ.get("HOST_ARCH", ""),
          "agent_ver": os.environ.get("AGENT_VER", "unknown"),
          "iface": os.environ.get("IFACE", ""),
          "iface_up": bool(show.strip()),
          "uptime_sec": int(up) if up.isdigit() else None,
          "wg_listen": int(os.environ.get("WG_LISTEN") or 1632),
          "peer_count": len(peers),
          "peers_online": sum(1 for p in peers if p["online"]),
          "peers": peers}
print(json.dumps({"stats": stats, "status": status}))
PY
)
    [[ -n "$STATUS_JSON" ]] || STATUS_JSON='{"stats":{},"status":{}}'

    # ----- public endpoint guess from default route -----
    local DEF_IF PUB_IP WG_ENDPOINT
    DEF_IF=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
    PUB_IP=$(ifconfig "$DEF_IF" 2>/dev/null | awk '/inet /{print $2; exit}')
    WG_ENDPOINT="${PUB_IP:-}:${WG_LISTEN}"

    local LAN_JSON
    LAN_JSON=$(python3 - <<'PY'
import json, subprocess, re
out = subprocess.check_output(["/sbin/ifconfig"], text=True)
addrs, iface = [], ""
for line in out.splitlines():
    m = re.match(r"^([a-z0-9]+):", line)
    if m: iface = m.group(1); continue
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)\s+netmask\s+0x([0-9a-fA-F]+)", line)
    if not m: continue
    ip, hexmask = m.group(1), m.group(2)
    # Skip loopback, link-local, and our own wg subnet (10.88.x is the
    # mesh; reporting it back as a LAN would confuse site detection).
    if ip.startswith("127.") or ip.startswith("169.254.") or ip.startswith("10.88."):
        continue
    bits = bin(int(hexmask, 16)).count("1")
    addrs.append({"iface": iface, "cidr": f"{ip}/{bits}"})
print(json.dumps(addrs))
PY
)

    # ----- 1. heartbeat -----
    local HB_BODY HB_STATUS HB_RESP
    HB_BODY=$(STATUS_JSON="$STATUS_JSON" LAN_JSON="$LAN_JSON" WG_ENDPOINT="$WG_ENDPOINT" \
              python3 - <<'PY'
import os, json
combo = json.loads(os.environ["STATUS_JSON"])
print(json.dumps({
  "lan_addrs":   json.loads(os.environ["LAN_JSON"]),
  "wg_endpoint": os.environ["WG_ENDPOINT"],
  "stats":       combo.get("stats", {}),
  "status":      combo.get("status", {}),
}))
PY
)
    HB_RESP=$(mktemp)
    HB_STATUS=$(curl -sS -o "$HB_RESP" -w '%{http_code}' --max-time 10 \
        -X POST "$SERVER/v1/heartbeat" \
        -H "Authorization: Bearer $TOKEN" \
        -H "X-Device-Id: $DEVICE_ID" \
        -H 'Content-Type: application/json' \
        -d "$HB_BODY" 2>>"$LOG" || echo "000")
    local HB_BODY_BACK
    HB_BODY_BACK=$(cat "$HB_RESP" 2>/dev/null)
    rm -f "$HB_RESP"
    if [[ "$HB_STATUS" != "200" ]]; then
        log "[$IFACE] heartbeat HTTP $HB_STATUS: $(printf '%s' "$HB_BODY_BACK" | head -c 200)"
    fi

    # ----- 2. policy: server-rejected token → evict THIS iface -----
    if [[ "$HB_STATUS" == "401" ]] && \
       echo "$HB_BODY_BACK" | grep -qE 'invalid device token|token expired|token does not match'; then
        log "[$IFACE] EVICT: server rejected token; tearing down"
        launchctl bootout system/com.wireguard.wg-mac."$IFACE" 2>>"$LOG" || true
        launchctl disable system/com.wireguard.wg-mac."$IFACE" 2>>"$LOG" || true
        rm -f "/etc/wireguard/$IFACE.conf"
        rm -f "/var/run/wireguard/$IFACE.pid" \
              "/var/run/wireguard/$IFACE.sock" \
              "/var/run/wireguard/$IFACE.name"
        rm -f "$STATE"
        # Don't touch other ifaces or the agent itself — siblings keep
        # running. Agent will see one fewer state file next tick.
        log "[$IFACE] EVICT: done"
        return
    fi

    # ----- 3. peer list refresh -----
    case "$ROLE" in
        hub) PEER_URL="$SERVER/v1/hub/peers" ;;
        *)   PEER_URL="$SERVER/v1/peers" ;;
    esac

    local PEER_RESP PEER_STATUS
    PEER_RESP=$(mktemp)
    PEER_STATUS=$(curl -sS -o "$PEER_RESP" -w '%{http_code}' --max-time 10 \
        "$PEER_URL" \
        -H "Authorization: Bearer $TOKEN" \
        -H "X-Device-Id: $DEVICE_ID" 2>>"$LOG" || echo "000")
    if [[ "$PEER_STATUS" != "200" ]]; then
        log "[$IFACE] peers HTTP $PEER_STATUS: $(cat "$PEER_RESP" 2>/dev/null | head -c 200)"
        rm -f "$PEER_RESP"
        return
    fi

    # ----- 4. render fresh conf -----
    local NEW_CONF
    NEW_CONF=$(mktemp)
    python3 - <<PY "$NEW_CONF" "$PEER_RESP" "/etc/wireguard/$IFACE.conf" "$ROLE"
import json, sys
out_path, resp_path, conf_path, role = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
priv = addr = listen = ""
try:
    for line in open(conf_path):
        line = line.strip()
        if line.startswith("PrivateKey"): priv = line.split("=",1)[1].strip()
        elif line.startswith("Address"):  addr = line.split("=",1)[1].strip()
        elif line.startswith("ListenPort"): listen = line.split("=",1)[1].strip()
except FileNotFoundError:
    sys.exit("conf not found")
if not priv:
    sys.exit("priv key missing from existing conf")
resp = json.load(open(resp_path))

lines = [
    "[Interface]",
    f"PrivateKey = {priv}",
    f"Address    = {addr or resp.get('device_ip','') + '/24'}",
    f"ListenPort = {listen or '1632'}",
    "",
]
keepalive = resp.get("keepalive_sec", 25)
for p in resp.get("peers", []):
    pub = p.get("pubkey", "")
    if not pub: continue
    aips = []
    if p.get("wg_ip"):
        wgip = p["wg_ip"]
        aips.append(wgip if "/" in wgip else wgip + "/32")
    for e in (p.get("allowed_extra") or []):
        aips.append(e)
    if not aips: continue
    lines.append("[Peer]")
    lines.append(f"PublicKey  = {pub}")
    if p.get("endpoint"):
        lines.append(f"Endpoint   = {p['endpoint']}")
    lines.append(f"AllowedIPs = {', '.join(aips)}")
    if keepalive:
        lines.append(f"PersistentKeepalive = {keepalive}")
    lines.append("")
open(out_path, "w").write("\n".join(lines))
PY

    local CUR_CONF="/etc/wireguard/$IFACE.conf"
    if [[ -f "$CUR_CONF" ]] && cmp -s "$NEW_CONF" "$CUR_CONF"; then
        :
    else
        install -m 0600 "$NEW_CONF" "$CUR_CONF"
        log "[$IFACE] conf changed; kickstart wg-mac.$IFACE"
        launchctl kickstart -k "system/com.wireguard.wg-mac.$IFACE" 2>>"$LOG" || true
    fi
    rm -f "$NEW_CONF" "$PEER_RESP"
}

for s in "${state_files[@]}"; do
    process_iface "$s"
done

# After peer-refresh has had a chance to install a fresh conf, walk every
# wg iface on the host and reconcile its routes. Runs unconditionally.
reconcile_routes
