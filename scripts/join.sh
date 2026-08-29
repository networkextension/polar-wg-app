#!/bin/bash
# wg-mac join — onboard a new device into a tailscale-style mesh.
#
# Served by the Polar control plane at GET /v1/install, with the
# __SERVER_PLACEHOLDER__ string substituted to the server's public URL.
#
# Usage:
#   curl -sSL https://join.example/v1/install | sudo bash -s -- --token=<TOKEN>
#
# Optional args:
#   --hostname=NAME    override the registered hostname (default: scutil/hostname)
#   --listen=PORT      override wg UDP listen port (default: 1632)
#   --iface=NAME       force a logical iface name (default: next-free wgcN)
#   --force            with --iface, overwrite an existing iface non-interactively
#   --reinstall        re-register the SAME token (dev only; re-consumes it)
#
# Identity model (read this before touching the iface logic):
#   A token is consumed exactly once, at /v1/register. After that the device
#   is a member and everything ongoing is heartbeat + peer sync handled by
#   wgctl-agent — there is no "re-join". So:
#     • Same token, already registered on this host  → refuse (it's a bug;
#       re-running would try to re-consume an already-spent token).
#     • A different token                            → a *different* hub /
#       membership → allocate the NEXT-FREE wgcN, never clobber an existing
#       iface. Each membership is its own /etc/wgctl/<iface>.json.
#
# What it does, in order:
#   1. refuse early if this token is already registered here
#   2. pick the iface (next-free wgcN, or --iface)
#   3. download <server>/v1/bundle and run install.sh (version-aware; will
#      NOT overwrite up-to-date binaries, NOT restart other live tunnels)
#   4. generate a Curve25519 keypair locally; private key never leaves the box
#   5. POST <server>/v1/register
#   6. render /etc/wireguard/<iface>.conf + /etc/wgctl/<iface>.json
#   7. bootstrap ONLY this iface's launchd daemon
#
# Base system only — no python3. /usr/bin/python3 is a Command Line Tools
# *stub*: on a Mac without Xcode CLT it prints "No developer tools were
# found" and exits non-zero, which made this script unrunnable on a stock
# macOS install. JSON is read with plutil(1) and written with printf.

set -euo pipefail

# ── parse args ───────────────────────────────────────────────────────────────
SERVER="__SERVER_PLACEHOLDER__"
TOKEN=""
HOSTNAME_OVERRIDE=""
SITE_SLUG=""
WG_LISTEN=1632
IFACE=""          # empty → auto-allocate next-free wgcN
FORCE=0
REINSTALL=0
HOST_ID=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --token=*)    TOKEN="${1#*=}";;
        --hostname=*) HOSTNAME_OVERRIDE="${1#*=}";;
        --site=*)     SITE_SLUG="${1#*=}";;
        --listen=*)   WG_LISTEN="${1#*=}";;
        --iface=*)    IFACE="${1#*=}";;
        --force)      FORCE=1;;
        --reinstall)  REINSTALL=1;;
        --server=*)   SERVER="${1#*=}";;   # offline test
        --host-id=*)  HOST_ID="${1#*=}";;
        *) echo "unknown arg: $1" >&2; exit 1;;
    esac
    shift
done

# host_id ties this wg device to its polar-hosts host row (wg↔hosts cross-link,
# stamped at register). Auto-read from the local polar-agent config if not given.
if [[ -z "$HOST_ID" ]]; then
    for cfg in "$HOME/.polar/agent.toml" /Users/*/.polar/agent.toml /var/root/.polar/agent.toml; do
        [[ -r "$cfg" ]] || continue
        HOST_ID=$(sed -n 's/^[[:space:]]*host_id[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$cfg" | head -1)
        [[ -n "$HOST_ID" ]] && { echo "==> using host_id from $cfg"; break; }
    done
fi
HOST_ID=$(printf '%s' "$HOST_ID" | tr -d '[:space:]')

[[ $EUID -eq 0 ]] || { echo "must run as root (use sudo bash)" >&2; exit 1; }
[[ -n "$TOKEN" ]] || { echo "--token=<TOKEN> required" >&2; exit 1; }
[[ "$WG_LISTEN" =~ ^[0-9]+$ ]] || { echo "--listen must be a port number" >&2; exit 1; }
[[ "$SERVER" != "__SERVER_PLACEHOLDER__" ]] || {
    echo "SERVER not set; this script must be served by control plane with __SERVER_PLACEHOLDER__ substituted, OR call with --server=https://..." >&2
    exit 1
}
SERVER="${SERVER%/}"

# Token prefix dispatch — redirect a pasted Tailscale key (see howto doc).
case "$TOKEN" in
    polar_wg_*) ;;  # native path, fall through
    tskey-*)
        cat >&2 <<TS
✗ This looks like a Tailscale PreAuthKey, not a wg-mac token.
  Polar dock issues both kinds; pick the one matching your client.

  To onboard with the official Tailscale client instead:

      brew install --cask tailscale
      sudo tailscale up --login-server=${SERVER} --authkey=${TOKEN}

  See ${SERVER}/v1/install for the wg-mac variant.
TS
        exit 2
        ;;
    *)
        echo "warning: token does not start with polar_wg_ — proceeding anyway, server will be the final arbiter" >&2
        ;;
esac

# ── JSON helpers (plutil + printf; no python) ────────────────────────────────
# plutil parses JSON natively and ships in the macOS base system.
#   jget   FILE KEYPATH → scalar at KEYPATH; "" when absent or JSON null
#   jcount FILE KEYPATH → element count of an array/dict; 0 when absent
#   json_esc STR        → STR escaped for use inside a JSON string literal
# `plutil -extract <array> raw` prints the element count, which is how jcount
# gets a length without a second parser.
# Gate on plutil's exit status, never on its output: macOS 14's plutil prints
# "Could not extract value ..." to *stdout* (macOS 26+ uses stderr), so a
# missing key would otherwise be substituted into the conf as if it were data.
jget() {
    local v
    v=$(plutil -extract "$2" raw -o - -- "$1" 2>/dev/null) || return 0
    printf '%s' "$v"
}
jcount() {
    local v
    v=$(plutil -extract "$2" raw -o - -- "$1" 2>/dev/null) || { printf 0; return 0; }
    case "$v" in ""|*[!0-9]*) printf 0;; *) printf '%s' "$v";; esac
}
json_esc() { printf '%s' "$1" | tr -d '[:cntrl:]' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }
# A JSON string literal, or bare null when the value is empty (matches what
# json.dumps(None) used to write into the state file).
json_str_or_null() {
    if [[ -n "$1" ]]; then printf '"%s"' "$(json_esc "$1")"; else printf 'null'; fi
}

# ── 0. identity: is this token already registered on this host? ───────────────
# A token is single-use. If we already hold a state file carrying it, this is
# a re-run (a bug), not a fresh join. Refuse — don't re-consume the token.
# Also handles the legacy single-file /etc/wgctl/config.json.
mkdir -p /etc/wgctl && chmod 0700 /etc/wgctl
TOKEN_IFACE=""
for st in /etc/wgctl/*.json; do
    [[ -f "$st" ]] || continue                      # unmatched glob
    [[ "$(jget "$st" token)" == "$TOKEN" ]] || continue
    # logical iface name = state's "iface" field, else the filename stem
    TOKEN_IFACE=$(jget "$st" iface)
    [[ -n "$TOKEN_IFACE" ]] || TOKEN_IFACE=$(basename "$st" .json)
    break
done

if [[ -n "$TOKEN_IFACE" && $REINSTALL -eq 0 ]]; then
    cat >&2 <<MSG
✗ This token is already registered on this host as iface "$TOKEN_IFACE".
  A join token is consumed once; re-running with the same token is a no-op
  (and would try to re-spend a used token). Ongoing peer sync is handled by
  wgctl-agent — nothing to re-run.

  • status:            sudo wgctl show $TOKEN_IFACE
  • join a DIFFERENT hub: re-run with that hub's own token (gets its own iface)
  • force re-register (dev only, re-consumes the token):  add --reinstall
MSG
    exit 3
fi

# ── 1. pick the iface ─────────────────────────────────────────────────────────
iface_in_use() {
    local n="$1"
    [[ -f "/etc/wgctl/$n.json" ]] && return 0
    [[ -f "/etc/wireguard/$n.conf" ]] && return 0
    launchctl print "system/com.wireguard.wg-mac.$n" >/dev/null 2>&1 && return 0
    return 1
}

if [[ $REINSTALL -eq 1 && -n "$TOKEN_IFACE" ]]; then
    # Re-register onto the same iface this token already owns.
    IFACE="${IFACE:-$TOKEN_IFACE}"
    echo "warning: --reinstall will re-register token on iface '$IFACE' and restart it" >&2
elif [[ -n "$IFACE" ]]; then
    # Explicit iface. If it already belongs to something else, ask/force.
    if iface_in_use "$IFACE"; then
        if [[ $FORCE -eq 1 ]]; then
            echo "warning: overwriting existing iface '$IFACE' (--force)" >&2
        elif [[ -r /dev/tty ]]; then
            printf "iface '%s' already exists — overwrite it? [y/N] " "$IFACE" > /dev/tty
            read -r ans < /dev/tty || ans=""
            [[ "$ans" =~ ^[Yy]$ ]] || { echo "aborted." >&2; exit 1; }
        else
            echo "✗ iface '$IFACE' already exists; pass --force to overwrite (non-interactive)" >&2
            exit 1
        fi
    fi
else
    # Auto-allocate the next-free wgcN so we never clobber an existing iface.
    n=0
    while iface_in_use "wgc$n"; do n=$((n+1)); done
    IFACE="wgc$n"
    echo "==> allocating iface $IFACE"
fi

STATE_FILE="/etc/wgctl/$IFACE.json"

# ── tmp workspace ────────────────────────────────────────────────────────────
TMP=$(mktemp -d /tmp/wg-mac-join.XXXXXX)
trap "rm -rf $TMP" EXIT
echo "==> workspace $TMP"

# ── 2. fetch + extract bundle ────────────────────────────────────────────────
echo "==> downloading bundle from $SERVER/v1/bundle"
curl -fsSL --retry 3 "$SERVER/v1/bundle" -o "$TMP/bundle.tar.gz"
mkdir -p "$TMP/wg-mac"
tar xzf "$TMP/bundle.tar.gz" -C "$TMP/wg-mac" --strip-components=1
test -x "$TMP/wg-mac/build/wgctl"   || { echo "bad bundle: no wgctl"   >&2; exit 1; }
test -x "$TMP/wg-mac/build/wg_core" || { echo "bad bundle: no wg_core" >&2; exit 1; }

# ── 3. install binaries via bundle's install.sh ──────────────────────────────
# Version-aware: install.sh skips an up-to-date install and never restarts a
# live tunnel. WG_NO_ENABLE=1: we render the conf ourselves and bootstrap below.
echo "==> ensuring binaries are installed (version-aware)"
WG_SKIP_BUILD=1 WG_NO_ENABLE=1 \
    bash "$TMP/wg-mac/scripts/install.sh" "$IFACE" >/dev/null

# ── 4. generate keypair ──────────────────────────────────────────────────────
echo "==> generating Curve25519 keypair"
PRIV=$(/usr/local/bin/wgctl genkey)
PUB=$(echo "$PRIV" | /usr/local/bin/wgctl pubkey)

# ── 5. collect lan_addrs ─────────────────────────────────────────────────────
HOSTNAME_REPORT="${HOSTNAME_OVERRIDE:-$(scutil --get LocalHostName 2>/dev/null || hostname -s)}"

# Skip loopback, link-local and our own mesh subnet — reporting 10.88.x back
# as a LAN would confuse server-side site detection. The netmask arrives as
# hex (0xffffff00), so the prefix length is a per-nibble popcount.
LAN_ADDRS_JSON=$(ifconfig | LC_ALL=C awk '
    BEGIN { split("0 1 1 2 1 2 2 3 1 2 2 3 2 3 3 4", pc); hex = "0123456789abcdef" }
    /^[a-z][a-z0-9]*:/ { iface = substr($1, 1, length($1) - 1); next }
    $1 == "inet" && $3 == "netmask" {
        ip = $2; mask = $4
        if (ip ~ /^127\./ || ip ~ /^169\.254\./ || ip ~ /^10\.88\./) next
        sub(/^0[xX]/, "", mask)
        bits = 0
        for (k = 1; k <= length(mask); k++)
            bits += pc[index(hex, tolower(substr(mask, k, 1)))]
        out = out (out == "" ? "" : ",") \
              "{\"iface\":\"" iface "\",\"cidr\":\"" ip "/" bits "\"}"
    }
    END { print "[" out "]" }')

AGENT_VER=$(cat "$TMP/wg-mac/VERSION" 2>/dev/null || echo "unknown")

ARCH_RAW=$(uname -m)
case "$ARCH_RAW" in
    x86_64|amd64)   ARCH=amd64 ;;
    arm64|aarch64)  ARCH=arm64 ;;
    *)              ARCH="$ARCH_RAW" ;;
esac

# ── 6. POST /v1/register ─────────────────────────────────────────────────────
echo "==> registering with control plane $SERVER"

# host_id cross-links to polar-hosts; the server stamps wg_devices.host_id.
HOST_ID_FIELD=""
if [[ -n "$HOST_ID" ]]; then
    HOST_ID_FIELD=$(printf ',"host_id":"%s"' "$(json_esc "$HOST_ID")")
fi

REQ_JSON=$(printf '{"token":"%s","pubkey":"%s","hostname":"%s","os":"darwin","arch":"%s","agent_ver":"%s","lan_addrs":%s,"wg_listen":%d,"site_slug":"%s"%s}' \
    "$(json_esc "$TOKEN")" "$(json_esc "$PUB")" "$(json_esc "$HOSTNAME_REPORT")" \
    "$(json_esc "$ARCH")" "$(json_esc "$AGENT_VER")" "$LAN_ADDRS_JSON" \
    "$WG_LISTEN" "$(json_esc "$SITE_SLUG")" "$HOST_ID_FIELD")

# Body to a file (plutil reads it below) and the status separately, so a
# rejected token shows the server's reason instead of a bare curl exit code.
RESP_FILE="$TMP/register.json"
HTTP=$(curl -sS --retry 3 --connect-timeout 15 --max-time 60 \
    -X POST "$SERVER/v1/register" \
    -H 'Content-Type: application/json' \
    -d "$REQ_JSON" -o "$RESP_FILE" -w '%{http_code}') || HTTP=000
if [[ ! "$HTTP" =~ ^2[0-9][0-9]$ ]]; then
    echo "✗ register failed (HTTP $HTTP)" >&2
    head -c 500 "$RESP_FILE" 2>/dev/null >&2; echo >&2
    exit 1
fi

# ── 7. render conf + per-iface state ──────────────────────────────────────────
echo "==> rendering /etc/wireguard/$IFACE.conf and $STATE_FILE"

DEVICE_IP=$(jget "$RESP_FILE" device_ip)
DEVICE_ID=$(jget "$RESP_FILE" device_id)
if [[ -z "$DEVICE_IP" || -z "$DEVICE_ID" ]]; then
    echo "✗ register response missing device_ip/device_id:" >&2
    head -c 500 "$RESP_FILE" >&2; echo >&2
    exit 1
fi
MESH_CIDR=$(jget "$RESP_FILE" mesh_cidr)
[[ -n "$MESH_CIDR" ]] || MESH_CIDR="10.88.0.0/24"
MESH_PREFIX="${MESH_CIDR##*/}"          # Address needs the mesh prefix, not /32
KEEPALIVE=$(jget "$RESP_FILE" keepalive_sec)
[[ -n "$KEEPALIVE" ]] || KEEPALIVE=25

# <iface>.conf — Address carries the mesh prefix (not /32) so wg_core installs
# the kernel route (see src/wg_core.c utun_apply_inet4). Default /24.
CONF_TMP=$(mktemp "/etc/wireguard/.$IFACE.conf.XXXXXX")
{
    echo "[Interface]"
    echo "PrivateKey = $PRIV"
    echo "Address    = $DEVICE_IP/$MESH_PREFIX"
    echo "ListenPort = $WG_LISTEN"
    NPEERS=$(jcount "$RESP_FILE" peers)
    p=0
    while [[ $p -lt $NPEERS ]]; do
        PUBKEY=$(jget "$RESP_FILE" "peers.$p.pubkey")
        if [[ -z "$PUBKEY" ]]; then p=$((p + 1)); continue; fi
        WGIP=$(jget "$RESP_FILE" "peers.$p.wg_ip")
        AIPS=""
        if [[ -n "$WGIP" ]]; then
            case "$WGIP" in */*) AIPS="$WGIP";; *) AIPS="$WGIP/32";; esac
        fi
        NEXTRA=$(jcount "$RESP_FILE" "peers.$p.allowed_extra")
        e=0
        while [[ $e -lt $NEXTRA ]]; do
            EXTRA=$(jget "$RESP_FILE" "peers.$p.allowed_extra.$e")
            if [[ -n "$EXTRA" ]]; then AIPS="${AIPS:+$AIPS, }$EXTRA"; fi
            e=$((e + 1))
        done
        # A peer with no AllowedIPs would be a no-op route; skip it rather than
        # emit a half-formed stanza. Same rules as wgctl-agent's re-render —
        # if the two disagree the agent rewrites this conf and kickstarts the
        # tunnel on every tick.
        if [[ -z "$AIPS" ]]; then p=$((p + 1)); continue; fi
        echo ""
        echo "[Peer]"
        echo "PublicKey  = $PUBKEY"
        ENDPOINT=$(jget "$RESP_FILE" "peers.$p.endpoint")
        if [[ -n "$ENDPOINT" ]]; then echo "Endpoint   = $ENDPOINT"; fi
        echo "AllowedIPs = $AIPS"
        if [[ "$KEEPALIVE" != "0" ]]; then echo "PersistentKeepalive = $KEEPALIVE"; fi
        p=$((p + 1))
    done
} > "$CONF_TMP"
chmod 0600 "$CONF_TMP"
mv -f "$CONF_TMP" "/etc/wireguard/$IFACE.conf"

# /etc/wgctl/<iface>.json — per-iface state (one file per membership).
ROLE=$(jget "$RESP_FILE" role)
[[ -n "$ROLE" ]] || ROLE=device
STATE_TMP=$(mktemp /etc/wgctl/.state.XXXXXX)
cat > "$STATE_TMP" <<EOF
{
  "server": "$(json_esc "$SERVER")",
  "device_id": "$(json_esc "$DEVICE_ID")",
  "token": "$(json_esc "$TOKEN")",
  "wg_ip": "$(json_esc "$DEVICE_IP")",
  "site_id": $(json_str_or_null "$(jget "$RESP_FILE" site_id)"),
  "iface": "$(json_esc "$IFACE")",
  "wg_listen": $WG_LISTEN,
  "role": "$(json_esc "$ROLE")",
  "token_expires": $(json_str_or_null "$(jget "$RESP_FILE" token_expires)")
}
EOF
chmod 0600 "$STATE_TMP"
mv -f "$STATE_TMP" "$STATE_FILE"

# ── 8. bootstrap ONLY this iface's launchd daemon ─────────────────────────────
# Fresh iface → bootstrap is additive (other live tunnels untouched).
# --reinstall onto an existing iface → restart it (it changed).
echo "==> starting launchd daemon for $IFACE"
PLIST="/Library/LaunchDaemons/com.wireguard.wg-mac.${IFACE}.plist"
launchctl bootout  "system/com.wireguard.wg-mac.${IFACE}" 2>/dev/null || true
launchctl enable   "system/com.wireguard.wg-mac.${IFACE}" 2>/dev/null || true
launchctl bootstrap system "$PLIST"
sleep 2
launchctl kickstart -k "system/com.wireguard.wg-mac.${IFACE}"

# Make sure the heartbeat/peer-sync agent is running now that a state file exists.
AGENT_PLIST="/Library/LaunchDaemons/com.wireguard.wgctl-agent.plist"
if ! launchctl print "system/com.wireguard.wgctl-agent" >/dev/null 2>&1; then
    launchctl enable  "system/com.wireguard.wgctl-agent" 2>/dev/null || true
    launchctl bootstrap system "$AGENT_PLIST" 2>/dev/null || true
fi

# ── 9. summary ────────────────────────────────────────────────────────────────
sleep 1
WG_IP=$(jget "$STATE_FILE" wg_ip)
cat <<DONE

  ✓ joined mesh
      device_ip:  $WG_IP
      iface:      $IFACE
      server:     $SERVER

  status:   sudo wgctl show $IFACE
  log:      sudo tail -f /var/log/wireguard.${IFACE}.err.log
  leave:    sudo wgctl leave $IFACE    (deregister + uninstall)

DONE
