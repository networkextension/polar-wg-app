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
#   --listen=PORT      override wg UDP listen port (default: 51820)
#   --iface=NAME       override logical iface name (default: wgc0)
#   --reinstall        force re-register even if /etc/wgctl/config.json exists
#
# What it does, in order:
#   1. download <server>/v1/bundle (wg-mac binaries + scripts)
#   2. run bundle's scripts/install.sh to lay down /usr/local/bin/{wgctl,wg_core}
#      and /Library/LaunchDaemons/com.wireguard.wg-mac.<iface>.plist (NOT bootstrapped)
#   3. generate a Curve25519 keypair locally; private key never leaves the device
#   4. POST <server>/v1/register with {token, pubkey, lan_addrs, ...}
#   5. render /etc/wireguard/<iface>.conf from the response peer list
#   6. write /etc/wgctl/config.json with the join state
#   7. launchctl bootstrap the daemon → wg_core comes up, handshake, online
#
# After this script returns the device is reachable on its assigned mesh IP.
# A periodic refresh agent (wgctl refresh) keeps the peer list in sync.

set -euo pipefail

# ── parse args ───────────────────────────────────────────────────────────────
# Kept in sync with Polar's wg_install_script.go template — they
# represent the same protocol, this is the local reference/test
# implementation. Production is rendered by the control plane.
SERVER="__SERVER_PLACEHOLDER__"
TOKEN=""
HOSTNAME_OVERRIDE=""
SITE_SLUG=""
WG_LISTEN=1632
IFACE="wgc0"
REINSTALL=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --token=*)    TOKEN="${1#*=}";;
        --hostname=*) HOSTNAME_OVERRIDE="${1#*=}";;
        --site=*)     SITE_SLUG="${1#*=}";;
        --listen=*)   WG_LISTEN="${1#*=}";;
        --iface=*)    IFACE="${1#*=}";;
        --reinstall)  REINSTALL=1;;
        --server=*)   SERVER="${1#*=}";;   # offline test
        *) echo "unknown arg: $1" >&2; exit 1;;
    esac
    shift
done

[[ $EUID -eq 0 ]] || { echo "must run as root (use sudo bash)" >&2; exit 1; }
[[ -n "$TOKEN" ]] || { echo "--token=<TOKEN> required" >&2; exit 1; }
[[ "$SERVER" != "__SERVER_PLACEHOLDER__" ]] || {
    echo "SERVER not set; this script must be served by control plane with __SERVER_PLACEHOLDER__ substituted, OR call with --server=https://..." >&2
    exit 1
}

# Strip trailing slash from SERVER for cleaner URLs.
SERVER="${SERVER%/}"

# Token prefix dispatch — see doc/wg-mac-tailscale-howto.md.
# Polar mints two tokens per click: polar_wg_<hex> for this script,
# tskey-<...> for the stock Tailscale client. If the operator pasted
# the wrong half we want to redirect them, not fail opaquely 200
# lines later inside /v1/register.
case "$TOKEN" in
    polar_wg_*) ;;  # native path, fall through
    tskey-*)
        cat >&2 <<TS
✗ This looks like a Tailscale PreAuthKey, not a wg-mac token.
  Polar dock issues both kinds; pick the one matching your client.

  To onboard with the official Tailscale client instead:

      brew install --cask tailscale
      sudo tailscale up --login-server=${SERVER} --authkey=${TOKEN}

  The same mesh; Polar's embedded Headscale will admit your device.
  See ${SERVER}/v1/install for the wg-mac variant.
TS
        exit 2
        ;;
    *)
        echo "warning: token does not start with polar_wg_ — proceeding anyway, server will be the final arbiter" >&2
        ;;
esac

# Honor existing install unless --reinstall.
if [[ -f /etc/wgctl/config.json && $REINSTALL -eq 0 ]]; then
    echo "/etc/wgctl/config.json exists; pass --reinstall to overwrite" >&2
    exit 1
fi

# ── tmp workspace ────────────────────────────────────────────────────────────
TMP=$(mktemp -d /tmp/wg-mac-join.XXXXXX)
trap "rm -rf $TMP" EXIT
echo "==> workspace $TMP"

# ── 1. fetch + extract bundle ────────────────────────────────────────────────
echo "==> downloading bundle from $SERVER/v1/bundle"
curl -fsSL --retry 3 "$SERVER/v1/bundle" -o "$TMP/bundle.tar.gz"
mkdir -p "$TMP/wg-mac"
tar xzf "$TMP/bundle.tar.gz" -C "$TMP/wg-mac" --strip-components=1
test -x "$TMP/wg-mac/build/wgctl"   || { echo "bad bundle: no wgctl"   >&2; exit 1; }
test -x "$TMP/wg-mac/build/wg_core" || { echo "bad bundle: no wg_core" >&2; exit 1; }

# ── 2. install binaries via bundle's install.sh ──────────────────────────────
echo "==> installing binaries + plist (no bootstrap yet)"
# WG_SKIP_BUILD: don't run make. WG_NO_ENABLE: don't bootstrap yet — we
# need to write the conf first.
WG_SKIP_BUILD=1 WG_NO_ENABLE=1 \
    bash "$TMP/wg-mac/scripts/install.sh" "$IFACE" >/dev/null

# ── 3. generate keypair ──────────────────────────────────────────────────────
echo "==> generating Curve25519 keypair"
PRIV=$(/usr/local/bin/wgctl genkey)
PUB=$(echo "$PRIV" | /usr/local/bin/wgctl pubkey)

# ── 4. collect lan_addrs ────────────────────────────────────────────────────
HOSTNAME_REPORT="${HOSTNAME_OVERRIDE:-$(scutil --get LocalHostName 2>/dev/null || hostname -s)}"

# Pull active IPv4 interfaces with their /prefix. ifconfig prefix is hex,
# convert to decimal. Skip 127/8 and 169.254/16.
LAN_ADDRS_JSON=$(python3 <<'PY'
import json, subprocess, re
out = subprocess.run(["ifconfig"], check=True, capture_output=True, text=True).stdout
addrs, cur_iface = [], None
for line in out.splitlines():
    m = re.match(r"^([a-z][a-z0-9]+):", line)
    if m: cur_iface = m.group(1); continue
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+) netmask 0x([0-9a-f]+)", line)
    if not m: continue
    ip, mask_hex = m.group(1), m.group(2)
    if ip.startswith("127.") or ip.startswith("169.254."): continue
    mask = int(mask_hex, 16)
    prefix = bin(mask).count("1")
    addrs.append({"iface": cur_iface, "cidr": f"{ip}/{prefix}"})
print(json.dumps(addrs))
PY
)

# Agent version: bundle/VERSION or "unknown".
AGENT_VER=$(cat "$TMP/wg-mac/VERSION" 2>/dev/null || echo "unknown")

# Normalize ARCH to match what the control plane expects (amd64 / arm64).
ARCH_RAW=$(uname -m)
case "$ARCH_RAW" in
    x86_64|amd64)   ARCH=amd64 ;;
    arm64|aarch64)  ARCH=arm64 ;;
    *)              ARCH="$ARCH_RAW" ;;
esac

# ── 5. POST /v1/register ─────────────────────────────────────────────────────
echo "==> registering with control plane $SERVER"

REQ_JSON=$(python3 <<PY
import json
print(json.dumps({
    "token":     "$TOKEN",
    "pubkey":    "$PUB",
    "hostname":  "$HOSTNAME_REPORT",
    "os":        "darwin",
    "arch":      "$ARCH",
    "agent_ver": "$AGENT_VER",
    "lan_addrs": $LAN_ADDRS_JSON,
    "wg_listen": $WG_LISTEN,
    "site_slug": "$SITE_SLUG"
}))
PY
)

RESP=$(curl -fsSL --retry 3 -X POST "$SERVER/v1/register" \
    -H 'Content-Type: application/json' \
    -d "$REQ_JSON") || {
    echo "register failed; response:" >&2
    echo "$RESP" >&2
    exit 1
}

# ── 6. render conf + state ───────────────────────────────────────────────────
echo "==> rendering /etc/wireguard/$IFACE.conf and /etc/wgctl/config.json"

mkdir -p /etc/wgctl
chmod 0700 /etc/wgctl

# Pass priv + listen + iface + resp + server + token via env, then write
# two files atomically (tmp then rename + chmod 0600).
PRIV="$PRIV" IFACE="$IFACE" LISTEN="$WG_LISTEN" RESP="$RESP" \
SERVER="$SERVER" TOKEN="$TOKEN" python3 <<'PY'
import json, os, tempfile

resp   = json.loads(os.environ["RESP"])
priv   = os.environ["PRIV"]
iface  = os.environ["IFACE"]
listen = os.environ["LISTEN"]

# wgc0.conf
conf_path = f"/etc/wireguard/{iface}.conf"
# Address MUST carry the mesh prefix (not /32): wg_core only installs the
# kernel route when prefix_len < 32 (src/wg_core.c utun_apply_inet4). A /32
# isolates the device — handshake succeeds but no mesh IP (e.g. the hub
# 10.88.0.1) is routable. Derive prefix from mesh_cidr, default /24.
mesh_prefix = (resp.get("mesh_cidr") or "10.88.0.0/24").split("/")[-1]
lines = [
    "[Interface]",
    f"PrivateKey = {priv}",
    f"Address    = {resp['device_ip']}/{mesh_prefix}",
    f"ListenPort = {listen}",
    "",
]
for p in resp["peers"]:
    extras = p.get("allowed_extra", []) or []
    aips = ([p["wg_ip"] + "/32"] if p.get("wg_ip") else []) + extras
    lines += [
        "[Peer]",
        f"PublicKey  = {p['pubkey']}",
        f"Endpoint   = {p['endpoint']}",
        f"AllowedIPs = {', '.join(aips)}",
        f"PersistentKeepalive = {resp.get('keepalive_sec', 25)}",
        "",
    ]
with tempfile.NamedTemporaryFile("w", dir="/etc/wireguard",
                                  delete=False, prefix=f".{iface}.conf.") as f:
    f.write("\n".join(lines))
    tmp = f.name
os.chmod(tmp, 0o600)
os.replace(tmp, conf_path)

# /etc/wgctl/config.json
state = {
    "server":        os.environ["SERVER"],
    "device_id":     resp["device_id"],
    "token":         os.environ["TOKEN"],
    "wg_ip":         resp["device_ip"],
    "site_id":       resp.get("site_id"),
    "iface":         iface,
    "token_expires": resp.get("token_expires"),
}
state_path = "/etc/wgctl/config.json"
with tempfile.NamedTemporaryFile("w", dir="/etc/wgctl",
                                  delete=False, prefix=".config.json.") as f:
    json.dump(state, f, indent=2)
    tmp = f.name
os.chmod(tmp, 0o600)
os.replace(tmp, state_path)
PY

# ── 7. bootstrap launchd ─────────────────────────────────────────────────────
echo "==> starting launchd daemon"
PLIST="/Library/LaunchDaemons/com.wireguard.wg-mac.${IFACE}.plist"
launchctl bootout  "system/com.wireguard.wg-mac.${IFACE}" 2>/dev/null || true
launchctl enable   "system/com.wireguard.wg-mac.${IFACE}" 2>/dev/null || true
launchctl bootstrap system "$PLIST"
sleep 2
launchctl kickstart -k "system/com.wireguard.wg-mac.${IFACE}"

# ── 8. summary ──────────────────────────────────────────────────────────────
sleep 1
WG_IP=$(python3 -c 'import json; print(json.load(open("/etc/wgctl/config.json"))["wg_ip"])')
cat <<DONE

  ✓ joined mesh
      device_ip:  $WG_IP
      iface:      $IFACE
      server:     $SERVER

  status:   sudo wgctl show $IFACE
  log:      sudo tail -f /var/log/wireguard.${IFACE}.err.log
  refresh:  sudo wgctl refresh         (re-fetch peer list manually)
  leave:    sudo wgctl leave $IFACE    (deregister + uninstall)

DONE
