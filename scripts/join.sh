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

# ── 0. identity: is this token already registered on this host? ───────────────
# A token is single-use. If we already hold a state file carrying it, this is
# a re-run (a bug), not a fresh join. Refuse — don't re-consume the token.
# Also handles the legacy single-file /etc/wgctl/config.json.
mkdir -p /etc/wgctl && chmod 0700 /etc/wgctl
TOKEN_IFACE=""
if compgen -G "/etc/wgctl/*.json" >/dev/null 2>&1; then
    TOKEN_IFACE=$(TOKEN="$TOKEN" python3 - <<'PY'
import glob, json, os
tok = os.environ["TOKEN"]
for path in sorted(glob.glob("/etc/wgctl/*.json")):
    try:
        st = json.load(open(path))
    except Exception:
        continue
    if st.get("token") == tok:
        # logical iface name = state's "iface" field, else the filename stem
        name = st.get("iface") or os.path.basename(path)[:-5]
        print(name)
        break
PY
)
fi

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
    if ip.startswith("127.") or ip.startswith("169.254.") or ip.startswith("10.88."): continue
    mask = int(mask_hex, 16)
    prefix = bin(mask).count("1")
    addrs.append({"iface": cur_iface, "cidr": f"{ip}/{prefix}"})
print(json.dumps(addrs))
PY
)

AGENT_VER=$(cat "$TMP/wg-mac/VERSION" 2>/dev/null || echo "unknown")

ARCH_RAW=$(uname -m)
case "$ARCH_RAW" in
    x86_64|amd64)   ARCH=amd64 ;;
    arm64|aarch64)  ARCH=arm64 ;;
    *)              ARCH="$ARCH_RAW" ;;
esac

# ── 6. POST /v1/register ─────────────────────────────────────────────────────
echo "==> registering with control plane $SERVER"

REQ_JSON=$(TOKEN="$TOKEN" PUB="$PUB" HOSTNAME_REPORT="$HOSTNAME_REPORT" \
    ARCH="$ARCH" AGENT_VER="$AGENT_VER" LAN="$LAN_ADDRS_JSON" \
    WG_LISTEN="$WG_LISTEN" SITE_SLUG="$SITE_SLUG" python3 <<'PY'
import json, os
print(json.dumps({
    "token":     os.environ["TOKEN"],
    "pubkey":    os.environ["PUB"],
    "hostname":  os.environ["HOSTNAME_REPORT"],
    "os":        "darwin",
    "arch":      os.environ["ARCH"],
    "agent_ver": os.environ["AGENT_VER"],
    "lan_addrs": json.loads(os.environ["LAN"]),
    "wg_listen": int(os.environ["WG_LISTEN"]),
    "site_slug": os.environ["SITE_SLUG"],
}))
PY
)

RESP=$(curl -fsSL --retry 3 --connect-timeout 15 --max-time 60 \
    -X POST "$SERVER/v1/register" \
    -H 'Content-Type: application/json' \
    -d "$REQ_JSON") || {
    echo "register failed (curl exit $?); response:" >&2
    echo "$RESP" >&2
    exit 1
}

# ── 7. render conf + per-iface state ──────────────────────────────────────────
echo "==> rendering /etc/wireguard/$IFACE.conf and $STATE_FILE"

PRIV="$PRIV" IFACE="$IFACE" LISTEN="$WG_LISTEN" RESP="$RESP" \
SERVER="$SERVER" TOKEN="$TOKEN" python3 <<'PY'
import json, os, tempfile

resp   = json.loads(os.environ["RESP"])
priv   = os.environ["PRIV"]
iface  = os.environ["IFACE"]
listen = os.environ["LISTEN"]

# <iface>.conf — Address carries the mesh prefix (not /32) so wg_core installs
# the kernel route (see src/wg_core.c utun_apply_inet4). Default /24.
conf_path = f"/etc/wireguard/{iface}.conf"
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

# /etc/wgctl/<iface>.json — per-iface state (one file per membership).
state = {
    "server":        os.environ["SERVER"],
    "device_id":     resp["device_id"],
    "token":         os.environ["TOKEN"],
    "wg_ip":         resp["device_ip"],
    "site_id":       resp.get("site_id"),
    "iface":         iface,
    "wg_listen":     int(listen),
    "role":          resp.get("role", "device"),
    "token_expires": resp.get("token_expires"),
}
state_path = f"/etc/wgctl/{iface}.json"
with tempfile.NamedTemporaryFile("w", dir="/etc/wgctl",
                                  delete=False, prefix=".state.") as f:
    json.dump(state, f, indent=2)
    tmp = f.name
os.chmod(tmp, 0o600)
os.replace(tmp, state_path)
PY

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
WG_IP=$(python3 -c "import json; print(json.load(open('$STATE_FILE'))['wg_ip'])")
cat <<DONE

  ✓ joined mesh
      device_ip:  $WG_IP
      iface:      $IFACE
      server:     $SERVER

  status:   sudo wgctl show $IFACE
  log:      sudo tail -f /var/log/wireguard.${IFACE}.err.log
  leave:    sudo wgctl leave $IFACE    (deregister + uninstall)

DONE
