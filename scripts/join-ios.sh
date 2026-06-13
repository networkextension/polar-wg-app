#!/bin/bash
# join-ios.sh — register a jailbroken iOS device into a Polar wg-mac mesh
# and bring up the tunnel. Run as root on-device.
#
# Usage:
#   bash join-ios.sh --token=polar_wg_xxxx --server=https://wg.4950.store:2443 [--iface=NAME]
#
# Identity model (same as the macOS join): a token is consumed once at
# /v1/register. Same token already registered here → refuse (re-run is a
# bug). Different token → a different membership → next-free wgcN. State is
# per-iface: /etc/wgctl/<iface>.json (one file per membership).
#
# Output: /etc/wireguard/<iface>.conf + /etc/wgctl/<iface>.json + a running
# wg_core (via `wgctl up`).

set -euo pipefail

TOKEN=""
SERVER=""
IFACE=""        # empty → auto-allocate next-free wgcN
FORCE=0
REINSTALL=0
for arg in "$@"; do
    case "$arg" in
        --token=*)   TOKEN="${arg#--token=}" ;;
        --server=*)  SERVER="${arg#--server=}" ;;
        --iface=*)   IFACE="${arg#--iface=}" ;;
        --force)     FORCE=1 ;;
        --reinstall) REINSTALL=1 ;;
        -h|--help)
            sed -n '2,12p' "$0"; exit 0 ;;
        *)
            echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

[ -n "$TOKEN" ]  || { echo "--token required";  exit 2; }
[ -n "$SERVER" ] || { echo "--server required"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "must run as root"; exit 1; }

SERVER="${SERVER%/}"   # strip trailing /

# Token prefix dispatch — same as the macOS join.
case "$TOKEN" in
    polar_wg_*) ;;
    tskey-*)
        cat >&2 <<TS
✗ This looks like a Tailscale PreAuthKey, not a wg-mac token.
  iOS doesn't ship a usable Tailscale CLI for jailbroken devices. Ask Polar
  for a polar_wg_* token, or wrap a Linux jump host.
TS
        exit 2 ;;
    *)
        echo "warning: token does not start with polar_wg_ — server will be the final arbiter" >&2 ;;
esac

mkdir -p /etc/wireguard /etc/wgctl
chmod 700 /etc/wireguard /etc/wgctl

# ── 0. already-registered? (token is single-use) ─────────────────────────────
TOKEN_IFACE=""
if ls /etc/wgctl/*.json >/dev/null 2>&1; then
    TOKEN_IFACE=$(TOKEN="$TOKEN" python3 - <<'PY'
import glob, json, os
tok = os.environ["TOKEN"]
for path in sorted(glob.glob("/etc/wgctl/*.json")):
    try:
        st = json.load(open(path))
    except Exception:
        continue
    if st.get("token") == tok:
        print(st.get("iface") or os.path.basename(path)[:-5]); break
PY
)
fi

if [ -n "$TOKEN_IFACE" ] && [ "$REINSTALL" = 0 ]; then
    cat >&2 <<MSG
✗ This token is already registered on this device as iface "$TOKEN_IFACE".
  A join token is consumed once; re-running with it is a no-op. Ongoing peer
  sync is handled by wgctl-agent.

  • status:               wgctl show $TOKEN_IFACE
  • join a DIFFERENT hub:  re-run with that hub's own token
  • force re-register:     add --reinstall (dev only; re-consumes the token)
MSG
    exit 3
fi

# ── 1. pick the iface ─────────────────────────────────────────────────────────
iface_in_use() {
    n="$1"
    [ -f "/etc/wgctl/$n.json" ]      && return 0
    [ -f "/etc/wireguard/$n.conf" ]  && return 0
    [ -f "/var/run/wireguard/$n.name" ] && return 0
    return 1
}

if [ "$REINSTALL" = 1 ] && [ -n "$TOKEN_IFACE" ]; then
    IFACE="${IFACE:-$TOKEN_IFACE}"
    echo "warning: --reinstall re-registers token on iface '$IFACE'" >&2
elif [ -n "$IFACE" ]; then
    if iface_in_use "$IFACE"; then
        if [ "$FORCE" = 1 ]; then
            echo "warning: overwriting existing iface '$IFACE' (--force)" >&2
        elif [ -r /dev/tty ]; then
            printf "iface '%s' already exists — overwrite it? [y/N] " "$IFACE" > /dev/tty
            read -r ans < /dev/tty || ans=""
            case "$ans" in [Yy]) ;; *) echo "aborted." >&2; exit 1 ;; esac
        else
            echo "✗ iface '$IFACE' already exists; pass --force to overwrite" >&2
            exit 1
        fi
    fi
else
    n=0
    while iface_in_use "wgc$n"; do n=$((n+1)); done
    IFACE="wgc$n"
    echo "==> allocating iface $IFACE"
fi

STATE_FILE="/etc/wgctl/$IFACE.json"

HOST=$(hostname)
LISTEN=$((RANDOM + 30000))

echo "==> generating keypair"
PRIV=$(/usr/local/bin/wgctl genkey)
PUB=$(printf %s "$PRIV" | /usr/local/bin/wgctl pubkey)

# Collect lan_addrs — array of {iface, cidr}. Skip 127/8, 169.254/16, 10.88/8.
LAN_ADDRS=$(python3 <<'PY'
import json, subprocess, re
out = subprocess.run(["ifconfig"], check=True, capture_output=True, text=True).stdout
addrs, cur = [], None
for line in out.splitlines():
    m = re.match(r"^([a-z][a-z0-9]+):", line)
    if m: cur = m.group(1); continue
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+) netmask 0x([0-9a-f]+)", line)
    if not m: continue
    ip, mh = m.group(1), m.group(2)
    if ip.startswith("127.") or ip.startswith("169.254.") or ip.startswith("10.88."): continue
    addrs.append({"iface": cur, "cidr": f"{ip}/{bin(int(mh,16)).count('1')}"})
print(json.dumps(addrs))
PY
)

REQ=$(TOKEN="$TOKEN" PUB="$PUB" HOST="$HOST" LISTEN="$LISTEN" LAN="$LAN_ADDRS" python3 -c "
import json, os
print(json.dumps({
  'token':     os.environ['TOKEN'],
  'pubkey':    os.environ['PUB'],
  'hostname':  os.environ['HOST'],
  'os':        'darwin',
  'arch':      'arm64',
  'agent_ver': 'wg-mac-ios-0.1',
  'lan_addrs': json.loads(os.environ['LAN']),
  'wg_listen': int(os.environ['LISTEN']),
}))")

echo "==> POST $SERVER/v1/register"
# -k: iOS curl may lack the full LE chain on stock jailbreaks
RESP=$(curl -ksSL --retry 3 --connect-timeout 15 --max-time 60 -X POST "$SERVER/v1/register" \
    -H 'Content-Type: application/json' -d "$REQ") || {
    echo "register failed; response:" >&2; echo "$RESP" >&2; exit 1; }

# Validate response has device_ip
if ! printf %s "$RESP" | python3 -c "
import json, sys
d = json.loads(sys.stdin.read())
if 'device_ip' not in d:
    print(f'server rejected: {d}', file=sys.stderr); sys.exit(1)
"; then
    exit 1
fi

echo "==> rendering /etc/wireguard/$IFACE.conf + $STATE_FILE"
PRIV="$PRIV" IFACE="$IFACE" LISTEN="$LISTEN" RESP="$RESP" SERVER="$SERVER" TOKEN="$TOKEN" python3 <<'PY'
import json, os, tempfile
r = json.loads(os.environ['RESP'])
priv  = os.environ['PRIV']
iface = os.environ['IFACE']
listen = os.environ['LISTEN']

# Address MUST carry the mesh prefix (not /32): wg_core only installs the
# kernel route when prefix_len < 32. /32 = isolated, handshake but no mesh.
mesh_prefix = (r.get('mesh_cidr') or '10.88.0.0/24').split('/')[-1]
lines = [
    '[Interface]',
    f'PrivateKey = {priv}',
    f"Address    = {r['device_ip']}/{mesh_prefix}",
    f'ListenPort = {listen}',
    '',
]
for p in r['peers']:
    extras = p.get('allowed_extra', []) or []
    aips = ([p['wg_ip'] if '/' in p['wg_ip'] else p['wg_ip']+'/32'] if p.get('wg_ip') else []) + extras
    lines += [
        '[Peer]',
        f"PublicKey  = {p['pubkey']}",
        f"Endpoint   = {p['endpoint']}",
        f"AllowedIPs = {', '.join(aips)}",
        f"PersistentKeepalive = {r.get('keepalive_sec', 25)}",
        '',
    ]

conf = f'/etc/wireguard/{iface}.conf'
with tempfile.NamedTemporaryFile('w', dir='/etc/wireguard', delete=False,
                                  prefix=f'.{iface}.conf.') as f:
    f.write('\n'.join(lines)); tmp = f.name
os.chmod(tmp, 0o600); os.replace(tmp, conf)

state = {
    'server':        os.environ['SERVER'],
    'device_id':     r['device_id'],
    'token':         os.environ['TOKEN'],
    'wg_ip':         r['device_ip'],
    'site_id':       r.get('site_id'),
    'iface':         iface,
    'wg_listen':     int(listen),
    'role':          r.get('role', 'device'),
    'token_expires': r.get('token_expires'),
}
state_path = f'/etc/wgctl/{iface}.json'
with tempfile.NamedTemporaryFile('w', dir='/etc/wgctl', delete=False,
                                  prefix='.state.') as f:
    json.dump(state, f, indent=2); tmp = f.name
os.chmod(tmp, 0o600); os.replace(tmp, state_path)

print(f"  wg_ip={r['device_ip']}  peers={len(r['peers'])}")
PY

echo "==> wgctl up $IFACE"
/usr/local/bin/wgctl up "$IFACE"

sleep 2
echo
/usr/local/bin/wgctl show "$IFACE"

WG_IP=$(python3 -c "import json; print(json.load(open('$STATE_FILE'))['wg_ip'])")
HUB_IP=$(python3 -c "import json,sys; r=json.loads(sys.argv[1]); print(r.get('hub',{}).get('wg_ip') or '10.88.0.1')" "$RESP")

cat <<DONE

  ✓ joined Polar mesh
      device_ip: $WG_IP
      iface:     $IFACE
      server:    $SERVER

  ping check:   ping -c 3 $HUB_IP
  status:       wgctl show $IFACE
  bring down:   wgctl down $IFACE

DONE
