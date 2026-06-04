#!/bin/bash
# join-ios.sh — register a jailbroken iOS device into a Polar wg-mac mesh
# and bring up the tunnel. Run as root on-device.
#
# Usage:
#   bash join-ios.sh --token=polar_wg_xxxx --server=https://wg.4950.store:2443 [--iface=wg0]
#
# Output: /etc/wireguard/<iface>.conf + /etc/wgctl/config.json + a running
# wg_core under launchd if installed, otherwise foreground / nohup.

set -euo pipefail

TOKEN=""
SERVER=""
IFACE="wg0"
REINSTALL=0
for arg in "$@"; do
    case "$arg" in
        --token=*)   TOKEN="${arg#--token=}" ;;
        --server=*)  SERVER="${arg#--server=}" ;;
        --iface=*)   IFACE="${arg#--iface=}" ;;
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

# Token prefix dispatch — same as the macOS join, see doc/wg-mac-tailscale-howto.md.
case "$TOKEN" in
    polar_wg_*) ;;
    tskey-*)
        cat >&2 <<TS
✗ This looks like a Tailscale PreAuthKey, not a wg-mac token.
  iOS doesn't ship a usable Tailscale CLI for jailbroken devices; the
  App-Store Tailscale app needs the regular OS. Ask Polar for a polar_wg_*
  token, or wrap a Linux jump host.
TS
        exit 2 ;;
    *)
        echo "warning: token does not start with polar_wg_ — server will be the final arbiter" >&2 ;;
esac

if [ -s /etc/wgctl/config.json ] && [ "$REINSTALL" = 0 ]; then
    echo "/etc/wgctl/config.json exists; pass --reinstall to overwrite" >&2
    exit 1
fi

mkdir -p /etc/wireguard /etc/wgctl
chmod 700 /etc/wireguard /etc/wgctl

HOST=$(hostname)
LISTEN=$((RANDOM + 30000))

echo "==> generating keypair"
PRIV=$(/usr/local/bin/wgctl genkey)
PUB=$(printf %s "$PRIV" | /usr/local/bin/wgctl pubkey)

# Collect lan_addrs — array of {iface, cidr}. Skip 127/8 + 169.254/16.
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
    if ip.startswith("127.") or ip.startswith("169.254."): continue
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
RESP=$(curl -ksSL --retry 3 -X POST "$SERVER/v1/register" \
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

echo "==> rendering /etc/wireguard/$IFACE.conf + /etc/wgctl/config.json"
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
    aips = ([p['wg_ip']+'/32'] if p.get('wg_ip') else []) + extras
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
    'token_expires': r.get('token_expires'),
}
with tempfile.NamedTemporaryFile('w', dir='/etc/wgctl', delete=False,
                                  prefix='.config.json.') as f:
    json.dump(state, f, indent=2); tmp = f.name
os.chmod(tmp, 0o600); os.replace(tmp, '/etc/wgctl/config.json')

print(f"  wg_ip={r['device_ip']}  peers={len(r['peers'])}")
PY

echo "==> wgctl up $IFACE"
/usr/local/bin/wgctl up "$IFACE"

sleep 2
echo
/usr/local/bin/wgctl show "$IFACE"

WG_IP=$(python3 -c 'import json; print(json.load(open("/etc/wgctl/config.json"))["wg_ip"])')
HUB_IP=$(python3 -c "import json,sys; r=json.loads(sys.argv[1]); print(r.get('hub',{}).get('wg_ip') or '10.88.0.1')" "$RESP")

cat <<DONE

  ✓ joined Polar mesh
      device_ip: $WG_IP
      iface:     $IFACE
      server:    $SERVER

  ping check:   ping -c 3 $HUB_IP
  status:       wgctl show $IFACE
  bring down:   wgctl down $IFACE
  reinstall:    join-ios.sh --token=... --server=... --reinstall

DONE
