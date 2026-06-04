#!/bin/bash
# deploy-ios.sh — push the cross-compiled wg-mac bundle to an Apple-Internal
# iOS device over SSH. Assumes:
#   • build/ios-arm64/{wg_core,wgctl} already built via build-ios-cli.sh
#   • You can ssh root@<DEVICE_IP> without password (ssh key in agent)
#   • Device booted with AMFI relaxed
#     (`nvram boot-args=... cs_enforcement_disable=1 amfi_get_out_of_my_way=0x1`)
#     OR ready for the trust-cache route (NOT proven to work on iOS 17 dev — see
#     scripts/build-ios-cli.sh).
#
# Usage: bash scripts/deploy-ios.sh <DEVICE_IP> [<SSH_PORT>]

set -euo pipefail

DEVICE="${1:?usage: deploy-ios.sh <DEVICE_IP> [<SSH_PORT>]}"
PORT="${2:-22}"

cd "$(dirname "$0")/.."   # repo root

OUT=build/ios-arm64
[ -x "$OUT/wg_core" ] || { echo "missing $OUT/wg_core — run scripts/build-ios-cli.sh first"; exit 2; }
[ -x "$OUT/wgctl" ]   || { echo "missing $OUT/wgctl   — run scripts/build-ios-cli.sh first"; exit 2; }

SSH="ssh -p $PORT root@$DEVICE"
SCP="scp -P $PORT"

echo "→ create dirs on $DEVICE"
$SSH 'mkdir -p /usr/local/bin /usr/local/sbin /usr/local/libexec/wg-mac /etc/wireguard /etc/wgctl /var/run/wireguard /var/log
chmod 700 /etc/wireguard /etc/wgctl /var/run/wireguard'

echo "→ scp binaries"
$SCP "$OUT/wg_core"          "root@$DEVICE:/usr/local/bin/wg_core"
$SCP "$OUT/wgctl"            "root@$DEVICE:/usr/local/bin/wgctl"
$SCP scripts/wg-postup.sh    "root@$DEVICE:/usr/local/libexec/wg-mac/postup.sh"
$SCP scripts/wgctl-agent.sh  "root@$DEVICE:/usr/local/sbin/wgctl-agent"
$SCP scripts/join.sh         "root@$DEVICE:/usr/local/sbin/wgctl-join"
$SCP "$OUT/deploy/wgmac.tcache" "root@$DEVICE:/tmp/wgmac.tcache"

echo "→ chmod"
$SSH 'chmod 755 /usr/local/bin/wg_core /usr/local/bin/wgctl
chmod 755 /usr/local/sbin/wgctl-agent /usr/local/sbin/wgctl-join
chmod 755 /usr/local/libexec/wg-mac/postup.sh'

echo "→ smoke test (will fail under stock AMFI; success means boot-args bypass active)"
$SSH '/usr/local/bin/wgctl --help 2>&1 | head -5 || echo "(wgctl exit=$?)"'

echo
echo "Done. To bring up a tunnel:"
echo "  ssh root@$DEVICE"
echo "  /usr/local/bin/wgctl genkey > /etc/wireguard/wg0.key"
echo "  /usr/local/bin/wgctl pubkey < /etc/wireguard/wg0.key"
echo "  cat > /etc/wireguard/wg0.conf <<EOF"
echo "  [Interface]"
echo "  PrivateKey = ..."
echo "  Address = 10.88.0.X/24"
echo "  [Peer]"
echo "  PublicKey = ..."
echo "  Endpoint = wg.4950.store:1632"
echo "  AllowedIPs = 10.88.0.0/24"
echo "  PersistentKeepalive = 25"
echo "  EOF"
echo "  /usr/local/bin/wgctl up wg0"
echo
echo "Or for Polar-mesh auto-register:"
echo "  /usr/local/sbin/wgctl-join --token=polar_wg_xxx --server=https://wg.4950.store:2443"
