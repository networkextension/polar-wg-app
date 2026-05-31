#!/bin/bash
# install-ios.sh — install wg-mac on a jailbroken iPhone / iPad.
# Run from inside the unpacked wg-mac-ios bundle:
#     tar xzf wg-mac-ios-arm64-<ver>.tar.gz
#     cd wg-mac-ios-arm64-<ver>
#     bash install.sh
#
# Drops binaries into /usr/local/{bin,sbin,libexec/wg-mac} and creates
# /etc/{wireguard,wgctl} + /var/run/wireguard + /var/log dirs.
# Idempotent — re-run to upgrade in place.

set -euo pipefail

# Resolve bundle dir (script may be invoked from anywhere).
SELF=$(cd "$(dirname "$0")" && pwd)
cd "$SELF"

[ "$(id -u)" = 0 ] || { echo "must run as root"; exit 1; }
[ -x bin/wg_core ] || { echo "missing bin/wg_core — corrupt bundle"; exit 1; }
[ -x bin/wgctl ]   || { echo "missing bin/wgctl   — corrupt bundle"; exit 1; }

install -d -m 0755 /usr/local/bin /usr/local/sbin /usr/local/libexec/wg-mac
install -d -m 0700 /etc/wireguard /etc/wgctl /var/run/wireguard
install -d -m 0755 /var/log

install -m 0755 bin/wg_core            /usr/local/bin/wg_core
install -m 0755 bin/wgctl              /usr/local/bin/wgctl
install -m 0755 sbin/wgctl-agent       /usr/local/sbin/wgctl-agent
install -m 0755 sbin/join.sh           /usr/local/sbin/wgctl-join
install -m 0755 libexec/postup.sh      /usr/local/libexec/wg-mac/postup.sh

# Default per-iface postup symlink (only if user hasn't put their own).
for iface in wg0; do
    link=/etc/wireguard/${iface}.postup
    [ -e "$link" ] || ln -sf /usr/local/libexec/wg-mac/postup.sh "$link"
done

cat <<DONE

✓ installed wg-mac on $(uname -n)

  binaries:   /usr/local/bin/{wg_core,wgctl}
  helpers:    /usr/local/sbin/{wgctl-agent,wgctl-join}
              /usr/local/libexec/wg-mac/postup.sh
  configs:    /etc/wireguard/<iface>.conf
  state:      /etc/wgctl/config.json

next steps:

  • Join a Polar mesh (token-based):
        /usr/local/sbin/wgctl-join --token=polar_wg_xxxx \\
                                   --server=https://wg.4950.store:2443

  • Or hand-rolled tunnel:
        /usr/local/bin/wgctl genkey > /etc/wireguard/wg0.key
        # ...write /etc/wireguard/wg0.conf...
        /usr/local/bin/wgctl up wg0
        /usr/local/bin/wgctl show wg0

  • Auto-start at boot:
        cp launchd/com.wireguard.wg-mac.wg0.plist /Library/LaunchDaemons/
        launchctl bootstrap system /Library/LaunchDaemons/com.wireguard.wg-mac.wg0.plist

DONE
