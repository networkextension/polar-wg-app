#!/bin/bash
# install-ios.sh — install wg-mac on a jailbroken iPhone / iPad.
# Run from inside the unpacked wg-mac-ios bundle:
#     tar xzf wg-mac-ios-arm64-<ver>.tar.gz
#     cd wg-mac-ios-arm64-<ver>
#     bash install.sh
#
# Drops binaries into /usr/local/{bin,sbin,libexec/wg-mac} and creates
# /etc/{wireguard,wgctl} + /var/run/wireguard + /var/log dirs.
#
# Install policy (safe-by-default):
#   • binaries absent             → install (first install)
#   • installed version == bundle → SKIP (no overwrite)
#   • installed version != bundle → SKIP by default; upgrade is opt-in via
#                                    WG_UPDATE=1 (overwriting a live wg_core
#                                    binary and restarting it can drop a
#                                    tunnel you reach the device over).
# Update:  WG_UPDATE=1 bash install.sh

set -euo pipefail

# Resolve bundle dir (script may be invoked from anywhere).
SELF=$(cd "$(dirname "$0")" && pwd)
cd "$SELF"

[ "$(id -u)" = 0 ] || { echo "must run as root"; exit 1; }
[ -x bin/wg_core ] || { echo "missing bin/wg_core — corrupt bundle"; exit 1; }
[ -x bin/wgctl ]   || { echo "missing bin/wgctl   — corrupt bundle"; exit 1; }

LIBEXEC=/usr/local/libexec/wg-mac
MARKER="$LIBEXEC/VERSION"
BUNDLE_VER="$(cat ./VERSION 2>/dev/null || echo "")"
INSTALLED_VER="$(cat "$MARKER" 2>/dev/null || echo "")"

# Decide whether to (re)install the binaries.
if [ ! -x /usr/local/bin/wg_core ] || [ ! -x /usr/local/bin/wgctl ]; then
    MODE=fresh
elif [ -n "${WG_UPDATE:-}" ]; then
    MODE=update
elif [ -n "$BUNDLE_VER" ] && [ "$BUNDLE_VER" = "$INSTALLED_VER" ]; then
    MODE=skip
else
    MODE=stale
fi

# Dirs are always ensured (idempotent, harmless).
install -d -m 0755 /usr/local/bin /usr/local/sbin "$LIBEXEC"
install -d -m 0700 /etc/wireguard /etc/wgctl /var/run/wireguard
install -d -m 0755 /var/log

case "$MODE" in
    skip)
        echo "==> wg-mac $INSTALLED_VER already installed (bundle $BUNDLE_VER) — binaries unchanged"
        ;;
    stale)
        echo "==> installed ${INSTALLED_VER:-unknown} != bundle ${BUNDLE_VER:-unknown}" >&2
        echo "    keeping existing binaries (a live tunnel is not disrupted by default)." >&2
        echo "    to upgrade:  WG_UPDATE=1 bash install.sh   (restarts running tunnels)" >&2
        ;;
    fresh|update)
        if [ "$MODE" = update ]; then
            echo "==> updating binaries (${INSTALLED_VER:-none} -> ${BUNDLE_VER:-bundle})"
            echo "    note: restart wg_core afterward; a tunnel you reach the device over may drop." >&2
        else
            echo "==> installing binaries (${BUNDLE_VER:-bundle})"
        fi
        install -m 0755 bin/wg_core       /usr/local/bin/wg_core
        install -m 0755 bin/wgctl         /usr/local/bin/wgctl
        install -m 0755 sbin/wgctl-agent  /usr/local/sbin/wgctl-agent
        install -m 0755 sbin/join.sh      /usr/local/sbin/wgctl-join
        install -m 0755 libexec/postup.sh "$LIBEXEC/postup.sh"
        printf '%s\n' "${BUNDLE_VER:-bundle}" > "$MARKER"
        ;;
esac

cat <<DONE

✓ wg-mac ready on $(uname -n)

  binaries:   /usr/local/bin/{wg_core,wgctl}
  helpers:    /usr/local/sbin/{wgctl-agent,wgctl-join}
              /usr/local/libexec/wg-mac/postup.sh
  configs:    /etc/wireguard/<iface>.conf
  state:      /etc/wgctl/<iface>.json

next steps:

  • Join a Polar mesh (token-based; picks the next-free iface):
        /usr/local/sbin/wgctl-join --token=polar_wg_xxxx \\
                                   --server=https://wg.4950.store:2443

  • Or hand-rolled tunnel:
        /usr/local/bin/wgctl genkey > /etc/wireguard/wg0.key
        # ...write /etc/wireguard/wg0.conf...
        /usr/local/bin/wgctl up wg0
        /usr/local/bin/wgctl show wg0

DONE
