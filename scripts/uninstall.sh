#!/bin/bash
# Reverse of install.sh. Leaves /etc/wireguard configs in place; the user
# can remove those manually.
#
# Usage:  sudo ./scripts/uninstall.sh [iface]
#         sudo ./scripts/uninstall.sh wg0     (default)

set -euo pipefail

IFACE="${1:-wg0}"
PREFIX="${PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"
LAUNCHDIR="/Library/LaunchDaemons"
PLIST_LABEL="com.wireguard.wg-mac.$IFACE"
PLIST_PATH="$LAUNCHDIR/$PLIST_LABEL.plist"

if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root" >&2; exit 1
fi

if [[ -f "$PLIST_PATH" ]]; then
    echo "==> Disabling $PLIST_LABEL"
    # `launchctl disable` is required BEFORE bootout — without it, launchd
    # keeps the daemon's KeepAlive credit alive for ~30s after bootout and
    # may respawn wg_core one or two more times before fully releasing it.
    launchctl disable "system/$PLIST_LABEL" 2>/dev/null || true
    launchctl bootout "system/$PLIST_LABEL" 2>/dev/null || true
    rm -f "$PLIST_PATH"
fi

# Final pkill in case anything escaped the bootout window.
pkill -9 -f "wg_core .* --logical-name $IFACE" 2>/dev/null || true

if pgrep -af "wg_core .* --logical-name $IFACE" >/dev/null 2>&1; then
    echo "==> Stopping running tunnel for $IFACE"
    "$BINDIR/wgctl" down "$IFACE" || true
fi

echo "==> Removing binaries"
rm -f "$BINDIR/wgctl" "$BINDIR/wg_core"

echo ""
echo "Done. /etc/wireguard configs were left in place."
echo "Remove them with:  sudo rm -rf /etc/wireguard"
