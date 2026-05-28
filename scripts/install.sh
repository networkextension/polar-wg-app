#!/bin/bash
# wgctl + wg_core deploy script for macOS.
#
# What it does:
#   1. Builds (via `make all`) if binaries are missing.
#   2. Installs wgctl + wg_core to /usr/local/bin.
#   3. Creates /etc/wireguard (mode 0700) and /var/run/wireguard.
#   4. Renders the launchd plist template for IFACE (default: wg0)
#      into /Library/LaunchDaemons.
#   5. If /etc/wireguard/<iface>.conf exists, runs launchctl bootstrap so
#      the tunnel comes up immediately AND on every boot.
#
# Idempotent: re-running upgrades binaries and reloads the daemon.
#
# Usage:  sudo ./scripts/install.sh [iface]
#         sudo ./scripts/install.sh wg0           (default)
#         WG_NO_ENABLE=1 sudo ./scripts/install.sh wg0   (skip launchctl)

set -euo pipefail

IFACE="${1:-wg0}"
PREFIX="${PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"
CONFDIR="/etc/wireguard"
RUNDIR="/var/run/wireguard"
LOGDIR="/var/log"
LAUNCHDIR="/Library/LaunchDaemons"
PLIST_LABEL="com.wireguard.wg-mac.$IFACE"
PLIST_PATH="$LAUNCHDIR/$PLIST_LABEL.plist"

SRCDIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE="$SRCDIR/scripts/com.wireguard.wg-mac.plist.template"

if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root" >&2
    echo "try:   sudo $0 $IFACE" >&2
    exit 1
fi

# Validate IFACE the same way wgctl does, before letting it reach a plist.
if ! [[ "$IFACE" =~ ^[a-z0-9_-]{1,15}$ ]]; then
    echo "error: invalid iface '$IFACE' (lowercase a-z, 0-9, _-, 1-15 chars)" >&2
    exit 1
fi

cd "$SRCDIR"
if [[ -f Makefile && -z "${WG_SKIP_BUILD:-}" ]]; then
    echo "==> Building"
    make all
elif [[ -x build/wgctl && -x build/wg_core ]]; then
    echo "==> Using prebuilt binaries (skipping build)"
else
    echo "error: no Makefile and no prebuilt binaries in build/" >&2
    echo "       (set WG_SKIP_BUILD=1 with build/wgctl + build/wg_core to bypass make)" >&2
    exit 1
fi

echo "==> Installing binaries to $BINDIR"
LIBEXEC=/usr/local/libexec/wg-mac
install -d "$BINDIR" /usr/local/sbin "$CONFDIR" "$RUNDIR" "$LOGDIR" "$LIBEXEC"
install -m 0755 build/wgctl                  "$BINDIR/wgctl"
install -m 0755 build/wg_core                "$BINDIR/wg_core"
# Reconciler agent (heartbeat + peer refresh). No-op until /etc/wgctl/
# config.json exists — i.e. until the device has joined a mesh.
install -m 0755 scripts/wgctl-agent.sh       /usr/local/sbin/wgctl-agent
# PostUp route installer. wg_core fork-execs /etc/wireguard/<iface>.postup
# after utun_configure; the agent re-runs it every 60 s as a route safety
# net. Default symlink is created the first time install.sh runs for an
# iface — operators who want a custom hook just replace the symlink.
install -m 0755 scripts/wg-postup.sh         "$LIBEXEC/postup.sh"
ln -sf "$BINDIR/../libexec/wg-mac/postup.sh" "$BINDIR/wg-postup"
chmod 0700 "$CONFDIR" "$RUNDIR"

POSTUP_LINK="$CONFDIR/$IFACE.postup"
if [[ ! -e "$POSTUP_LINK" ]]; then
    ln -s "$LIBEXEC/postup.sh" "$POSTUP_LINK"
    echo "==> Linked $POSTUP_LINK -> $LIBEXEC/postup.sh"
fi

echo "==> Rendering launchd plist for $IFACE"
sed "s/@IFACE@/$IFACE/g" "$TEMPLATE" > "$PLIST_PATH"
chown root:wheel "$PLIST_PATH"
chmod 0644 "$PLIST_PATH"

# Agent plist is iface-independent (one agent per host serves all
# meshes the host has joined). Install it always; bootstrap only if
# the host is already joined (config.json exists).
AGENT_PLIST="/Library/LaunchDaemons/com.wireguard.wgctl-agent.plist"
install -m 0644 -o root -g wheel scripts/com.wireguard.wgctl-agent.plist "$AGENT_PLIST"

if [[ -n "${WG_NO_ENABLE:-}" ]]; then
    echo "==> Skipping launchctl enable (WG_NO_ENABLE set)"
    echo ""
    echo "Done. To start manually:"
    echo "  sudo wgctl up $IFACE"
    exit 0
fi

if [[ ! -f "$CONFDIR/$IFACE.conf" ]]; then
    echo ""
    echo "  warning: $CONFDIR/$IFACE.conf does not exist yet."
    echo "  Skipping launchctl enable — drop a config there first, then run:"
    echo "      sudo launchctl bootstrap system $PLIST_PATH"
    echo ""
    echo "  Or test interactively:"
    echo "      sudo wgctl up $IFACE"
    exit 0
fi

echo "==> Enabling $PLIST_LABEL via launchctl"
launchctl bootout "system/$PLIST_LABEL" 2>/dev/null || true
launchctl enable "system/$PLIST_LABEL" 2>/dev/null || true
launchctl bootstrap system "$PLIST_PATH"
launchctl kickstart -k "system/$PLIST_LABEL"

# Bootstrap wgctl-agent only if the device has joined a mesh — i.e.
# /etc/wgctl/config.json exists. Otherwise we'd spam heartbeat 401s
# until the first /v1/register lands the file.
if [[ -f /etc/wgctl/config.json ]]; then
    echo "==> Enabling wgctl-agent (heartbeat + peer refresh)"
    launchctl bootout "system/com.wireguard.wgctl-agent" 2>/dev/null || true
    launchctl enable  "system/com.wireguard.wgctl-agent" 2>/dev/null || true
    launchctl bootstrap system "$AGENT_PLIST"
fi

echo ""
echo "Done. $IFACE is now managed by launchd and will start on every boot."
echo ""
echo "Useful commands:"
echo "  sudo wgctl show $IFACE                              # live status"
echo "  sudo launchctl print system/$PLIST_LABEL            # daemon state"
echo "  sudo tail -f $LOGDIR/wireguard.$IFACE.err.log       # logs"
echo "  sudo launchctl bootout system/$PLIST_LABEL          # stop + disable"
