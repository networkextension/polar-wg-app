#!/bin/bash
# wgctl + wg_core deploy script for macOS.
#
# What it does:
#   1. Builds (via `make all`) if invoked from a source tree (no WG_SKIP_BUILD).
#   2. Installs wgctl + wg_core to /usr/local/bin — but ONLY when needed
#      (see "install policy" below). Records the installed version in a
#      marker file so re-runs can tell same-version from an upgrade.
#   3. Creates /etc/wireguard (mode 0700) and /var/run/wireguard.
#   4. Renders the launchd plist template for IFACE (default: wg0).
#   5. If /etc/wireguard/<iface>.conf exists AND the daemon is not already
#      running, bootstraps it. A live tunnel is never torn down by default.
#
# Install policy (this is the safe-by-default contract):
#   • Source build (no WG_SKIP_BUILD): always installs the freshly built
#     binaries (dev workflow).
#   • Prebuilt/bundle (WG_SKIP_BUILD=1):
#       - binaries absent            → install (first install)
#       - installed version == bundle → SKIP (no overwrite, no restart)
#       - installed version != bundle → SKIP by default and tell the user
#         to run the update path. Upgrading a live binary + restarting the
#         daemon can drop a tunnel you may be managing the host over, so it
#         is opt-in, never automatic.
#   • Update path:  WG_UPDATE=1 sudo ./install.sh [iface]
#         overwrites binaries regardless of version and restarts the daemon.
#         WARNING: restarts running tunnels — do this over an out-of-band
#         path if you reach the host through its own mesh tunnel.
#
# Usage:  sudo ./scripts/install.sh [iface]
#         sudo ./scripts/install.sh wg0                  (default)
#         WG_NO_ENABLE=1 sudo ./scripts/install.sh wg0   (skip launchctl)
#         WG_UPDATE=1    sudo ./scripts/install.sh wg0   (force upgrade)

set -euo pipefail

IFACE="${1:-wg0}"
PREFIX="${PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"
CONFDIR="/etc/wireguard"
RUNDIR="/var/run/wireguard"
LOGDIR="/var/log"
LAUNCHDIR="/Library/LaunchDaemons"
LIBEXEC="$PREFIX/libexec/wg-mac"
MARKER="$LIBEXEC/VERSION"
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

# ── version detection ─────────────────────────────────────────────────────────
# Bundle version: the VERSION file shipped at the bundle root (date-sha).
# Installed version: the marker we wrote on the last successful install.
BUNDLE_VER="$(cat "$SRCDIR/VERSION" 2>/dev/null || echo "")"
INSTALLED_VER="$(cat "$MARKER" 2>/dev/null || echo "")"

# ── decide install mode ─────────────────────────────────────────────────────────
# fresh  : install binaries (first install, or dev source build)
# update : overwrite + restart (explicit WG_UPDATE=1)
# skip   : same version already installed — do nothing to binaries
# stale  : a different version is installed but update was not requested —
#          keep the existing binaries, tell the user how to upgrade
cd "$SRCDIR"
DEV_BUILD=0
if [[ -f Makefile && -z "${WG_SKIP_BUILD:-}" ]]; then
    DEV_BUILD=1
fi

if [[ ! -x "$BINDIR/wg_core" || ! -x "$BINDIR/wgctl" ]]; then
    MODE=fresh
elif [[ -n "${WG_UPDATE:-}" ]]; then
    MODE=update
elif [[ $DEV_BUILD -eq 1 ]]; then
    MODE=fresh   # you just built from source — install what you built
elif [[ -n "$BUNDLE_VER" && "$BUNDLE_VER" == "$INSTALLED_VER" ]]; then
    MODE=skip
else
    MODE=stale
fi

if [[ "$MODE" == "skip" ]]; then
    echo "==> wg-mac $INSTALLED_VER already installed (bundle $BUNDLE_VER) — binaries unchanged"
elif [[ "$MODE" == "stale" ]]; then
    echo "==> installed version ${INSTALLED_VER:-unknown} != bundle ${BUNDLE_VER:-unknown}" >&2
    echo "    keeping existing binaries (a live tunnel is not disrupted by default)." >&2
    echo "    to upgrade:  WG_UPDATE=1 sudo $0 $IFACE   (restarts running tunnels)" >&2
fi

# ── build (dev source path only, and only when we will install) ─────────────────
if [[ "$MODE" == "fresh" || "$MODE" == "update" ]]; then
    if [[ $DEV_BUILD -eq 1 ]]; then
        echo "==> Building"
        make all
    elif [[ -x build/wgctl && -x build/wg_core ]]; then
        echo "==> Using prebuilt binaries (skipping build)"
    else
        echo "error: no Makefile and no prebuilt binaries in build/" >&2
        echo "       (set WG_SKIP_BUILD=1 with build/wgctl + build/wg_core to bypass make)" >&2
        exit 1
    fi
fi

# ── install binaries (fresh/update only) ───────────────────────────────────────
install -d "$BINDIR" /usr/local/sbin "$CONFDIR" "$RUNDIR" "$LOGDIR" "$LIBEXEC"
if [[ "$MODE" == "fresh" || "$MODE" == "update" ]]; then
    if [[ "$MODE" == "update" ]]; then
        echo "==> Updating binaries in $BINDIR (${INSTALLED_VER:-none} -> ${BUNDLE_VER:-source})"
        echo "    note: this restarts the daemon; a tunnel you manage the host over may drop." >&2
    else
        echo "==> Installing binaries to $BINDIR (${BUNDLE_VER:-source})"
    fi
    install -m 0755 build/wgctl            "$BINDIR/wgctl"
    install -m 0755 build/wg_core          "$BINDIR/wg_core"
    install -m 0755 scripts/wgctl-agent.sh /usr/local/sbin/wgctl-agent
    install -m 0755 scripts/wg-postup.sh   "$LIBEXEC/postup.sh"
    ln -sf "$LIBEXEC/postup.sh"            "$BINDIR/wg-postup"
    # Record what we installed so the next run can compare versions.
    printf '%s\n' "${BUNDLE_VER:-source}" > "$MARKER"
fi
chmod 0700 "$CONFDIR" "$RUNDIR"

# PostUp route installer symlink — per iface, created once. wg_core
# fork-execs /etc/wireguard/<iface>.postup after utun_configure; the agent
# re-runs it every 60 s as a route safety net. Operators who want a custom
# hook just replace the symlink.
POSTUP_LINK="$CONFDIR/$IFACE.postup"
if [[ ! -e "$POSTUP_LINK" ]]; then
    ln -s "$LIBEXEC/postup.sh" "$POSTUP_LINK"
    echo "==> Linked $POSTUP_LINK -> $LIBEXEC/postup.sh"
fi

# Render/refresh the launchd plist for this iface (cheap, no daemon impact).
echo "==> Rendering launchd plist for $IFACE"
sed "s/@IFACE@/$IFACE/g" "$TEMPLATE" > "$PLIST_PATH"
chown root:wheel "$PLIST_PATH"
chmod 0644 "$PLIST_PATH"

# Agent plist is iface-independent (one agent per host serves all meshes).
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

# ── daemon: bring up only if not already running; never tear down a live
#    tunnel by default. The update path is the only thing that restarts it. ──
ALREADY_LOADED=0
launchctl print "system/$PLIST_LABEL" >/dev/null 2>&1 && ALREADY_LOADED=1

if [[ "$MODE" == "update" ]]; then
    echo "==> Restarting $PLIST_LABEL (update)"
    launchctl bootout "system/$PLIST_LABEL" 2>/dev/null || true
    launchctl enable "system/$PLIST_LABEL" 2>/dev/null || true
    launchctl bootstrap system "$PLIST_PATH"
    launchctl kickstart -k "system/$PLIST_LABEL"
elif [[ $ALREADY_LOADED -eq 1 ]]; then
    echo "==> $PLIST_LABEL already running — left untouched (use WG_UPDATE=1 to restart)"
else
    echo "==> Enabling $PLIST_LABEL via launchctl"
    launchctl enable "system/$PLIST_LABEL" 2>/dev/null || true
    launchctl bootstrap system "$PLIST_PATH"
    launchctl kickstart "system/$PLIST_LABEL" 2>/dev/null || true
fi

# Bootstrap wgctl-agent only if the device has joined a mesh — i.e. at least
# one /etc/wgctl/<iface>.json (or legacy config.json) exists. Otherwise we'd
# spam heartbeat 401s until the first /v1/register lands a state file.
if compgen -G "/etc/wgctl/*.json" >/dev/null 2>&1; then
    if launchctl print "system/com.wireguard.wgctl-agent" >/dev/null 2>&1; then
        echo "==> wgctl-agent already running — left untouched"
    else
        echo "==> Enabling wgctl-agent (heartbeat + peer refresh)"
        launchctl enable  "system/com.wireguard.wgctl-agent" 2>/dev/null || true
        launchctl bootstrap system "$AGENT_PLIST"
    fi
fi

echo ""
echo "Done. $IFACE is now managed by launchd and will start on every boot."
echo ""
echo "Useful commands:"
echo "  sudo wgctl show $IFACE                              # live status"
echo "  sudo launchctl print system/$PLIST_LABEL            # daemon state"
echo "  sudo tail -f $LOGDIR/wireguard.$IFACE.err.log       # logs"
echo "  sudo launchctl bootout system/$PLIST_LABEL          # stop + disable"
