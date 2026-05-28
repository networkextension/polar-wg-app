#!/bin/bash
# wg-postup — install per-peer AllowedIPs routes for a wg-mac utun.
#
# This is the script-level safety net for the route-loss bug:
#   * wg_core installs routes once in utun_configure() at startup.
#   * macOS sometimes flushes utun routes later (sleep/wake, primary
#     interface flip, configd cleanup).
#   * This script re-installs them. Idempotent — re-adding a route that
#     already points at the right utun is a no-op (we check first), and
#     a route pointing at a stale utun gets replaced.
#
# Invoked from three places:
#   1. wg_core, post-utun_configure  → /etc/wireguard/<iface>.postup
#      (we ship a symlink there pointing at this file).
#   2. wgctl-agent every 60 s         → defensive reconcile.
#   3. operator, manually             → `sudo wg-postup wgc0`.
#
# Usage:
#   wg-postup <iface>                       # parse /etc/wireguard/<iface>.conf
#   wg-postup <iface> <conf-path>           # explicit conf
#   wg-postup <iface> <conf-path> <utun>    # explicit utun unit (else read .name)
#
# Stderr: one line per add. Exit 0 on success (zero or more routes added).
set -u

IFACE="${1:-}"
CONF="${2:-/etc/wireguard/${IFACE}.conf}"
UTUN="${3:-}"

if [[ -z "$IFACE" ]]; then
    echo "usage: wg-postup <iface> [conf-path] [utun-unit]" >&2
    exit 2
fi
[[ $EUID -eq 0 ]] || { echo "wg-postup: must run as root" >&2; exit 1; }
[[ -r "$CONF" ]]  || { echo "wg-postup: conf $CONF not readable" >&2; exit 1; }

# Resolve the actual utun unit. wg_core writes it to <iface>.name on bring-up.
if [[ -z "$UTUN" ]]; then
    NAMEFILE="/var/run/wireguard/${IFACE}.name"
    [[ -r "$NAMEFILE" ]] && UTUN=$(head -1 "$NAMEFILE" | tr -d '[:space:]')
fi
if [[ -z "$UTUN" ]]; then
    echo "wg-postup[$IFACE]: no utun unit known (no $NAMEFILE); skip" >&2
    exit 0
fi
# Sanity: utun must currently exist.
if ! ifconfig "$UTUN" >/dev/null 2>&1; then
    echo "wg-postup[$IFACE]: utun $UTUN does not exist; skip" >&2
    exit 0
fi

# Pull every AllowedIPs entry across [Peer] blocks. The conf can have one
# or many; commas separate CIDRs within one entry. Portable to bash 3.2
# (macOS /bin/bash) — no `mapfile`.
CIDR_LIST=$(
    awk -F= 'tolower($1) ~ /^[ \t]*allowedips[ \t]*$/ {print $2}' "$CONF" \
        | tr ',' '\n' | sed -E 's/^[ \t]+|[ \t]+$//g' | sed '/^$/d'
)

added=0; kept=0; replaced=0
while IFS= read -r raw; do
    [[ -n "$raw" ]] || continue
    cidr="$raw"
    [[ "$cidr" == */* ]] || cidr="${cidr}/32"        # bare host → /32
    case "$cidr" in
        0.0.0.0/0|::/0) continue ;;                  # default route — never auto-add
    esac
    case "$cidr" in
        *:*) FAM="-inet6" ;;
        *)   FAM="-inet"  ;;
    esac

    # Does a route for this prefix already exist and point at our utun?
    # `route -n get` falls back to the default route when no specific entry
    # exists, so we have to look at BOTH `destination:` and `interface:`.
    # destination == default → no specific route covering this CIDR.
    get_out=$(/sbin/route -n get $FAM "$cidr" 2>/dev/null)
    cur_dst=$(printf '%s\n' "$get_out" | awk '/destination:/{print $2; exit}')
    cur_if=$(printf  '%s\n' "$get_out" | awk '/interface:/{print $2; exit}')
    [[ "$cur_dst" == "default" ]] && cur_if=""

    if [[ "$cur_if" == "$UTUN" ]]; then
        kept=$((kept+1))
        continue
    fi
    if [[ -n "$cur_if" ]]; then
        # Wrong interface (likely stale utun from a previous wg_core unit).
        /sbin/route -q -n delete $FAM "$cidr" >/dev/null 2>&1 || true
        replaced=$((replaced+1))
    fi
    if /sbin/route -q -n add $FAM "$cidr" -interface "$UTUN" >/dev/null 2>&1; then
        added=$((added+1))
        echo "wg-postup[$IFACE]: route add $cidr -> $UTUN" >&2
    else
        echo "wg-postup[$IFACE]: route add $cidr -> $UTUN FAILED" >&2
    fi
done <<< "$CIDR_LIST"

echo "wg-postup[$IFACE]: utun=$UTUN added=$added replaced=$replaced kept=$kept" >&2
exit 0
