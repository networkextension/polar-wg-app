#!/bin/bash
# Launch wg_core in tunnel mode. Must be run as root because:
#   1. opening com.apple.net.utun_control requires root
#   2. ifconfig / route add require root
#
# Usage: sudo ./run_tunnel.sh [config_path]
#        default config: src/client.conf
#
# Once running:
#   ping 10.88.0.1          # server tunnel IP
#   Ctrl-C to stop; the utun interface goes away automatically
#
set -e

CONFIG="${1:-src/client.conf}"

if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root (need utun + ifconfig privileges)" >&2
    echo "try:   sudo $0 $CONFIG" >&2
    exit 1
fi

if [[ ! -f build/wg_core ]]; then
    echo "build/wg_core not found — run 'make' first" >&2
    exit 1
fi

exec ./build/wg_core --tunnel "$CONFIG"
