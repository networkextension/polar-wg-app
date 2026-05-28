#!/usr/bin/env bash
# wg-mac tunnel diagnostic — read-only. Emits ONE JSON object on stdout.
#   sudo bash scripts/diagnose.sh [--iface=wgc0]
#
# Cross-platform: macOS (wgctl/launchd) and Linux/FreeBSD (wg/wg-quick).
# Keys: os, handshake_age_s (null=never), hub_endpoint, address_prefix (want 24),
#       listen_port, mesh_route (bool), listen_port_owner (proc/socket count),
#       wg_core_procs, ping_hub (ok|fail), hub.
set -u
IFACE="${WG_IFACE:-wgc0}"; LISTEN="${WG_LISTEN:-1632}"
for a in "$@"; do case "$a" in --iface=*) IFACE="${a#*=}";; --listen=*) LISTEN="${a#*=}";; esac; done
[ "$(id -u)" = 0 ] || { echo '{"error":"needs root (sudo)"}'; exit 2; }

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
[ "$OS" = freebsd ] && CONF="/usr/local/etc/wireguard/$IFACE.conf" || CONF="/etc/wireguard/$IFACE.conf"
[ -f "$CONF" ] || CONF="/etc/wireguard/$IFACE.conf"   # mac/linux default

ADDR_PREFIX=$(sed -n 's/.*Address[[:space:]]*=[[:space:]]*[0-9.]*\/\([0-9]*\).*/\1/p' "$CONF" 2>/dev/null | head -1)
[ -z "$ADDR_PREFIX" ] && ADDR_PREFIX=null
CONF_LISTEN=$(sed -n 's/.*ListenPort[[:space:]]*=[[:space:]]*\([0-9]*\).*/\1/p' "$CONF" 2>/dev/null | head -1)
[ -z "$CONF_LISTEN" ] && CONF_LISTEN=null
HUB=$(sed -n 's/.*\(10\.88\.0\.1\).*/\1/p' "$CONF" 2>/dev/null | head -1); HUB="${HUB:-10.88.0.1}"

if [ "$OS" = darwin ]; then
  SHOW=$(wgctl show "$IFACE" 2>/dev/null)
  HS_AGE=$(printf '%s' "$SHOW" | sed -n 's/.*latest handshake:[[:space:]]*\([0-9]*\) seconds ago.*/\1/p' | sort -n | head -1)
  HUB_EP=$(printf '%s' "$SHOW" | sed -n 's/.*endpoint:[[:space:]]*\([^ ]*:[0-9]*\).*/\1/p' | tail -1)
  MESH_ROUTE=$(netstat -rn 2>/dev/null | grep -qE '10\.88(\.0)?(/| )' && echo true || echo false)
  PORT_OWNERS=$(lsof -nP -iUDP:"$LISTEN" 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')
  WGCORE=$(ps ax 2>/dev/null | grep -c '[w]g_core')
  ping -c2 -t5 "$HUB" >/dev/null 2>&1 && PING=ok || PING=fail
else
  # Linux / FreeBSD: native kernel WireGuard.
  NOW=$(date +%s)
  HS_AGE=$(wg show "$IFACE" latest-handshakes 2>/dev/null | awk -v now="$NOW" '$2>0{a=now-$2; if(m==""||a<m)m=a} END{if(m!="")print m}')
  HUB_EP=$(wg show "$IFACE" endpoints 2>/dev/null | awk '$2!="(none)"{print $2}' | tail -1)
  MESH_ROUTE=$( { ip route 2>/dev/null || netstat -rn 2>/dev/null; } | grep -qE '10\.88' && echo true || echo false)
  if command -v ss >/dev/null 2>&1; then
    PORT_OWNERS=$(ss -lunH "sport = :$LISTEN" 2>/dev/null | grep -c .)
  elif command -v sockstat >/dev/null 2>&1; then
    PORT_OWNERS=$(sockstat -4 -l 2>/dev/null | awk -v p="$LISTEN" '$0 ~ ":"p"$"{c++} END{print c+0}')
  else
    PORT_OWNERS=$(lsof -nP -iUDP:"$LISTEN" 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')
  fi
  WGCORE=$(wg show interfaces 2>/dev/null | tr ' ' '\n' | grep -c "^$IFACE$")
  ping -c2 -W2 "$HUB" >/dev/null 2>&1 && PING=ok || PING=fail
fi
[ -z "${HS_AGE:-}" ] && HS_AGE=null

printf '{"os":"%s","iface":"%s","handshake_age_s":%s,"hub_endpoint":"%s","address_prefix":%s,"listen_port":%s,"mesh_route":%s,"listen_port_owner":%s,"wg_core_procs":%s,"hub":"%s","ping_hub":"%s"}\n' \
  "$OS" "$IFACE" "$HS_AGE" "${HUB_EP:-}" "$ADDR_PREFIX" "$CONF_LISTEN" "$MESH_ROUTE" "${PORT_OWNERS:-0}" "${WGCORE:-0}" "$HUB" "$PING"
