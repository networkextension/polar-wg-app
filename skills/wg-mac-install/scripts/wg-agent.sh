#!/usr/bin/env bash
# wg-agent — portable reconciler for native (Linux/FreeBSD) wg-mac memberships.
#
# The Linux/FreeBSD counterpart of macOS scripts/wgctl-agent.sh. Per
# /etc/wgctl/<iface>.json it:
#   1. POST /v1/heartbeat  with the v2 status block (see doc/hub-status.md)
#   2. on 401 invalid-token → self-evict THIS iface (wg-quick down + cleanup)
#   3. GET /v1/peers (or /v1/hub/peers for role=hub)
#   4. re-render the wg-quick conf; if it changed, reload the interface
#
# Native WireGuard is kernel-side, so wg-quick's Table=auto already installs
# the AllowedIPs routes — there's no per-peer route fix-up to do here.
#
# Scheduled every 60 s by a systemd timer (wg-agent.timer) or cron.
# Logs: /var/log/wg-agent.log
set -u
STATE_DIR=/etc/wgctl
LOG=/var/log/wg-agent.log
AGENT_VER=wg-agent-native-1
# Long-poll tuning (env-overridable). See scripts/wgctl-agent.sh for the model:
# bounded long-poll loop per run, auto-degrades to single fetch.
LP_BUDGET=${WGCTL_LP_BUDGET:-55}
LP_WAIT=${WGCTL_LP_WAIT:-45}
LP_MIN_RETURN=${WGCTL_LP_MIN_RETURN:-5}
LP_FLOOR=${WGCTL_LP_FLOOR:-10}
log(){ printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$LOG" 2>/dev/null; }

[ "$(id -u)" = 0 ] || { echo "wg-agent: must run as root" >&2; exit 1; }
command -v wg >/dev/null 2>&1 || { log "wg not found; is wireguard-tools installed?"; exit 1; }

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$(uname -m)" in x86_64|amd64) ARCH=amd64;; arm64|aarch64) ARCH=arm64;; *) ARCH=$(uname -m);; esac
[ "$OS" = freebsd ] && CONFDIR=/usr/local/etc/wireguard || CONFDIR=/etc/wireguard
[ "$OS" = freebsd ] && RUNDIR=/var/run/wireguard || RUNDIR=/run/wireguard
mkdir -p "$RUNDIR" 2>/dev/null || true
HAS_SYSTEMD=0; [ "$OS" = linux ] && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] && HAS_SYSTEMD=1
if [ -r /proc/uptime ]; then UPTIME=$(cut -d. -f1 /proc/uptime); else
  _b=$(sysctl -n kern.boottime 2>/dev/null | sed -n 's/.*sec = \([0-9]*\).*/\1/p')
  [ -n "$_b" ] && UPTIME=$(( $(date +%s) - _b )) || UPTIME=""
fi

# Single-instance guard: a long-poll run can last ~55s; cron (* * * * *) could
# fire a second instance. systemd-timer OnUnitActiveSec and launchd don't
# overlap, but cron does — so hold an flock when available (FreeBSD may lack it,
# in which case we proceed; systemd path is the common Linux scheduler anyway).
if command -v flock >/dev/null 2>&1 && exec 9>"$RUNDIR/wg-agent.lock" 2>/dev/null; then
  flock -n 9 || { log "another wg-agent already running; skip"; exit 0; }
fi

reload_iface() {  # apply a changed conf
  local iface="$1"
  if [ "$HAS_SYSTEMD" = 1 ]; then systemctl restart "wg-quick@$iface" 2>>"$LOG"
  else wg-quick down "$iface" 2>>"$LOG"; wg-quick up "$iface" 2>>"$LOG"; fi
}

evict_iface() {   # server rejected our token: tear this iface down
  local iface="$1" state="$2"
  log "[$iface] EVICT: server rejected token"
  if [ "$HAS_SYSTEMD" = 1 ]; then systemctl disable --now "wg-quick@$iface" 2>>"$LOG"; fi
  wg-quick down "$iface" 2>>"$LOG" || true
  rm -f "$CONFDIR/$iface.conf" "$state" "$RUNDIR/$iface.rev"
}

# Persist the rev cursor atomically (only when non-empty).
save_rev() {  # iface, rev
  [ -n "$2" ] || return 0
  printf '%s\n' "$2" > "$RUNDIR/$1.rev.tmp" 2>/dev/null && mv "$RUNDIR/$1.rev.tmp" "$RUNDIR/$1.rev" 2>/dev/null
}

# Fetch peers once. WAIT>0 → long-poll (?wait/?rev); REV omitted when empty.
# Globals out: PR_OUTCOME{applied,unchanged,notmod,error}, PR_ELAPSED, PR_NEWREV.
peer_refresh_once() {
  local IFACE="$1" SERVER="$2" TOKEN="$3" DEVICE_ID="$4" ROLE="$5" WAIT="$6" REV="$7"
  PR_OUTCOME=error; PR_ELAPSED=0; PR_NEWREV=""
  local base; case "$ROLE" in hub) base="$SERVER/v1/hub/peers";; *) base="$SERVER/v1/peers";; esac
  local url="$base" maxt=10
  if [ "$WAIT" -gt 0 ]; then
    url="$base?wait=$WAIT"
    [ -n "$REV" ] && url="$url&rev=$(printf '%s' "$REV" | sed 's/[^A-Za-z0-9._-]/-/g')"
    maxt=$((WAIT + 10))
  fi
  local PR t0 t1 PCODE
  PR=$(mktemp); t0=$(date +%s)
  PCODE=$(curl -sS -o "$PR" -w '%{http_code}' --max-time "$maxt" "$url" \
          -H "Authorization: Bearer $TOKEN" -H "X-Device-Id: $DEVICE_ID" 2>>"$LOG" || echo 000)
  t1=$(date +%s); PR_ELAPSED=$((t1 - t0))
  if [ "$PCODE" != 200 ]; then log "[$IFACE] peers HTTP $PCODE"; rm -f "$PR"; PR_OUTCOME=error; return; fi
  if grep -q '"not_modified"[[:space:]]*:[[:space:]]*true' "$PR"; then
    PR_NEWREV=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("rev","") or "")' "$PR" 2>/dev/null)
    rm -f "$PR"; PR_OUTCOME=notmod; return
  fi
  PR_NEWREV=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("rev","") or "")' "$PR" 2>/dev/null)
  local NEW CONF; NEW=$(mktemp); CONF="$CONFDIR/$IFACE.conf"
  python3 - "$NEW" "$PR" "$CONF" <<'PY'
import json, sys
new_path, resp_path, conf_path = sys.argv[1], sys.argv[2], sys.argv[3]
priv = addr = listen = ""
try:
    for line in open(conf_path):
        s = line.strip()
        if s.startswith("PrivateKey"): priv = s.split("=",1)[1].strip()
        elif s.startswith("Address"):  addr = s.split("=",1)[1].strip()
        elif s.startswith("ListenPort"): listen = s.split("=",1)[1].strip()
except FileNotFoundError:
    sys.exit("conf missing")
if not priv: sys.exit("priv missing")
resp = json.load(open(resp_path))
lines = ["[Interface]", f"PrivateKey = {priv}",
         f"Address    = {addr or resp.get('device_ip','')+'/24'}",
         f"ListenPort = {listen or '1632'}", ""]
ka = resp.get("keepalive_sec", 25)
for p in resp.get("peers", []):
    if not p.get("pubkey"): continue
    aips = ([p["wg_ip"] + "/32"] if p.get("wg_ip") else []) + (p.get("allowed_extra") or [])
    if not aips: continue
    lines += ["[Peer]", f"PublicKey  = {p['pubkey']}"]
    if p.get("endpoint"): lines += [f"Endpoint   = {p['endpoint']}"]
    lines += [f"AllowedIPs = {', '.join(aips)}"]
    if ka: lines += [f"PersistentKeepalive = {ka}"]
    lines += [""]
open(new_path, "w").write("\n".join(lines))
PY
  if [ -s "$NEW" ]; then
    if [ -f "$CONF" ] && cmp -s "$NEW" "$CONF"; then PR_OUTCOME=unchanged; else
      install -m 0600 "$NEW" "$CONF"; log "[$IFACE] conf changed; reload"; reload_iface "$IFACE"; PR_OUTCOME=applied
    fi
  else
    PR_OUTCOME=unchanged   # empty render (conf missing) → leave running conf alone
  fi
  rm -f "$NEW" "$PR"
}

# Bounded long-poll loop (single iface). Auto-detect + degrade; see wgctl-agent.sh.
peer_refresh_loop() {
  local IFACE="$1" SERVER="$2" TOKEN="$3" DEVICE_ID="$4" ROLE="$5"
  local rev; rev=$(cat "$RUNDIR/$IFACE.rev" 2>/dev/null)
  local deadline=$(( $(date +%s) + LP_BUDGET ))
  local mode="probe" wait_for=0
  while :; do
    local now remaining
    now=$(date +%s); remaining=$(( deadline - now ))
    [ "$remaining" -le 1 ] && break
    if [ "$mode" = longpoll ] || [ "$mode" = trial ]; then
      wait_for=$LP_WAIT
      [ "$wait_for" -gt "$remaining" ] && wait_for=$remaining
      [ "$wait_for" -lt 1 ] && break
    fi
    peer_refresh_once "$IFACE" "$SERVER" "$TOKEN" "$DEVICE_ID" "$ROLE" "$wait_for" "$rev"
    if [ -n "$PR_NEWREV" ] && [ "$PR_NEWREV" != "$rev" ]; then save_rev "$IFACE" "$PR_NEWREV"; rev="$PR_NEWREV"; fi
    case "$PR_OUTCOME" in
      error)  break ;;
      notmod) mode=longpoll; continue ;;
    esac
    case "$mode" in
      probe)
        [ -z "$PR_NEWREV" ] && break
        mode=trial; continue ;;
      trial)
        if [ "$PR_ELAPSED" -ge "$LP_MIN_RETURN" ]; then mode=longpoll; continue; fi
        log "[$IFACE] server ignores ?wait (${PR_ELAPSED}s); single-fetch mode"; break ;;
      longpoll)
        if [ "$PR_ELAPSED" -lt "$LP_MIN_RETURN" ] && [ "$PR_OUTCOME" = unchanged ]; then
          [ $(( deadline - $(date +%s) )) -le "$LP_FLOOR" ] && break
          sleep "$LP_FLOOR"
        fi
        continue ;;
    esac
  done
}

process_iface() {
  local STATE="$1" IFACE
  IFACE=$(basename "$STATE" .json)

  local SERVER DEVICE_ID TOKEN ROLE WG_LISTEN
  read -r SERVER DEVICE_ID TOKEN ROLE WG_LISTEN <<EOF
$(python3 - "$STATE" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
print(c.get("server","").rstrip("/"), c.get("device_id",""), c.get("token",""),
      c.get("role","device"), c.get("wg_listen",1632))
PY
)
EOF
  [ -n "$SERVER" ] && [ -n "$DEVICE_ID" ] && [ -n "$TOKEN" ] || { log "[$IFACE] state incomplete; skip"; return; }

  local DUMP HB_BODY
  DUMP=$(wg show "$IFACE" dump 2>/dev/null)
  HB_BODY=$(DUMP="$DUMP" ROLE="$ROLE" IFACE="$IFACE" WG_LISTEN="$WG_LISTEN" \
            HOST_OS="$OS" HOST_ARCH="$ARCH" HOST_UPTIME="$UPTIME" AGENT_VER="$AGENT_VER" \
            python3 - <<'PY'
import os, re, json, time, subprocess, shutil
dump = os.environ.get("DUMP","")
now = int(time.time())
peers = []
for i, line in enumerate(dump.splitlines()):
    if i == 0: continue                      # interface line
    f = line.split('\t')
    if len(f) < 8: continue
    pub, _psk, ep, aips, lhs, rx, tx, _ka = f[:8]
    lhs = int(lhs) if lhs.isdigit() else 0
    age = None if lhs == 0 else max(0, now - lhs)
    wgip = aips.split(',')[0].strip().split('/')[0] if aips and aips != "(none)" else None
    peers.append({"pubkey": pub, "wg_ip": wgip,
                  "endpoint": None if ep == "(none)" else ep,
                  "last_handshake_sec": age,
                  "rx_bytes": int(rx) if rx.isdigit() else 0,
                  "tx_bytes": int(tx) if tx.isdigit() else 0,
                  "online": age is not None and age < 180})
ages = [p["last_handshake_sec"] for p in peers if p["last_handshake_sec"] is not None]
stats = {"rx_bytes": sum(p["rx_bytes"] for p in peers),
         "tx_bytes": sum(p["tx_bytes"] for p in peers),
         "last_handshake_sec": min(ages) if ages else 0}

# lan_addrs + public-endpoint guess
lan, pub_ip = [], ""
if shutil.which("ip"):
    out = subprocess.run(["ip","-o","-4","addr","show"], capture_output=True, text=True).stdout
    for l in out.splitlines():
        m = re.search(r'^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+/\d+)', l)
        if not m: continue
        ifc, cidr = m.group(1), m.group(2); ip = cidr.split('/')[0]
        if ifc == "lo" or ip.startswith(("127.","169.254.","10.88.")): continue
        lan.append({"iface": ifc, "cidr": cidr})
    g = subprocess.run(["ip","route","get","1.1.1.1"], capture_output=True, text=True).stdout
    m = re.search(r'src\s+(\d+\.\d+\.\d+\.\d+)', g);  pub_ip = m.group(1) if m else ""
else:
    out = subprocess.run(["ifconfig"], capture_output=True, text=True).stdout
    cur = None
    for l in out.splitlines():
        m = re.match(r'^([a-z][a-z0-9]+):', l)
        if m: cur = m.group(1); continue
        m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)\s+netmask\s+0x([0-9a-fA-F]+)', l)
        if not m: continue
        ip = m.group(1)
        if ip.startswith(("127.","169.254.","10.88.")): continue
        lan.append({"iface": cur, "cidr": f"{ip}/{bin(int(m.group(2),16)).count('1')}"})
    if lan: pub_ip = lan[0]["cidr"].split('/')[0]

up = os.environ.get("HOST_UPTIME","")
status = {"schema": 1, "role": os.environ.get("ROLE","device"),
          "os": os.environ.get("HOST_OS",""), "arch": os.environ.get("HOST_ARCH",""),
          "agent_ver": os.environ.get("AGENT_VER","unknown"),
          "iface": os.environ.get("IFACE",""), "iface_up": bool(dump.strip()),
          "uptime_sec": int(up) if up.isdigit() else None,
          "wg_listen": int(os.environ.get("WG_LISTEN") or 1632),
          "peer_count": len(peers), "peers_online": sum(1 for p in peers if p["online"]),
          "peers": peers}
print(json.dumps({"lan_addrs": lan,
                  "wg_endpoint": f"{pub_ip}:{os.environ.get('WG_LISTEN','1632')}" if pub_ip else "",
                  "stats": stats, "status": status}))
PY
)

  # ----- 1. heartbeat -----
  local HB_RESP HB_CODE HB_TXT
  HB_RESP=$(mktemp)
  HB_CODE=$(curl -sS -o "$HB_RESP" -w '%{http_code}' --max-time 10 \
            -X POST "$SERVER/v1/heartbeat" -H "Authorization: Bearer $TOKEN" \
            -H "X-Device-Id: $DEVICE_ID" -H 'Content-Type: application/json' \
            -d "$HB_BODY" 2>>"$LOG" || echo 000)
  HB_TXT=$(cat "$HB_RESP" 2>/dev/null); rm -f "$HB_RESP"
  [ "$HB_CODE" = 200 ] || log "[$IFACE] heartbeat HTTP $HB_CODE: $(printf '%s' "$HB_TXT" | head -c 160)"

  # ----- 2. eviction policy -----
  if [ "$HB_CODE" = 401 ] && printf '%s' "$HB_TXT" | grep -qE 'invalid device token|token expired|token does not match'; then
    evict_iface "$IFACE" "$STATE"; return
  fi

  # ----- 3. peer refresh (long-poll on single iface, else one immediate fetch) -----
  if [ "${LONGPOLL_OK:-0}" = 1 ]; then
    peer_refresh_loop "$IFACE" "$SERVER" "$TOKEN" "$DEVICE_ID" "$ROLE"
  else
    local rev0; rev0=$(cat "$RUNDIR/$IFACE.rev" 2>/dev/null)
    peer_refresh_once "$IFACE" "$SERVER" "$TOKEN" "$DEVICE_ID" "$ROLE" 0 "$rev0"
    [ -n "$PR_NEWREV" ] && [ "$PR_NEWREV" != "$rev0" ] && save_rev "$IFACE" "$PR_NEWREV"
  fi
}

shopt -s nullglob 2>/dev/null || true
state_files=("$STATE_DIR"/*.json)
# Long-poll only with a single mesh iface (a ~45s hold must not starve another
# iface's heartbeat); multi-iface keeps the per-iface immediate fetch.
LONGPOLL_OK=0
[ "${#state_files[@]}" -eq 1 ] && LONGPOLL_OK=1
found=0
for s in "${state_files[@]}"; do
  [ -e "$s" ] || continue
  found=1
  process_iface "$s"
done
[ "$found" = 1 ] || log "no memberships in $STATE_DIR; no-op"
