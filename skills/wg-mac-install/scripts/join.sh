#!/usr/bin/env bash
# wg-mac install + join — cross-platform.
#
#   macOS         : pulls the published wg-mac tarball, installs wg_core + wgctl,
#                   registers, brings the tunnel up via launchd.
#   Linux/FreeBSD : self-contained native path — installs wireguard-tools,
#                   registers, renders a wg-quick conf, brings it up, and schedules
#                   the portable reconciler (heartbeat + peer refresh).
#
# Emits ONE JSON object on stdout; progress on stderr.
#
#   sudo bash scripts/join.sh --token=polar_wg_<…> \
#        [--server=https://wg.4950.store:2443] [--iface=wgc0] [--listen=1632] [--reinstall]
set -u
SELF_DIR=$(cd "$(dirname "$0")" && pwd)
log()  { printf '%s\n' "$*" >&2; }
emit() { printf '{"status":"%s","iface":"%s","hub":"%s","detail":"%s"}\n' \
           "$1" "${IFACE:-}" "${HUB:-}" "${2//\"/\'}"; }

TOKEN=""; SERVER="${WG_SERVER:-https://wg.4950.store:2443}"
IFACE="${WG_IFACE:-wgc0}"; LISTEN="${WG_LISTEN:-1632}"; REINSTALL=""; HUB=""
for a in "$@"; do case "$a" in
  --token=*)  TOKEN="${a#*=}";;
  --server=*) SERVER="${a#*=}";;
  --iface=*)  IFACE="${a#*=}";;
  --listen=*) LISTEN="${a#*=}";;
  --reinstall) REINSTALL="--reinstall";;
esac; done
SERVER="${SERVER%/}"

[ -n "$TOKEN" ]    || { log "✗ --token required"; emit error "no token"; exit 2; }
[ "$(id -u)" = 0 ] || { log "✗ run as root (sudo)"; emit requires_unmet "needs root"; exit 2; }

case "$TOKEN" in
  tskey-*) log "✗ tskey- is a Tailscale key, not wg-mac (see SKILL.md Step 0)";
           emit wrong_token_kind "tskey- belongs to Tailscale"; exit 3;;
  polar_wg_*) :;;
  *) log "warning: token not polar_wg_*, proceeding — server arbitrates";;
esac

# Control-plane preflight is shared by both paths: it both proves reachability
# (the classic :443-vs-:2443 mistake) and, on macOS, yields BUNDLE_VERSION.
preflight() {
  log "==> preflight $SERVER/v1/install"
  local code
  code=$(curl -fsS --max-time 8 -o /tmp/wgskill.install -w '%{http_code}' "$SERVER/v1/install" 2>/dev/null)
  [ "$code" = 200 ] || { log "✗ control plane HTTP '$code' (must be :2443)";
                         emit control_plane_unreachable "GET /v1/install -> $code"; return 1; }
}

# ── package-manager shim (native path) ──────────────────────────────────────
PKG=""
detect_pkg() { for m in apt-get dnf yum pacman apk zypper pkg; do
  command -v "$m" >/dev/null 2>&1 && { PKG=$m; return; }; done; }
pkg_install() { case "$PKG" in
  apt-get) apt-get update -qq >&2; DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" >&2;;
  dnf)     dnf install -y "$@" >&2;;
  yum)     yum install -y "$@" >&2;;
  pacman)  pacman -Sy --noconfirm "$@" >&2;;
  apk)     apk add --no-cache "$@" >&2;;
  zypper)  zypper -n install "$@" >&2;;
  pkg)     pkg install -y "$@" >&2;;
  *) return 1;; esac; }

# ═══ macOS: bundle + launchd (unchanged behavior) ════════════════════════════
macos_join() {
  preflight || exit 4
  local VER WORK OUT RC
  VER=$(sed -n "s/^BUNDLE_VERSION='\(.*\)'/\1/p" /tmp/wgskill.install | head -1)
  [ -n "$VER" ] || { emit error "no BUNDLE_VERSION"; exit 4; }
  WORK=$(mktemp -d); log "==> fetching wg-mac bundle $VER"
  curl -fsSL --max-time 30 "$SERVER/v1/bundle/$VER" -o "$WORK/b.tgz" \
    || { emit download_failed "bundle $VER"; exit 4; }
  tar xzf "$WORK/b.tgz" -C "$WORK" --strip-components=1 || { emit error "untar"; exit 4; }
  cd "$WORK"

  if lsof -nP -iUDP:"$LISTEN" >/dev/null 2>&1; then
    log "==> freeing UDP $LISTEN (stale tunnel)"
    launchctl bootout system/com.wireguard.wg-mac.wg0 2>/dev/null; wgctl down wg0 2>/dev/null
  fi

  log "==> install + join $IFACE @ $SERVER (listen $LISTEN)"
  WG_SKIP_BUILD=1 bash scripts/install.sh "$IFACE" >&2 2>&1
  OUT=$(WG_LISTEN="$LISTEN" bash scripts/join.sh \
          --server="$SERVER" --token="$TOKEN" --iface="$IFACE" --listen="$LISTEN" $REINSTALL 2>&1)
  RC=$?; printf '%s\n' "$OUT" >&2
  if [ $RC -ne 0 ]; then
    case "$OUT" in
      *409*token_already_bound*) emit token_already_bound "already registered; --reinstall to re-render";;
      *409*pubkey*)              emit pubkey_taken "wgctl down $IFACE then retry";;
      *500*)                     emit server_error "re-run register without -f to read body";;
      *)                         emit join_failed "join.sh exit $RC";;
    esac; exit 5
  fi
  HUB=$(printf '%s' "$OUT" | sed -n 's/.*hub[_a-z]*[": ]*\(10\.88\.[0-9.]*\).*/\1/p' | head -1)
  HUB="${HUB:-10.88.0.1}"

  sleep 6
  local HS RT PING
  HS=$(wgctl show "$IFACE" 2>/dev/null | grep -c 'latest handshake: [0-9]')
  RT=$(netstat -rn 2>/dev/null | grep -c '10\.88')
  ping -c2 -t5 "$HUB" >/dev/null 2>&1 && PING=ok || PING=fail
  log "==> handshakes=$HS route=$RT ping($HUB)=$PING"
  if [ "$HS" -ge 1 ] && [ "$RT" -ge 1 ] && [ "$PING" = ok ]; then
    emit ok "joined $IFACE, hub $HUB reachable"; exit 0
  fi
  emit joined_unverified "hs=$HS route=$RT ping=$PING — run scripts/diagnose.sh"; exit 0
}

# ═══ Linux / FreeBSD: native kernel WireGuard via wg-quick ═══════════════════
native_join() {
  local OSARG="$1"   # linux | freebsd
  preflight || exit 4

  # Honor an existing membership unless --reinstall.
  if [ -f "/etc/wgctl/$IFACE.json" ] && [ -z "$REINSTALL" ]; then
    log "✗ /etc/wgctl/$IFACE.json exists; pass --reinstall to re-register"
    emit token_already_bound "membership exists; --reinstall to overwrite"; exit 5
  fi

  detect_pkg
  local PYPKG=python3; [ "$PKG" = pacman ] && PYPKG=python
  command -v curl    >/dev/null 2>&1 || pkg_install curl    || true
  command -v python3 >/dev/null 2>&1 || pkg_install "$PYPKG" || true
  if ! command -v wg >/dev/null 2>&1 || ! command -v wg-quick >/dev/null 2>&1; then
    log "==> installing wireguard-tools (via $PKG)"
    pkg_install wireguard-tools || { emit requires_unmet "install wireguard-tools manually"; exit 4; }
  fi
  command -v wg >/dev/null 2>&1 && command -v wg-quick >/dev/null 2>&1 \
    || { emit requires_unmet "wg/wg-quick not found after install"; exit 4; }
  [ "$OSARG" = freebsd ] && kldload if_wg 2>/dev/null || true

  local CONFDIR; [ "$OSARG" = freebsd ] && CONFDIR=/usr/local/etc/wireguard || CONFDIR=/etc/wireguard
  mkdir -p "$CONFDIR" /etc/wgctl; chmod 0700 /etc/wgctl

  log "==> generating keypair"
  local PRIV PUB
  PRIV=$(wg genkey); PUB=$(printf '%s' "$PRIV" | wg pubkey)

  # lan_addrs: prefer iproute2; fall back to ifconfig (FreeBSD / minimal Linux).
  local LAN_JSON
  LAN_JSON=$(python3 - "$OSARG" <<'PY'
import json, re, subprocess, sys, shutil
addrs = []
if shutil.which("ip"):
    out = subprocess.run(["ip","-o","-4","addr","show"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        m = re.search(r'^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+/\d+)', line)
        if not m: continue
        ifc, cidr = m.group(1), m.group(2)
        ip = cidr.split('/')[0]
        if ifc == "lo" or ip.startswith(("127.","169.254.","10.88.")): continue
        addrs.append({"iface": ifc, "cidr": cidr})
else:
    out = subprocess.run(["ifconfig"], capture_output=True, text=True).stdout
    cur = None
    for line in out.splitlines():
        m = re.match(r'^([a-z][a-z0-9]+):', line)
        if m: cur = m.group(1); continue
        m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)\s+netmask\s+0x([0-9a-fA-F]+)', line)
        if not m: continue
        ip = m.group(1)
        if ip.startswith(("127.","169.254.","10.88.")): continue
        bits = bin(int(m.group(2),16)).count("1")
        addrs.append({"iface": cur, "cidr": f"{ip}/{bits}"})
print(json.dumps(addrs))
PY
)

  local ARCH; case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64;; arm64|aarch64) ARCH=arm64;; *) ARCH=$(uname -m);; esac
  local HOSTN; HOSTN=$(hostname -s 2>/dev/null || hostname)

  log "==> registering with $SERVER (os=$OSARG arch=$ARCH)"
  local REQ RESP
  REQ=$(TOKEN="$TOKEN" PUB="$PUB" HOSTN="$HOSTN" OSARG="$OSARG" ARCH="$ARCH" \
        LAN_JSON="$LAN_JSON" LISTEN="$LISTEN" python3 - <<'PY'
import json, os
print(json.dumps({
  "token": os.environ["TOKEN"], "pubkey": os.environ["PUB"],
  "hostname": os.environ["HOSTN"], "os": os.environ["OSARG"],
  "arch": os.environ["ARCH"], "agent_ver": "wg-agent-native-1",
  "lan_addrs": json.loads(os.environ["LAN_JSON"]),
  "wg_listen": int(os.environ["LISTEN"]), "site_slug": "",
}))
PY
)
  local RBODY RCODE
  RBODY=$(mktemp)
  RCODE=$(curl -sS -o "$RBODY" -w '%{http_code}' --max-time 20 \
            -X POST "$SERVER/v1/register" -H 'Content-Type: application/json' -d "$REQ" 2>>/dev/stderr || echo 000)
  RESP=$(cat "$RBODY"); rm -f "$RBODY"
  if [ "$RCODE" != 200 ]; then
    log "✗ register HTTP $RCODE: $(printf '%s' "$RESP" | head -c 200)"
    case "$RCODE" in
      401) emit invalid_token "register 401 — token bad/expired/revoked";;
      409) case "$RESP" in *pubkey*) emit pubkey_taken "pubkey already registered";;
                           *)        emit token_already_bound "token already consumed";; esac;;
      000) emit control_plane_unreachable "register no-response";;
      *)   emit server_error "register HTTP $RCODE";;
    esac; exit 5
  fi

  log "==> rendering $CONFDIR/$IFACE.conf"
  PRIV="$PRIV" RESP="$RESP" LISTEN="$LISTEN" CONF="$CONFDIR/$IFACE.conf" python3 - <<'PY'
import json, os, tempfile
resp = json.loads(os.environ["RESP"]); conf = os.environ["CONF"]
# Address carries the mesh /prefix so wg-quick (Table=auto) installs the mesh
# route — a /32 would isolate us even with a perfect handshake.
mp = (resp.get("mesh_cidr") or "10.88.0.0/24").split("/")[-1]
lines = ["[Interface]",
         f"PrivateKey = {os.environ['PRIV']}",
         f"Address    = {resp['device_ip']}/{mp}",
         f"ListenPort = {os.environ['LISTEN']}", ""]
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
d = os.path.dirname(conf)
with tempfile.NamedTemporaryFile("w", dir=d, delete=False, prefix=f".{os.path.basename(conf)}.") as f:
    f.write("\n".join(lines)); tmp = f.name
os.chmod(tmp, 0o600); os.replace(tmp, conf)
PY

  # State file (same shape the mac agent uses; one per iface). The agent
  # silently no-ops without it — heartbeat + peer-refresh both stop — so
  # treat write failure as fatal rather than letting the device drift.
  HUB=$(printf '%s' "$RESP" | sed -n 's/.*\(10\.88\.0\.1\).*/\1/p' | head -1); HUB="${HUB:-10.88.0.1}"
  mkdir -p /etc/wgctl && chmod 0700 /etc/wgctl
  PRIV="" RESP="$RESP" SERVER="$SERVER" TOKEN="$TOKEN" IFACE="$IFACE" LISTEN="$LISTEN" python3 - <<'PY' || \
    { log "✗ state file write failed (python error above)"; emit error "state file write failed"; exit 5; }
import json, os, sys, tempfile
try:
    resp = json.loads(os.environ["RESP"])
    state = {"server": os.environ["SERVER"], "device_id": resp["device_id"],
             "token": os.environ["TOKEN"], "wg_ip": resp["device_ip"],
             "role": resp.get("role","device"), "iface": os.environ["IFACE"],
             "wg_listen": int(os.environ["LISTEN"]), "site_id": resp.get("site_id"),
             "token_expires": resp.get("token_expires")}
    path = f"/etc/wgctl/{os.environ['IFACE']}.json"
    with tempfile.NamedTemporaryFile("w", dir="/etc/wgctl", delete=False, prefix=".st.") as f:
        json.dump(state, f, indent=2); tmp = f.name
    os.chmod(tmp, 0o600); os.replace(tmp, path)
except Exception as e:
    print(f"state-file: {type(e).__name__}: {e}", file=sys.stderr)
    sys.exit(1)
PY
  [ -s "/etc/wgctl/$IFACE.json" ] || \
    { log "✗ /etc/wgctl/$IFACE.json missing after write"; emit error "state file vanished"; exit 5; }

  log "==> bringing up $IFACE"
  if [ "$OSARG" = linux ] && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl enable "wg-quick@$IFACE" >&2 2>&1 || true
    wg-quick down "$IFACE" 2>/dev/null
    systemctl restart "wg-quick@$IFACE" >&2 2>&1 || wg-quick up "$IFACE" >&2 2>&1
  else
    wg-quick down "$IFACE" 2>/dev/null || true
    wg-quick up "$IFACE" >&2 2>&1 || { emit join_failed "wg-quick up failed"; exit 5; }
    if [ "$OSARG" = freebsd ]; then
      sysrc wireguard_enable=YES >&2 2>/dev/null || true
      sysrc "wireguard_interfaces+=$IFACE" >&2 2>/dev/null || true
    fi
  fi

  install_native_agent "$OSARG"

  sleep 4
  local HS RT PING
  HS=$(wg show "$IFACE" latest-handshakes 2>/dev/null | awk '$2>0' | wc -l | tr -d ' ')
  RT=$( { ip route 2>/dev/null || netstat -rn 2>/dev/null; } | grep -c '10\.88')
  if [ "$OSARG" = linux ]; then ping -c2 -W2 "$HUB" >/dev/null 2>&1 && PING=ok || PING=fail
  else                          ping -c2 -t5 "$HUB" >/dev/null 2>&1 && PING=ok || PING=fail; fi
  log "==> handshakes=$HS route=$RT ping($HUB)=$PING"
  if [ "$HS" -ge 1 ] && [ "$RT" -ge 1 ] && [ "$PING" = ok ]; then
    emit ok "joined $IFACE ($OSARG), hub $HUB reachable"; exit 0
  fi
  emit joined_unverified "hs=$HS route=$RT ping=$PING — run scripts/diagnose.sh"; exit 0
}

# Install the portable reconciler + a 60 s scheduler (systemd timer or cron).
install_native_agent() {
  local OSARG="$1"
  log "==> installing wg-agent (heartbeat + peer refresh, 60 s)"
  mkdir -p /usr/local/sbin
  install -m 0755 "$SELF_DIR/wg-agent.sh" /usr/local/sbin/wg-agent 2>/dev/null \
    || { cp "$SELF_DIR/wg-agent.sh" /usr/local/sbin/wg-agent && chmod 0755 /usr/local/sbin/wg-agent; }
  if [ "$OSARG" = linux ] && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    cat >/etc/systemd/system/wg-agent.service <<'EOF'
[Unit]
Description=wg-mac reconciler (heartbeat + peer refresh)
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/wg-agent
EOF
    cat >/etc/systemd/system/wg-agent.timer <<'EOF'
[Unit]
Description=run wg-agent every minute
[Timer]
OnBootSec=30
OnUnitActiveSec=60
AccuracySec=10
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload >&2 2>&1 || true
    systemctl enable --now wg-agent.timer >&2 2>&1 || true
  elif [ "$OSARG" = freebsd ]; then
    # FreeBSD base cron reads /etc/crontab (with explicit user field) and
    # per-user crontabs; /etc/cron.d/ is a Linux convention and is NOT
    # honoured by stock FreeBSD cron even when the directory exists. Use
    # /etc/crontab, idempotently. cron picks up edits on mtime change.
    if ! grep -q '/usr/local/sbin/wg-agent' /etc/crontab 2>/dev/null; then
      printf '\n# wg-mac reconciler (heartbeat + peer refresh, every 60s)\n* * * * *\troot\t/usr/local/sbin/wg-agent\n' \
        >> /etc/crontab
    fi
  elif [ -d /etc/cron.d ]; then
    printf 'SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n* * * * * root /usr/local/sbin/wg-agent\n' \
      > /etc/cron.d/wg-agent
  else
    ( crontab -l 2>/dev/null | grep -v '/usr/local/sbin/wg-agent';
      echo '* * * * * /usr/local/sbin/wg-agent' ) | crontab - 2>/dev/null || \
      log "warning: no systemd/cron — install a 60s schedule for /usr/local/sbin/wg-agent yourself"
  fi
}

case "$(uname -s)" in
  Darwin)  macos_join ;;
  Linux)   native_join linux ;;
  FreeBSD) native_join freebsd ;;
  *) log "✗ unsupported OS $(uname -s)"; emit unsupported_os "$(uname -s)"; exit 6 ;;
esac
