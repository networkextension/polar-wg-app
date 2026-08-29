#!/bin/bash
# wgctl-agent — periodic device-side reconciler.
#
# Multi-iface design: state lives in /etc/wgctl/<iface>.json (one file
# per mesh membership). Each iface gets independent heartbeat + peer
# refresh; revoking one token only takes that iface down, the rest
# keep running.
#
# Invoked by launchd every refresh_sec seconds (default 60). Per
# iface, each run:
#   1. POST /v1/heartbeat   (best-effort; lets admin UI show last-seen)
#   2. GET  /v1/peers       (or /v1/hub/peers if role==hub)
#   3. Render a fresh /etc/wireguard/<iface>.conf from the response
#   4. If conf changed, launchctl kickstart -k to pick up new peers
#   5. If server returns 401 invalid_device_token: self-evict THIS iface
#      (bootout + delete conf + delete state; don't touch siblings)
#
# Fail-soft: a bad server response leaves the existing conf alone;
# wg_core keeps running with the last good peer list. Only an explicit
# auth-rejected response triggers eviction.
#
# Base system only — no python3. /usr/bin/python3 is a Command Line Tools
# *stub* that fails on a Mac without Xcode CLT, which used to leave such a
# host joined but never reconciling. JSON is read with plutil(1), written
# with printf, and `wgctl show` is parsed with awk.
#
# Run: /usr/local/sbin/wgctl-agent
# Logs: /var/log/wgctl-agent.log

set -u

STATE_DIR=/etc/wgctl
LOG=/var/log/wgctl-agent.log
RUNDIR=/var/run/wireguard

# Long-poll tuning (env-overridable for tests). Each invocation runs a
# bounded long-poll loop up to LP_BUDGET sec then exits, so launchd relaunches
# it (StartInterval=60 > LP_BUDGET ⇒ no overlap). LP_WAIT is what we ask the
# server to hold a connection open. Against a server that does NOT support
# long-poll the loop auto-degrades to a single fetch (no busy-loop) — see
# peer_refresh_loop. LP_MIN_RETURN is the "fast return" threshold used to tell
# a held connection from a server that ignores ?wait.
LP_BUDGET=${WGCTL_LP_BUDGET:-55}
LP_WAIT=${WGCTL_LP_WAIT:-45}
LP_MIN_RETURN=${WGCTL_LP_MIN_RETURN:-5}
LP_FLOOR=${WGCTL_LP_FLOOR:-10}

log() {
    printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$LOG"
}

die() {
    log "ERROR $*"
    exit 1
}

[[ $EUID -eq 0 ]] || die "must run as root"

# ── JSON helpers (plutil + printf; no python) ────────────────────────────────
# plutil parses JSON natively and ships in the macOS base system. Keep these
# byte-identical to the copies in scripts/join.sh — the two render the same
# conf, and any drift makes the agent rewrite (and restart) a tunnel that
# join.sh just wrote.
#   jget   FILE KEYPATH → scalar at KEYPATH; "" when absent or JSON null
#   jcount FILE KEYPATH → element count of an array/dict; 0 when absent
#   json_esc STR        → STR escaped for use inside a JSON string literal
# Gate on plutil's exit status, never on its output: macOS 14's plutil prints
# "Could not extract value ..." to *stdout* (macOS 26+ uses stderr), so a
# missing key would otherwise be substituted into the conf as if it were data.
jget() {
    local v
    v=$(plutil -extract "$2" raw -o - -- "$1" 2>/dev/null) || return 0
    printf '%s' "$v"
}
jcount() {
    local v
    v=$(plutil -extract "$2" raw -o - -- "$1" 2>/dev/null) || { printf 0; return 0; }
    case "$v" in ""|*[!0-9]*) printf 0;; *) printf '%s' "$v";; esac
}
json_esc() { printf '%s' "$1" | tr -d '[:cntrl:]' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

# lan_addrs — skip loopback, link-local and our own mesh subnet (reporting
# 10.88.x back as a LAN would confuse server-side site detection). The netmask
# arrives as hex (0xffffff00), so the prefix length is a per-nibble popcount.
lan_addrs_json() {
    /sbin/ifconfig | LC_ALL=C awk '
        BEGIN { split("0 1 1 2 1 2 2 3 1 2 2 3 2 3 3 4", pc); hex = "0123456789abcdef" }
        /^[a-z][a-z0-9]*:/ { iface = substr($1, 1, length($1) - 1); next }
        $1 == "inet" && $3 == "netmask" {
            ip = $2; mask = $4
            if (ip ~ /^127\./ || ip ~ /^169\.254\./ || ip ~ /^10\.88\./) next
            sub(/^0[xX]/, "", mask)
            bits = 0
            for (k = 1; k <= length(mask); k++)
                bits += pc[index(hex, tolower(substr(mask, k, 1)))]
            out = out (out == "" ? "" : ",") \
                  "{\"iface\":\"" iface "\",\"cidr\":\"" ip "/" bits "\"}"
        }
        END { print "[" out "]" }'
}

# ── public egress IP ─────────────────────────────────────────────────
# wg_endpoint is documented as the "public observed peer" (JOIN_PROTOCOL
# §heartbeat), but this used to report the default NIC's own address —
# behind NAT that is an RFC1918 address, never the egress IP, so an
# egress change was invisible to the control plane. Ask an external echo
# service instead.
#
# Cached: ifconfig.co asks for <=1 request/min per source IP and every
# device behind one NAT shares that budget, so a 60s heartbeat must not
# probe every tick. When every probe fails we keep serving the last known
# IP (stale beats nothing) and retry sooner than the full TTL.
PUBIP_CACHE=$STATE_DIR/public_ip
PUBIP_TTL=${WGCTL_PUBIP_TTL:-900}
PUBIP_RETRY=${WGCTL_PUBIP_RETRY:-120}
PUBIP_URLS=${WGCTL_PUBIP_URLS:-"https://ifconfig.co/ip https://ifconfig.me/ip"}

public_ip() {
    local now stamp cached url fresh
    now=$(date +%s)
    stamp=0; cached=""
    if [[ -r "$PUBIP_CACHE" ]]; then
        read -r stamp cached < "$PUBIP_CACHE" 2>/dev/null || { stamp=0; cached=""; }
        [[ "$stamp" =~ ^[0-9]+$ ]] || stamp=0
    fi
    if [[ -n "$cached" ]] && (( now - stamp < PUBIP_TTL )); then
        printf '%s' "$cached"
        return
    fi
    for url in $PUBIP_URLS; do
        fresh=$(curl -4 -fsS --connect-timeout 3 --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]')
        [[ "$fresh" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || continue
        printf '%s %s\n' "$now" "$fresh" > "$PUBIP_CACHE"
        [[ "$fresh" == "$cached" ]] || log "public egress IP: ${cached:-none} -> $fresh"
        printf '%s' "$fresh"
        return
    done
    printf '%s %s\n' "$(( now - PUBIP_TTL + PUBIP_RETRY ))" "$cached" > "$PUBIP_CACHE"
    printf '%s' "$cached"
}

# ── host-level facts (same for every iface this tick; see doc/hub-status.md) ──
HOST_OS=$(uname -s | tr '[:upper:]' '[:lower:]')   # darwin / linux / freebsd
case "$(uname -m)" in
    x86_64|amd64)  HOST_ARCH=amd64 ;;
    arm64|aarch64) HOST_ARCH=arm64 ;;
    *)             HOST_ARCH=$(uname -m) ;;
esac
# Host uptime in seconds (best-effort; emitted as null when unknown).
if [[ -r /proc/uptime ]]; then
    HOST_UPTIME=$(cut -d. -f1 /proc/uptime)        # Linux
else
    _boot=$(sysctl -n kern.boottime 2>/dev/null | sed -n 's/.*sec = \([0-9]*\).*/\1/p')
    [[ -n "$_boot" ]] && HOST_UPTIME=$(( $(date +%s) - _boot )) || HOST_UPTIME=""
fi
# Agent version: bundle leaves it here at install; "unknown" otherwise.
# install.sh writes $PREFIX/libexec/wg-mac/VERSION; the share/ path never
# existed, so agent_ver was always "unknown". Keep share/ as a fallback for
# any host that predates the fix.
AGENT_VER=$(cat /usr/local/libexec/wg-mac/VERSION /usr/local/share/wg-mac/VERSION 2>/dev/null | head -1)
[[ -n "$AGENT_VER" ]] || AGENT_VER="unknown"

# Migration: old single-file layout /etc/wgctl/config.json gets
# renamed to /etc/wgctl/<iface>.json (iface from inside, default wgc0).
if [[ -f "$STATE_DIR/config.json" ]]; then
    legacy_iface=$(jget "$STATE_DIR/config.json" iface)
    [[ -n "$legacy_iface" ]] || legacy_iface=wgc0
    if [[ ! -f "$STATE_DIR/$legacy_iface.json" ]]; then
        mv "$STATE_DIR/config.json" "$STATE_DIR/$legacy_iface.json"
        log "migrated config.json -> $legacy_iface.json"
    else
        rm -f "$STATE_DIR/config.json"
    fi
fi

# Defensive route reconcile — runs unconditionally each tick (called both
# from the no-state-files early-exit and after process_iface). wg_core
# installs AllowedIPs routes at startup, but macOS occasionally flushes
# utun routes (sleep/wake, primary-iface flip). Idempotent: existing
# routes are left alone, missing or stale ones are re-installed.
# Decoupled from /etc/wgctl/*.json so a hub bootstrapped manually (no
# register flow, no state file) still gets this coverage.
reconcile_routes() {
    shopt -s nullglob
    for conf in /etc/wireguard/*.conf; do
        local iface; iface=$(basename "$conf" .conf)
        local hook="/etc/wireguard/$iface.postup"
        [[ -x "$hook" ]] || continue
        "$hook" "$iface" "$conf" >>"$LOG" 2>&1 || true
    done
}

# ── peer refresh: one fetch ──────────────────────────────────────────────────
# Fetch the peer list once and reconcile the iface conf. With WAIT>0 the URL
# carries long-poll params (?wait/?rev) and the server may hold the request up
# to WAIT seconds; REV is the opaque cursor from the last applied response,
# omitted when empty (cold start → full list immediately).
# Returns via globals:
#   PR_OUTCOME  applied | unchanged | notmod | error
#   PR_ELAPSED  seconds the request took (used to detect a held connection)
#   PR_NEWREV   server's current rev for this view (may be empty)
peer_refresh_once() {
    local IFACE="$1" SERVER="$2" TOKEN="$3" DEVICE_ID="$4" ROLE="$5" WAIT="$6" REV="$7"
    PR_OUTCOME=error; PR_ELAPSED=0; PR_NEWREV=""

    local base
    case "$ROLE" in
        hub) base="$SERVER/v1/hub/peers" ;;
        *)   base="$SERVER/v1/peers" ;;
    esac
    local url="$base" maxt=10
    if [[ "$WAIT" -gt 0 ]]; then
        url="$base?wait=$WAIT"
        [[ -n "$REV" ]] && url="$url&rev=$(printf '%s' "$REV" | sed 's/[^A-Za-z0-9._-]/-/g')"
        maxt=$((WAIT + 10))
    fi

    local resp t0 t1 code
    resp=$(mktemp)
    t0=$(date +%s)
    code=$(curl -sS -o "$resp" -w '%{http_code}' --max-time "$maxt" \
        "$url" \
        -H "Authorization: Bearer $TOKEN" \
        -H "X-Device-Id: $DEVICE_ID" 2>>"$LOG" || echo "000")
    t1=$(date +%s)
    PR_ELAPSED=$((t1 - t0))

    if [[ "$code" != "200" ]]; then
        log "[$IFACE] peers HTTP $code: $(head -c 200 "$resp" 2>/dev/null)"
        rm -f "$resp"; PR_OUTCOME=error; return
    fi

    # Long-poll "nothing changed" sentinel: server held the request until the
    # wait elapsed without a peer-set change. This is also how we know the
    # server supports long-poll at all.
    if [[ "$(jget "$resp" not_modified)" == "true" ]]; then
        PR_NEWREV=$(jget "$resp" rev)
        rm -f "$resp"; PR_OUTCOME=notmod; return
    fi

    # Full list. Capture the server rev (empty against a server that doesn't
    # send one yet — that keeps us in single-fetch mode, i.e. today's behavior).
    PR_NEWREV=$(jget "$resp" rev)

    local NEW_CONF CUR_CONF="/etc/wireguard/$IFACE.conf"
    NEW_CONF=$(mktemp)

    # Carry the identity forward from the live conf; only the peer set is
    # server-supplied. A conf with no PrivateKey means something else has
    # already broken it — leave it alone rather than installing a keyless one.
    local C_PRIV C_ADDR C_LISTEN
    C_PRIV=$(sed -n 's/^[[:space:]]*PrivateKey[[:space:]]*=[[:space:]]*//p' "$CUR_CONF" 2>/dev/null | head -1 | tr -d '[:space:]')
    C_ADDR=$(sed -n 's/^[[:space:]]*Address[[:space:]]*=[[:space:]]*//p'    "$CUR_CONF" 2>/dev/null | head -1 | tr -d '[:space:]')
    C_LISTEN=$(sed -n 's/^[[:space:]]*ListenPort[[:space:]]*=[[:space:]]*//p' "$CUR_CONF" 2>/dev/null | head -1 | tr -d '[:space:]')
    if [[ -z "$C_PRIV" ]]; then
        log "[$IFACE] no PrivateKey in $CUR_CONF; leaving conf alone"
        rm -f "$NEW_CONF" "$resp"; PR_OUTCOME=error; return
    fi
    [[ -n "$C_ADDR" ]]   || C_ADDR="$(jget "$resp" device_ip)/24"
    [[ -n "$C_LISTEN" ]] || C_LISTEN=1632

    local KEEPALIVE NPEERS p PUBKEY WGIP AIPS NEXTRA e EXTRA ENDPOINT
    KEEPALIVE=$(jget "$resp" keepalive_sec)
    [[ -n "$KEEPALIVE" ]] || KEEPALIVE=25
    {
        echo "[Interface]"
        echo "PrivateKey = $C_PRIV"
        echo "Address    = $C_ADDR"
        echo "ListenPort = $C_LISTEN"
        NPEERS=$(jcount "$resp" peers)
        p=0
        while [[ $p -lt $NPEERS ]]; do
            PUBKEY=$(jget "$resp" "peers.$p.pubkey")
            if [[ -z "$PUBKEY" ]]; then p=$((p + 1)); continue; fi
            WGIP=$(jget "$resp" "peers.$p.wg_ip")
            AIPS=""
            if [[ -n "$WGIP" ]]; then
                case "$WGIP" in */*) AIPS="$WGIP";; *) AIPS="$WGIP/32";; esac
            fi
            NEXTRA=$(jcount "$resp" "peers.$p.allowed_extra")
            e=0
            while [[ $e -lt $NEXTRA ]]; do
                EXTRA=$(jget "$resp" "peers.$p.allowed_extra.$e")
                [[ -n "$EXTRA" ]] && AIPS="${AIPS:+$AIPS, }$EXTRA"
                e=$((e + 1))
            done
            if [[ -z "$AIPS" ]]; then p=$((p + 1)); continue; fi
            echo ""
            echo "[Peer]"
            echo "PublicKey  = $PUBKEY"
            ENDPOINT=$(jget "$resp" "peers.$p.endpoint")
            [[ -n "$ENDPOINT" ]] && echo "Endpoint   = $ENDPOINT"
            echo "AllowedIPs = $AIPS"
            [[ "$KEEPALIVE" != "0" ]] && echo "PersistentKeepalive = $KEEPALIVE"
            p=$((p + 1))
        done
    } > "$NEW_CONF"

    if [[ -f "$CUR_CONF" ]] && cmp -s "$NEW_CONF" "$CUR_CONF"; then
        PR_OUTCOME=unchanged
    else
        install -m 0600 "$NEW_CONF" "$CUR_CONF"
        log "[$IFACE] conf changed; kickstart wg-mac.$IFACE"
        launchctl kickstart -k "system/com.wireguard.wg-mac.$IFACE" 2>>"$LOG" || true
        PR_OUTCOME=applied
    fi
    rm -f "$NEW_CONF" "$resp"
}

# Persist the rev cursor only after a response we actually applied/saw, atomically.
save_rev() {  # iface, rev
    [[ -n "$2" ]] || return 0
    printf '%s\n' "$2" > "$RUNDIR/$1.rev.tmp" 2>/dev/null && mv "$RUNDIR/$1.rev.tmp" "$RUNDIR/$1.rev" 2>/dev/null
}

# ── peer refresh: bounded long-poll loop ─────────────────────────────────────
# Runs up to LP_BUDGET seconds, then returns so launchd relaunches. Auto-detects
# server long-poll support (probe → trial → longpoll) and degrades to a single
# fetch — never a busy-loop — against a server that ignores ?wait/?rev.
peer_refresh_loop() {
    local IFACE="$1" SERVER="$2" TOKEN="$3" DEVICE_ID="$4" ROLE="$5"
    local rev; rev=$(cat "$RUNDIR/$IFACE.rev" 2>/dev/null)
    local deadline=$(( $(date +%s) + LP_BUDGET ))
    local mode="probe" wait_for=0

    while :; do
        local now remaining
        now=$(date +%s); remaining=$(( deadline - now ))
        [[ $remaining -le 1 ]] && break
        if [[ "$mode" == "longpoll" || "$mode" == "trial" ]]; then
            wait_for=$LP_WAIT
            [[ $wait_for -gt $remaining ]] && wait_for=$remaining
            [[ $wait_for -lt 1 ]] && break
        fi

        peer_refresh_once "$IFACE" "$SERVER" "$TOKEN" "$DEVICE_ID" "$ROLE" "$wait_for" "$rev"

        if [[ -n "$PR_NEWREV" && "$PR_NEWREV" != "$rev" ]]; then
            save_rev "$IFACE" "$PR_NEWREV"; rev="$PR_NEWREV"
        fi

        case "$PR_OUTCOME" in
            error)  break ;;                 # network/5xx: don't hammer
            notmod) mode="longpoll"; continue ;;   # server held it → supported
        esac

        # applied / unchanged:
        case "$mode" in
            probe)
                [[ -z "$PR_NEWREV" ]] && break       # legacy server (no rev) → done
                mode="trial"; continue               # has rev; try a real long-poll
                ;;
            trial)
                if [[ $PR_ELAPSED -ge $LP_MIN_RETURN ]]; then
                    mode="longpoll"; continue        # server blocked → supported
                fi
                log "[$IFACE] server ignores ?wait (${PR_ELAPSED}s); single-fetch mode"
                break                                # not long-poll → no busy-loop
                ;;
            longpoll)
                # Guard a misbehaving server that returns instantly with no change.
                if [[ $PR_ELAPSED -lt $LP_MIN_RETURN && "$PR_OUTCOME" == "unchanged" ]]; then
                    [[ $(( deadline - $(date +%s) )) -le $LP_FLOOR ]] && break
                    sleep "$LP_FLOOR"
                fi
                continue
                ;;
        esac
    done
}

mkdir -p "$RUNDIR" 2>/dev/null || true

# Walk every state file. /etc/wgctl/<iface>.json is the canonical form.
shopt -s nullglob
state_files=("$STATE_DIR"/*.json)
if [[ ${#state_files[@]} -eq 0 ]]; then
    # No mesh memberships → skip heartbeat/peer-refresh, but still run
    # the route reconcile pass: a host can be on a wg iface without
    # going through /v1/register (manually-configured hub, legacy
    # install). Reconcile is cheap and noop-on-good-state.
    log "no state files in $STATE_DIR; route-reconcile only"
    reconcile_routes
    exit 0
fi

# Long-poll only with a single mesh iface: a ~45s hold on one iface must not
# starve another iface's heartbeat. Multi-iface hosts keep today's per-iface
# single fetch (≈60s propagation), which is no regression.
LONGPOLL_OK=0
[[ ${#state_files[@]} -eq 1 ]] && LONGPOLL_OK=1

# --- per-iface reconcile loop ---
process_iface() {
    local STATE="$1"
    local IFACE
    IFACE=$(basename "$STATE" .json)

    SERVER=$(jget "$STATE" server); SERVER="${SERVER%/}"
    DEVICE_ID=$(jget "$STATE" device_id)
    TOKEN=$(jget "$STATE" token)
    ROLE=$(jget "$STATE" role);           [[ -n "$ROLE" ]]      || ROLE=device
    WG_LISTEN=$(jget "$STATE" wg_listen); [[ -n "$WG_LISTEN" ]] || WG_LISTEN=1632

    if [[ -z "$SERVER" || -z "$DEVICE_ID" || -z "$TOKEN" ]]; then
        log "[$IFACE] state missing server/device_id/token; skipping"
        return
    fi

    # ----- wg stats + per-peer status for heartbeat (doc/hub-status.md) -----
    # One pass over `wgctl show <iface>` builds both the legacy aggregate
    # `stats` and the v2 `status` block (per-peer roster). For a hub this
    # roster is the authoritative "who's online" view of the whole mesh.
    local SHOW
    SHOW=""
    [[ -x /usr/local/bin/wgctl ]] && SHOW=$(/usr/local/bin/wgctl show "$IFACE" 2>/dev/null)
    # Two lines out of awk: the legacy aggregate `stats`, then the v2 `status`
    # block. wg_core prints "peer #0: <pub>", upstream wg prints "peer: <pub>";
    # both are accepted (matching only the latter once left every counter at 0).
    local COMBO
    COMBO=$(printf '%s\n' "$SHOW" | LC_ALL=C awk \
        -v role="$ROLE" -v iface="$IFACE" -v listen="$WG_LISTEN" \
        -v host_os="$HOST_OS" -v host_arch="$HOST_ARCH" \
        -v uptime="$HOST_UPTIME" -v agent_ver="$AGENT_VER" '
    function jesc(v) { gsub(/\\/, "\\\\", v); gsub(/"/, "\\\"", v); return v }
    function jstr(v) { return (v == "" ? "null" : "\"" jesc(v) "\"") }
    function tob(num, unit) { return int((num + 0) * (unit in UNIT ? UNIT[unit] : 1)) }
    function hsecs(t,   sec, part, q, u, rest) {
        sec = 0; rest = t
        while (match(rest, /[0-9]+[ \t]+(day|hour|minute|second)/)) {
            part = substr(rest, RSTART, RLENGTH)
            split(part, q, /[ \t]+/)
            u = q[2]
            sec += (q[1] + 0) * (u == "day" ? 86400 : \
                                (u == "hour" ? 3600 : (u == "minute" ? 60 : 1)))
            rest = substr(rest, RSTART + RLENGTH)
        }
        return sec
    }
    BEGIN {
        UNIT["B"] = 1; UNIT["KiB"] = 1024; UNIT["MiB"] = 1048576
        UNIT["GiB"] = 1073741824; UNIT["TiB"] = 1099511627776
        np = 0; cur = 0; seen = 0
    }
    {
        s = $0
        sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s)
        if (s == "") next
        seen = 1
        if (s ~ /^peer([ \t]+#[0-9]+)?:[ \t]+[^ \t]/) {
            nf = split(s, f, /[ \t]+/)
            np++; cur = np
            pub[cur] = f[nf]; rx[cur] = 0; tx[cur] = 0; hsset[cur] = 0
            next
        }
        if (cur == 0) next
        if (s ~ /^endpoint:[ \t]/) {
            nf = split(s, f, /[ \t]+/); ep[cur] = f[nf]; next
        }
        if (s ~ /^allowed ips:[ \t]/) {
            t = s; sub(/^allowed ips:[ \t]*/, "", t)
            split(t, c, ",")
            v = c[1]; sub(/^[ \t]+/, "", v); sub(/[ \t]+$/, "", v)
            split(v, g, "/"); wgip[cur] = g[1]; next
        }
        if (s ~ /^latest handshake:[ \t]/ && s ~ /[ \t]ago$/) {
            t = s; sub(/^latest handshake:[ \t]*/, "", t); sub(/[ \t]+ago$/, "", t)
            hs[cur] = hsecs(t); hsset[cur] = 1; next
        }
        if (s ~ /^transfer:[ \t]/) {
            nf = split(s, f, /[ \t]+/)
            if (nf >= 7 && f[4] ~ /^received/ && f[7] ~ /^sent/) {
                rx[cur] = tob(f[2], f[3]); tx[cur] = tob(f[5], f[6])
            }
            next
        }
    }
    END {
        online = 0; minh = -1; rxs = 0; txs = 0; plist = ""
        for (k = 1; k <= np; k++) {
            rxs += rx[k]; txs += tx[k]
            up = (hsset[k] && hs[k] < 180)
            if (up) online++
            if (hsset[k] && (minh < 0 || hs[k] < minh)) minh = hs[k]
            plist = plist (k > 1 ? "," : "") \
                "{\"pubkey\":" jstr(pub[k]) \
                ",\"wg_ip\":" jstr(wgip[k]) \
                ",\"endpoint\":" jstr(ep[k]) \
                ",\"last_handshake_sec\":" (hsset[k] ? hs[k] "" : "null") \
                ",\"rx_bytes\":" rx[k] + 0 \
                ",\"tx_bytes\":" tx[k] + 0 \
                ",\"online\":" (up ? "true" : "false") "}"
        }
        if (minh < 0) minh = 0
        printf "{\"rx_bytes\":%d,\"tx_bytes\":%d,\"last_handshake_sec\":%d}\n",
               rxs, txs, minh
        printf "{\"schema\":1,\"role\":\"%s\",\"os\":\"%s\",\"arch\":\"%s\"", \
               jesc(role), jesc(host_os), jesc(host_arch)
        printf ",\"agent_ver\":\"%s\",\"iface\":\"%s\",\"iface_up\":%s", \
               jesc(agent_ver == "" ? "unknown" : agent_ver), jesc(iface), \
               (seen ? "true" : "false")
        printf ",\"uptime_sec\":%s,\"wg_listen\":%d", \
               (uptime ~ /^[0-9]+$/ ? uptime "" : "null"), \
               (listen == "" ? 1632 : listen)
        printf ",\"peer_count\":%d,\"peers_online\":%d,\"peers\":[%s]}\n", \
               np, online, plist
    }')
    local STATS_JSON STATUS_JSON
    STATS_JSON=$(printf '%s\n' "$COMBO" | sed -n 1p)
    STATUS_JSON=$(printf '%s\n' "$COMBO" | sed -n 2p)
    [[ -n "$STATS_JSON"  ]] || STATS_JSON='{}'
    [[ -n "$STATUS_JSON" ]] || STATUS_JSON='{}'


    # ----- public egress IP (external echo service, cached) -----
    local PUB_IP WG_ENDPOINT
    PUB_IP=$(public_ip)
    # Blank on total lookup failure, deliberately: the server keeps the
    # previous endpoint when this field is empty, whereas the ":$WG_LISTEN"
    # a failed lookup used to yield overwrote it with junk.
    WG_ENDPOINT=""
    [[ -n "$PUB_IP" ]] && WG_ENDPOINT="$PUB_IP:$WG_LISTEN"

    local LAN_JSON
    LAN_JSON=$(lan_addrs_json)

    # ----- 1. heartbeat -----
    local HB_BODY HB_STATUS HB_RESP
    HB_BODY=$(printf '{"lan_addrs":%s,"wg_endpoint":"%s","stats":%s,"status":%s}' \
        "$LAN_JSON" "$(json_esc "$WG_ENDPOINT")" "$STATS_JSON" "$STATUS_JSON")
    HB_RESP=$(mktemp)
    HB_STATUS=$(curl -sS -o "$HB_RESP" -w '%{http_code}' --max-time 10 \
        -X POST "$SERVER/v1/heartbeat" \
        -H "Authorization: Bearer $TOKEN" \
        -H "X-Device-Id: $DEVICE_ID" \
        -H 'Content-Type: application/json' \
        -d "$HB_BODY" 2>>"$LOG" || echo "000")
    local HB_BODY_BACK
    HB_BODY_BACK=$(cat "$HB_RESP" 2>/dev/null)
    rm -f "$HB_RESP"
    if [[ "$HB_STATUS" != "200" ]]; then
        log "[$IFACE] heartbeat HTTP $HB_STATUS: $(printf '%s' "$HB_BODY_BACK" | head -c 200)"
    fi

    # ----- 2. policy: server-rejected token → evict THIS iface -----
    if [[ "$HB_STATUS" == "401" ]] && \
       echo "$HB_BODY_BACK" | grep -qE 'invalid device token|token expired|token does not match'; then
        log "[$IFACE] EVICT: server rejected token; tearing down"
        launchctl bootout system/com.wireguard.wg-mac."$IFACE" 2>>"$LOG" || true
        launchctl disable system/com.wireguard.wg-mac."$IFACE" 2>>"$LOG" || true
        rm -f "/etc/wireguard/$IFACE.conf"
        rm -f "/var/run/wireguard/$IFACE.pid" \
              "/var/run/wireguard/$IFACE.sock" \
              "/var/run/wireguard/$IFACE.name" \
              "/var/run/wireguard/$IFACE.rev"
        rm -f "$STATE"
        # Don't touch other ifaces or the agent itself — siblings keep
        # running. Agent will see one fewer state file next tick.
        log "[$IFACE] EVICT: done"
        return
    fi

    # ----- 3. peer list refresh -----
    # Single mesh iface → bounded long-poll loop (near-instant propagation when
    # the server supports it, auto-degrades otherwise). Multi-iface → one
    # immediate fetch per iface (today's behavior), so no iface starves another.
    if [[ "${LONGPOLL_OK:-0}" == 1 ]]; then
        peer_refresh_loop "$IFACE" "$SERVER" "$TOKEN" "$DEVICE_ID" "$ROLE"
    else
        local rev0; rev0=$(cat "$RUNDIR/$IFACE.rev" 2>/dev/null)
        peer_refresh_once "$IFACE" "$SERVER" "$TOKEN" "$DEVICE_ID" "$ROLE" 0 "$rev0"
        [[ -n "$PR_NEWREV" && "$PR_NEWREV" != "$rev0" ]] && save_rev "$IFACE" "$PR_NEWREV"
    fi
}

for s in "${state_files[@]}"; do
    process_iface "$s"
done

# After peer-refresh has had a chance to install a fresh conf, walk every
# wg iface on the host and reconcile its routes. Runs unconditionally.
reconcile_routes
