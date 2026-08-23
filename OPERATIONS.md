# OPERATIONS — wg-mac

Operational cheat sheet for the wgctl / wg_core CLI on macOS. All commands
assume the standard install layout produced by `scripts/install.sh`:

- `/usr/local/bin/wgctl` and `/usr/local/bin/wg_core` — binaries
- `/etc/wireguard/<iface>.conf` — wg-quick-style INI config (mode 0600)
- `/var/run/wireguard/<iface>.{pid,name,sock}` — runtime files
- `/Library/LaunchDaemons/com.wireguard.wg-mac.<iface>.plist` — launchd
- `/var/log/wireguard.<iface>.{out,err}.log` — daemon logs

`<iface>` is a logical name (a-z, 0-9, _-, ≤15 chars). The actual macOS
device is a kernel-assigned `utunN`; read `/var/run/wireguard/<iface>.name`
or `wgctl show <iface>` to find it.

## Status

```bash
sudo wgctl show wg0
sudo launchctl print system/com.wireguard.wg-mac.wg0 | grep -E "state =|pid ="
sudo tail -f /var/log/wireguard.wg0.err.log
ifconfig | grep -B1 "inet 10.99"
```

## Stop / start / restart (launchd-managed)

Plain `wgctl down` will not work against a launchd-managed instance —
launchd will respawn it. Use `launchctl` instead.

```bash
# Stop (and prevent respawn)
sudo launchctl bootout system/com.wireguard.wg-mac.wg0

# Start
sudo launchctl enable system/com.wireguard.wg-mac.wg0
sudo launchctl bootstrap system /Library/LaunchDaemons/com.wireguard.wg-mac.wg0.plist

# Restart in one shot
sudo launchctl kickstart -k system/com.wireguard.wg-mac.wg0
```

## Install / uninstall

### From source tree

```bash
cd <repo>
sudo ./scripts/install.sh wg0         # builds + installs + bootstraps
sudo ./scripts/uninstall.sh wg0       # bootout + disable + remove binaries
```

`install.sh` will skip the `launchctl bootstrap` step if
`/etc/wireguard/wg0.conf` doesn't exist yet — drop a config there first.

### From a bundle (no source tree on target)

Build a portable tarball from the repo, push, extract, install:

```bash
# On the build host
cd <repo>
bash scripts/make-bundle.sh                # writes dist/wg-mac-<ver>.tar.gz

# On the target host
scp wg-mac-<ver>.tar.gz user@host:/tmp/
ssh user@host '
  cd /tmp && tar xzf wg-mac-<ver>.tar.gz && cd wg-mac-<ver>
  sudo ./scripts/install.sh wg0
'
```

The bundle ships prebuilt `arm64` binaries; install.sh auto-detects them
and skips the build step. Set `WG_SKIP_BUILD=1` to force-skip on a host
with a Makefile.

## Redeploying after a source change

```bash
cd <repo>
make all
bash scripts/make-bundle.sh
LATEST=$(ls -t dist/wg-mac-*.tar.gz | head -1)

# Push + install on remote
scp "$LATEST" user@host:/tmp/
ssh user@host "
  BUNDLE=\$(basename $LATEST)
  cd /tmp && rm -rf wg-mac-extract && mkdir wg-mac-extract
  tar xzf \$BUNDLE -C wg-mac-extract --strip-components=1
  sudo bash wg-mac-extract/scripts/install.sh wg0
"

# Install on the build host itself (requires root locally)
rm -rf /tmp/wg-mac-local && mkdir /tmp/wg-mac-local
tar xzf "$LATEST" -C /tmp/wg-mac-local --strip-components=1
sudo bash /tmp/wg-mac-local/scripts/install.sh wg0
```

## Keygen

```bash
wgctl genkey > priv.key                     # private key (clamped)
wgctl pubkey < priv.key > pub.key           # derived public key
wgctl genpsk                                # 32-byte preshared key
```

These don't require root.

## Config templates

### Initiator side (drives handshake + rekey)

```ini
[Interface]
PrivateKey = <yours>
Address    = 10.99.0.1/24
ListenPort = 51820

[Peer]
PublicKey  = <peer pubkey>
Endpoint   = <peer host>:51820
AllowedIPs = 10.99.0.2/32
PersistentKeepalive = 25
```

### Responder side (passive — peer drives)

Drop the `Endpoint` line. The peer's source address is learned from its
first packet (roaming).

```ini
[Interface]
PrivateKey = <yours>
Address    = 10.99.0.2/24
ListenPort = 51820

[Peer]
PublicKey  = <peer pubkey>
AllowedIPs = 10.99.0.1/32
```

Two-sided Endpoint configurations are supported; the rekey-jitter logic
in wg_core decorrelates the two rekey timers so they don't collide.

## Verifying interop

```bash
ping -c 3 10.99.0.2                              # local -> peer
ssh user@<peer-public-ip> 'ping -c 3 10.99.0.1'  # peer -> local

# Sustained, including rekey crossing (REKEY_AFTER_TIME = 120s)
ping -c 200 -i 1 10.99.0.2

# Throughput
dd if=/dev/urandom of=/tmp/blob bs=1M count=10
time scp -q /tmp/blob user@10.99.0.2:/tmp/blob
```

Expected on a 1 Gbps LAN: scp 10 MB in ~1–2 s; ping RTT 4–10 ms; rekey at
T+120s..150s causes one packet with elevated RTT, no drops.

## Troubleshooting

### `wgctl up` fails immediately

- Not root? `wgctl up` requires sudo.
- Config not at `/etc/wireguard/<iface>.conf`?
- `wg_core` not installed at `/usr/local/bin/wg_core`?

### Tunnel up but no traffic

- `wgctl show <iface>` — `latest handshake: never` means handshake never
  completed. Check the peer is reachable and the keys match.
- `tail /var/log/wireguard.<iface>.err.log` for `wg_encap FAILED` (no
  current keypair — usually a config mismatch) or `decap FAILED` (peer
  sent ciphertext we can't decrypt — key mismatch or replay).
- `ifconfig | grep 10.99` — the IP must be on the utun. If missing,
  `wg_core` failed to run `ifconfig` (likely permission or syntax).

### "Operation not permitted" running install.sh under osascript

macOS TCC blocks root processes spawned via `osascript with administrator
privileges` from reading user-mounted volumes (e.g. `/Volumes/...`).
Extract the bundle to `/tmp/wg-mac-local/` first, then point install.sh
there:

```bash
rm -rf /tmp/wg-mac-local && mkdir /tmp/wg-mac-local
tar xzf dist/wg-mac-<ver>.tar.gz -C /tmp/wg-mac-local --strip-components=1
sudo bash /tmp/wg-mac-local/scripts/install.sh wg0
```

### Stale wg_core after `bootout`

`launchctl bootout` ends the launchd registration but the daemon's
KeepAlive credit can carry into the ExitTimeOut window (~30s), so you
may see one or two more wg_core spawns before launchd fully releases.
`scripts/uninstall.sh` already does `launchctl disable` first, which
shortens this. To force-clear:

```bash
sudo launchctl disable system/com.wireguard.wg-mac.wg0
sudo launchctl bootout  system/com.wireguard.wg-mac.wg0
sudo pkill -9 -f "wg_core .* --logical-name wg0"
```

## Behavior reference

| Constant | Value | Where |
|---|---|---|
| `REKEY_TIMEOUT_SEC` | 5 | handshake retransmit interval |
| `REKEY_AFTER_TIME_SEC` | 120 | proactive rekey threshold |
| `REKEY_JITTER_MAX_SEC` | 30 | random rekey offset, per keypair |
| `REJECT_AFTER_TIME_SEC` | 180 | keypair becomes unusable |
| `KEEPALIVE_TIMEOUT_SEC` | 10 | inbound idle window |
| `MAX_HANDSHAKE_ATTEMPTS` | 18 | give-up threshold (~90s) |

Defined in `src/wg_core.c`.

## File map

```
/etc/wireguard/<iface>.conf            INI config (0600, root)
/usr/local/bin/wgctl                   CLI entry point
/usr/local/bin/wg_core                 tunnel daemon
/Library/LaunchDaemons/                launchd plist
  com.wireguard.wg-mac.<iface>.plist
/var/run/wireguard/                    runtime dir (0700, root)
  <iface>.pid                          wg_core PID
  <iface>.name                         kernel utun device (e.g. "utun4")
  <iface>.sock                         status-dump UNIX socket (0600)
/var/log/wireguard.<iface>.out.log     stdout
/var/log/wireguard.<iface>.err.log     stderr + trace
```
