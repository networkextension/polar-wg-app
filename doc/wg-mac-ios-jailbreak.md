# wg-mac on jailbroken iOS

User-space WireGuard for jailbroken iPhone / iPad. The same `wg_core` and
`wgctl` binaries that ship in the macOS bundle, cross-compiled for
arm64-iphoneos and packaged as a self-extracting tarball.

This document covers:

1. [Why a separate iOS bundle](#1-why-a-separate-ios-bundle)
2. [Building from source](#2-building-from-source)
3. [Packaging](#3-packaging)
4. [Deploying to a device](#4-deploying-to-a-device)
5. [Joining a Polar mesh](#5-joining-a-polar-mesh)
6. [Auto-start at boot](#6-auto-start-at-boot)
7. [How it works — the design](#7-how-it-works--the-design)
8. [Code-signing notes](#8-code-signing-notes)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. Why a separate iOS bundle

The macOS `dist/wg-mac-<ver>.tar.gz` ships Mach-O binaries with
`platform MACOS` (LC_BUILD_VERSION). iOS's kernel rejects them at exec
time — wrong platform value, wrong linked `libSystem` path, the wrong
Swift runtime location. The iOS bundle is a separate build that
targets `arm64-apple-ios15.0`, links against the iPhoneOS SDK, and pulls
in the iOS variant of CryptoKit / Swift compat libs.

Functionally it's the same client: `wg_core` opens a utun device via
`PF_SYSTEM / SYSPROTO_CONTROL / com.apple.net.utun_control` and runs the
WireGuard handshake + dataplane in userspace. No NetworkExtension, no
PacketTunnelProvider, no containing `.app` — just a long-running
unix process under root.

## 2. Building from source

Build host: a Mac with Xcode (any version ≥ 15) installed. The script
borrows three macOS-private headers (`net/if_utun.h`,
`sys/kern_control.h`, `sys/sys_domain.h`) that iPhoneOS SDK doesn't ship;
the underlying kernel ABI is identical, so the borrowed headers work.

```sh
cd wg-mac
bash scripts/build-ios-cli.sh
```

Output:
- `build/ios-arm64/wg_core` — ~180 KB, ad-hoc signed, `platform IOS minos 15.0`
- `build/ios-arm64/wgctl` — ~120 KB, same
- `build/ios-arm64/libwg.a` + `libswift_crypto.a` — intermediates

Verify the build:

```sh
otool -lv build/ios-arm64/wg_core | grep -A2 BUILD_VERSION
# expected: platform IOS, minos 15.0
otool -L build/ios-arm64/wg_core | head -5
# expected: /usr/lib/libSystem.B.dylib + iOS-pathed CryptoKit + Swift libs
codesign -dvvv build/ios-arm64/wg_core 2>&1 | grep CDHash=
# capture this — useful if you need to whitelist via trust cache (§8)
```

## 3. Packaging

```sh
bash scripts/make-bundle-ios.sh                  # auto-versioned
bash scripts/make-bundle-ios.sh 20260531-test1   # explicit version
```

Produces `dist/wg-mac-ios-arm64-<ver>.tar.gz` (≈ 300 KB) with this layout:

```
wg-mac-ios-arm64-<ver>/
├── VERSION
├── install.sh
├── README.md
├── bin/
│   ├── wg_core
│   └── wgctl
├── sbin/
│   ├── join.sh
│   └── wgctl-agent
├── libexec/
│   └── postup.sh
└── launchd/
    └── com.wireguard.wg-mac.wg0.plist
```

## 4. Deploying to a device

Prerequisites on the device:
- Jailbroken iOS arm64 (any flavor that lets unsigned / ad-hoc-signed
  Mach-O binaries run — see [§8](#8-code-signing-notes) for what specifically
  must be relaxed).
- Root SSH access. OpenSSH from Procursus / Sileo is the default; the
  port is usually 22 but check your jailbreak.
- `bash`, `python3`, `curl` available on `$PATH`. All three are
  shipped by Procursus and most jailbreak bootstraps.
- Writable rootfs (so `/usr/local/bin/` etc. exist or can be created).

Push and unpack:

```sh
# from your build host
scp dist/wg-mac-ios-arm64-<ver>.tar.gz root@<ios-ip>:/tmp/
ssh root@<ios-ip>

# on device
cd /tmp
tar xzf wg-mac-ios-arm64-<ver>.tar.gz
cd wg-mac-ios-arm64-<ver>
bash install.sh
```

`install.sh` is idempotent: re-run to upgrade in place. It creates:

| Path                              | Mode  | Purpose                          |
|-----------------------------------|-------|----------------------------------|
| `/usr/local/bin/wg_core`          | 0755  | tunnel daemon                    |
| `/usr/local/bin/wgctl`            | 0755  | CLI (genkey, up, down, show)     |
| `/usr/local/sbin/wgctl-agent`     | 0755  | 60s reconciler (heartbeat etc.)  |
| `/usr/local/sbin/wgctl-join`      | 0755  | Polar mesh token-join helper     |
| `/usr/local/libexec/wg-mac/postup.sh` | 0755 | idempotent route re-installer  |
| `/etc/wireguard/`                 | 0700  | conf files                       |
| `/etc/wgctl/`                     | 0700  | state JSON                       |

## 5. Joining a Polar mesh

Get a `polar_wg_<32 hex>` token from the Polar admin UI
(`https://wg.4950.store:2443/wg-tokens.html`), then:

```sh
/usr/local/sbin/wgctl-join \
    --token=polar_wg_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
    --server=https://wg.4950.store:2443
```

The script:
1. Generates a Curve25519 keypair via `wgctl genkey | wgctl pubkey`.
2. Collects active LAN IPv4 addresses + prefix from `ifconfig`
   (formatted as `[{"iface": "en2", "cidr": "192.168.3.4/24"}, ...]`).
3. POSTs `/v1/register` with `os=darwin arch=arm64 agent_ver=wg-mac-ios-0.1`
   plus the token, pubkey, hostname, and LAN list. Uses `curl -k`
   because stock iOS curl on some jailbreaks lacks the full Let's
   Encrypt chain.
4. Renders `/etc/wireguard/wg0.conf` (Address = device_ip / mesh_prefix,
   one `[Peer]` per response peer) + `/etc/wgctl/config.json` (server +
   device_id + token, used by `wgctl-agent` for heartbeats).
5. Runs `wgctl up wg0`.
6. Prints `wgctl show wg0`.

`wg0` is the default iface. Pass `--iface=wg1` to use a different name.
Pass `--reinstall` to overwrite an existing `/etc/wgctl/config.json`
(the script refuses to do so by default to avoid blowing away a working
device record).

## 6. Auto-start at boot

```sh
cp /tmp/wg-mac-ios-arm64-<ver>/launchd/com.wireguard.wg-mac.wg0.plist \
   /Library/LaunchDaemons/
launchctl bootstrap system \
   /Library/LaunchDaemons/com.wireguard.wg-mac.wg0.plist
```

The plist runs `wg_core --tunnel --logical-name wg0
/etc/wireguard/wg0.conf` with `KeepAlive=true RunAtLoad=true`. Logs go to
`/var/log/wireguard.wg0.{out,err}.log`. iOS launchd accepts the same
plist format as macOS — no changes needed.

To stop:

```sh
launchctl bootout system/com.wireguard.wg-mac.wg0
```

## 7. How it works — the design

**No NetworkExtension.** The standard iOS WireGuard app uses a
`PacketTunnelProvider` — a Network Extension that the host app spawns
via `NETunnelProviderManager`. That path requires:
- A containing `.app` bundle.
- The `com.apple.developer.networking.networkextension` entitlement.
- Apple's developer-account provisioning, with the entitlement enabled.

A jailbroken device with relaxed code-signing doesn't need any of that.
The wg-mac binary creates a utun directly:

```c
fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
ioctl(fd, CTLIOCGINFO, &ci);             // ci.ctl_name = "com.apple.net.utun_control"
connect(fd, (struct sockaddr *)&sc, sizeof(sc));
getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &name_len);
```

iOS's kernel control framework (`/System/Library/Extensions/IONetworkingFamily.kext`
and friends) registers `com.apple.net.utun_control` exactly like macOS.
The only gate is whether the process is allowed to run at all — i.e.
AMFI. If AMFI lets the process exec, the utun creation path succeeds
even from a root-owned, non-NE-entitled binary.

**Routes** are installed via `route -n add -net <cidr> -interface <utun>`
inside `wg_core` after the utun is up. The `<iface>.postup` hook
(symlinked to `/usr/local/libexec/wg-mac/postup.sh` by default)
re-installs any missing routes — defense for the occasional case where
iOS flushes utun routes on sleep / network transition.

**Heartbeat / agent**: `wgctl-agent` is a portable bash reconciler that
POSTs `/v1/heartbeat` every 60 s (with the v2 `status` block — peer
roster, handshake age, byte counters), pulls `/v1/peers`, and rewrites
the conf + kickstart on diff. Schedule via launchd `StartInterval=60`
(the macOS install.sh has a sample plist).

## 8. Code-signing notes

This is the only thing about iOS vs. macOS that bites you. There are
three independent gates:

| Gate                      | What it does                                | How to relax it on a jailbreak |
|---------------------------|---------------------------------------------|--------------------------------|
| **AMFI** (kernel)         | Refuses to exec a Mach-O whose code-signature has an "unsuitable CT policy" (i.e. ad-hoc / unsigned / not in trust cache) | Most jailbreaks patch `amfid` or inject trust caches automatically. Some expose `ldid` for on-device signing. |
| **utun entitlement**      | Historically rumored to require `com.apple.developer.networking.networkextension` to create a utun | **Empirically false** on iOS 17. Once AMFI lets the binary run, utun creation is just root-level access — no entitlement check fires. |
| **launchd trust**         | launchd refuses to load plists pointing to binaries it doesn't trust | Same as AMFI — once the binary runs, the plist works. |

What the cross-compiled bundle ships:
- Both binaries are **ad-hoc signed** (`codesign -s -`) by the build
  script. CDHashes are printed at the end of `build-ios-cli.sh`.
- No entitlements are embedded. (Adding them doesn't help — AMFI
  rejects on signature policy, not entitlement absence.)

If your jailbreak doesn't auto-allow ad-hoc signed binaries:
- **Sileo / Procursus**: `apt install ldid` then on the device run
  `ldid -S /usr/local/bin/wg_core /usr/local/bin/wgctl` to re-sign with
  the jailbreak-friendly variant.
- **Dynamic trust cache** (some jailbreaks): take the CDHashes printed
  by `build-ios-cli.sh`, format them per your jailbreak's loader, and
  inject. Trust-cache format is `{ version:u32, uuid:16B, count:u32,
  entries: [cdhash:20B, hash_type:u8, flags:u8] }` wrapped in IM4P
  ASN.1 — there's a helper at `scripts/mk_trustcache.py` (private to
  this repo, see history).

## 9. Troubleshooting

**`Killed: 9` on exec, no output.** AMFI rejected the binary. Check
the kernel log:

```sh
log show --last 30s --predicate 'composedMessage CONTAINS "wg_core" OR composedMessage CONTAINS "wgctl"' --style compact
```

Look for `unsuitable CT policy` / `adhoc signed`. Fix per [§8](#8-code-signing-notes).

**`{"error":"invalid_input"}` from `/v1/register`.** Most likely the
`lan_addrs` field is a flat string array instead of an array of
`{iface, cidr}` objects. `join-ios.sh` formats it correctly; this only
bites if you're calling `/v1/register` by hand.

**SSL handshake fails (`curl: (60) Invalid certificate chain`).** The
device's curl trust store doesn't have the full Let's Encrypt
intermediate chain. The wrapper script uses `curl -k` for `/v1/register`,
but the `wgctl-agent` heartbeat needs the same treatment — either
install an updated CA bundle (Procursus: `apt install ca-certificates`)
or patch the agent to use `-k`.

**Tunnel up, handshake good, but can't reach mesh peers.** Check the
`Address` line in `/etc/wireguard/wg0.conf`. It MUST carry the mesh
prefix (e.g. `Address = 10.88.0.10/24`), not `/32`. `wg_core` only
installs the kernel network route when prefix_len < 32 — a `/32`
isolates the device. `join-ios.sh` derives the prefix from
`mesh_cidr` in the register response; if you wrote the conf by hand,
double-check.

**Routes disappear after sleep / network transition.** Expected — iOS
sometimes flushes utun routes. The `wg-postup.sh` hook re-installs
them. Make sure `/etc/wireguard/<iface>.postup` exists and is
executable (the installer creates a default symlink for `wg0`).

**No utun interface appears.** Either AMFI killed the process before
it got to `utun_open`, or your jailbreak's amfid patch is incomplete
(some only allow code already in a trust cache, not pure ad-hoc). Run
`wg_core --tunnel --logical-name wg0 /etc/wireguard/wg0.conf` in the
foreground to see why.

**`wgctl-agent` heartbeats failing 401.** The device's token was
revoked from Polar. `wgctl-agent` self-evicts the iface on 401 — it
deletes `/etc/wgctl/config.json` and tears down the tunnel. To rejoin,
ask for a fresh token and run `wgctl-join --reinstall ...`.

## See also

- `doc/JOIN_PROTOCOL.md` — `/v1/register` + `/v1/heartbeat` + `/v1/peers`
  request / response shapes.
- `doc/wg-mac-tailscale-howto.md` — operator-facing guidance on the
  `polar_wg_*` vs `tskey-*` token formats.
- `scripts/build-ios-cli.sh` — exact compile flags + Swift compat libs.
- `scripts/make-bundle-ios.sh` — exact tarball layout.
