# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

`polar-wg-app` (formerly `libwg`): Polar's cross-platform WireGuard **client**. A C protocol core ported from FreeBSD's kernel `if_wg` to sandboxed userspace, plus the hosts that drive it (macOS CLI, Apple NetworkExtension, Android JNI) and the device-side "join the mesh" tooling that talks to the Polar control plane (`polar-wg`, separate repo at `/Users/apple/github/Polar-/modules/polar-wg`). The control plane is at `https://wg.4950.store:2443` (not :443); mesh listen port is 1632.

## Build / test commands

```bash
make                     # build/libwg.a, build/libswift_crypto.a, build/wg_core, build/wgctl
make test                # 27-test KAT/unit/integration suite (build/crypto_vector_test) — the only automated C test
make xcframework         # build/xcframework/WireGuardCore.xcframework (macOS/iOS/tvOS/visionOS)
make build-ios           # xcframework + assert iOS slices exist
make clean
sudo ./build/wg_core /etc/wireguard/wg0.conf     # run a tunnel by hand (wg-quick-style INI)
sudo ./scripts/install.sh wg0                    # build + install to /usr/local/bin + launchd plist
sh scripts/make-bundle.sh [version]              # dist/wg-mac-<ver>.tar.gz universal (arm64+x86_64) bundle
bash scripts/build-ios-cli.sh                    # non-NE wg_core/wgctl for jailbroken iOS (build/ios-arm64/)
```

- `make` uses `/usr/bin/ar` explicitly — Homebrew binutils' `ar` produces archives the Apple linker rejects.
- There is no single-test selector in `crypto_vector_test`; it runs all 27 and prints `N/27 PASS`. Add new KATs there.
- Swift reconciler package: `cd WGAgent && swift test` (XCTest targets `WGAgentCoreTests`, `WGPlatformTests`). Use the `swift-6.3.2-RELEASE` toolchain for musl/Android cross builds, not Xcode's.
- Apple apps: `cd WireGuardSampleApp && xcodegen generate -s project.yml` (macOS) or `-s project-ios.yml` (iOS); `WireGuardSysExt/project.yml` likewise. End-to-end NE needs a Developer account + NE entitlement (see `NE_INTEGRATION.md`).
- Android: `cd WireGuardAndroid && ./gradlew assembleDebug`.
- CI: `.github/workflows/wg-agent-linux.yml` only compiles `skills/wg-mac-install/scripts/wg-agent.swift` on `swift:6.0-jammy` (deliberately old glibc so the binary runs on the 22.04 hub).

## Architecture (the big picture)

**The C library does no I/O.** Everything hangs off `src/wg_session.{h,c}`: `create/destroy/handle_udp/handle_tun/tick/kick` plus UAPI getters/setters, with three host callbacks (`send_udp`, `deliver_ip`, `log_line`). Every host owns its own packet plumbing and calls into the same `libwg.a`:

| Host | Where | I/O model |
|---|---|---|
| CLI `wg_core` (reference + debug vehicle) | `src/wg_core.c` | opens `utun` via `PF_SYSTEM`, own UDP sockets, `select()` loop, multi-peer, timers, UAPI socket for `wgctl` |
| Apple NetworkExtension | `NetworkExtension/Sources/PacketTunnelProvider.swift`, `WireGuardSampleApp/`, `WireGuardSysExt/` | `NEPacketTunnelFlow` + `NWUDPSession` + dispatch timer; `wg(8)` UAPI text travels over `sendProviderMessage` |
| Android | `WireGuardAndroid/app/src/main/cpp/wg_jni.c` | JNI bridge to the same API |

Layering under `wg_session.c`: `wg_noise.c` / `wg_cookie.c` are **unmodified FreeBSD** — never patch them; all adaptation lives in `src/macos_stubs/` (and `src/windows_stubs/`), which map kernel APIs (`mtx`, `rwlock`, `callout`, `mbuf`, `uma`, `crypto_dispatch`, epoch) onto pthreads/flat buffers/pure-C crypto. `wg_crypto_impl.c` is the pure-C RFC 8439 ChaCha20-Poly1305; Curve25519 is CryptoKit via `src/crypto_bridge.swift` on Apple (`libswift_crypto.a`, must be linked alongside `libwg.a`) and `curve25519_portable.c` elsewhere. `allowedips.c` is the LPM trie.

**`wg_core` data-plane knobs** (env vars read in `src/wg_core.c`): `WG_CONNECTED_TX=0` (rollback to plain `sendto`), `WG_TX_THREAD=1` (opt-in separate utun→udp thread; measured as loss on macOS, so off by default), `WG_TRACE=N` (per-direction packet trace cap; 0 = silent, −1 = unlimited — an uncapped trace once produced 80+ GB of stderr, so keep it capped).

**`wgctl`** (`src/wgctl.c`): user-facing CLI — `genkey/pubkey/genpsk/up/down/show` — talking to `wg_core` over `/var/run/wireguard/<iface>.sock`. Install layout: `/usr/local/bin/{wgctl,wg_core}`, `/etc/wireguard/<iface>.conf`, `/var/run/wireguard/<iface>.{pid,name,sock}`, `/Library/LaunchDaemons/com.wireguard.wg-mac.<iface>.plist`, `/var/log/wireguard.<iface>.{out,err}.log`. `<iface>` is a logical name; the real device is a kernel-assigned `utunN`. launchd-managed tunnels are restarted with `launchctl kickstart -k`, not `wgctl down` (see `OPERATIONS.md`).

**Mesh join / reconcile** (control-plane side, protocol in `doc/JOIN_PROTOCOL.md`, status block in `doc/hub-status.md`):
- `scripts/join.sh` — served by the CP at `/v1/install`; OS-detects. macOS: downloads `/v1/bundle` → `install.sh` → keygen → `POST /v1/register` → render conf + `/etc/wgctl/<iface>.json` → bootstrap launchd. Linux/FreeBSD: native kernel WireGuard + `wg-quick`. A token is consumed once; a second token means a *different* membership → next-free `wgcN`, never clobber an existing iface. The one-liner hardcodes `wgc0`, so second tunnels are done manually with `install.sh wgcN` + a unique port.
- Reconcilers (one state file per iface in `/etc/wgctl/`): `scripts/wgctl-agent.sh` (macOS, launchd every 60 s) and `skills/wg-mac-install/scripts/wg-agent.sh` (Linux/FreeBSD, systemd timer/cron). Each run: heartbeat → long-poll `/v1/peers` (or `/v1/hub/peers` for hubs) → re-render conf → restart only if changed → self-evict that iface on 401. `WGAgent/` is the in-progress Swift rewrite (`WGAgentCore` = pure logic, zero I/O; `WGPlatform` = host protocols); design in `doc/wg-agent-swift-design.md`.
- `scripts/install.sh` policy: from source always installs; from a bundle (`WG_SKIP_BUILD=1`) it never overwrites a different installed version unless `WG_UPDATE=1` — upgrading restarts live tunnels, which can cut the path you're administering the host over.

## Conventions and gotchas

- Debugging discipline from `PORTING_LOG.md`: when a handshake succeeds but data is silently dropped, dump wire bytes first; round-trip self-tests are not KATs — add a known-answer vector.
- `set=1 private_key` via UAPI is rejected on purpose.
- Interface `Address` must carry the `/24` mesh prefix; a `/32` breaks routing despite a healthy handshake.
- Secrets (`*.key`, `src/client*.conf`, `config/`) are gitignored; `dist/`, `build*/` are build output.
- Many top-level `*.md` files (`WORK_LOG*.md`, `TROUBLESHOOTING_*.md`, `NEXT_STEPS.md`, `works.md`, `todo.md`) are historical logs; `README.md`, `NE_INTEGRATION.md`, `OPERATIONS.md`, `doc/` are the current references.
