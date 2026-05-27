# polar-wg-app

Polar's cross-platform WireGuard client. C protocol core (Noise IKpsk2, ChaCha20-Poly1305, Blake2s, Curve25519) derived from FreeBSD kernel WireGuard, adapted for sandboxed userspace runtimes — macOS / iOS NetworkExtension, Android, and a CLI reference client. Companion to [polar-dock](https://github.com/networkextension/polar-dock); pulls per-user node configs from the Latch control plane.

> Formerly published as `libwg`. The project started as a header-shim port of FreeBSD's `if_wg` and grew through 13 merged PRs into a full client app.

## Status

| Surface | Status |
|---|---|
| Protocol core in C (Noise / cookie / crypto / allowedips / session API) | done — `libwg.a` |
| CLI VPN client (`wg_core`) | done — `200/200 ping 0% loss across a 120s rekey boundary` against a Linux peer |
| `WireGuardCore.xcframework` (macOS / iOS / tvOS / visionOS, arm64 + x86_64) | done — `make xcframework` |
| macOS / iOS SwiftUI host app + PacketTunnelProvider extension | done — `WireGuardSampleApp/` |
| `wg(8)` UAPI compatibility (`get=1` / `set=1` for endpoint, allowed-ips, PSK, peer add/remove, listen_port, keepalive) | done — `sendProviderMessage` carries the wire format unchanged |
| Latch platform-node sync (server list, country flags, route mode) | done — `TunnelManager.swift` |
| Android port (gradle, wgctl/wg_core via JNI) | in tree — `WireGuardAndroid/` |
| Test suite | **27/27 PASS** — Blake2s + Curve25519 + ChaCha20-Poly1305 KATs, allowedips trie unit tests, Noise loopback, UAPI round-trips |

End-to-end NE tunnel bring-up requires an Apple Developer account and the NetworkExtension entitlement — see [NE_INTEGRATION.md](./NE_INTEGRATION.md). Everything else runs from `make` + a Linux peer.

## Architecture

```
┌──────────────── macOS / iOS App ────────────────┐
│                                                  │
│  SwiftUI (ContentView + TunnelManager)           │
│     │                                            │
│     ├─ NETunnelProviderManager                   │
│     │     install / save / start / stop          │
│     │                                            │
│     └─ sendProviderMessage("get=1" / "set=1")    │
│           │                                      │
│  ┌────────┼── Extension (.appex) ────────────┐   │
│  │        ▼                                  │   │
│  │  PacketTunnelProvider (Swift)             │   │
│  │     ├─ NEPacketTunnelFlow                 │   │
│  │     ├─ NWUDPSession                       │   │
│  │     └─ DispatchSourceTimer @1Hz           │   │
│  │             │                             │   │
│  │             ▼                             │   │
│  │  wg_session_t  (C, I/O-free; 20 exports)  │   │
│  │     ├─ wg_session_handle_udp / _tun       │   │
│  │     ├─ wg_session_tick / _kick            │   │
│  │     ├─ wg_session_get_uapi / _set_uapi    │   │
│  │     └─ callbacks: send_udp, deliver_ip,   │   │
│  │                   log                     │   │
│  └───────────────────────────────────────────┘   │
│                                                  │
│  libwg.a (C)                                     │
│     ├─ wg_noise.c       Noise IKpsk2 (FreeBSD)   │
│     ├─ wg_cookie.c      MAC1/MAC2 (FreeBSD)      │
│     ├─ wg_crypto.c      Blake2s + mbuf encrypt   │
│     ├─ wg_crypto_impl.c ChaCha20-Poly1305 (pure C)│
│     ├─ allowedips.c     IPv4/IPv6 bit trie       │
│     └─ wg_session.c     I/O-free session API     │
│                                                  │
│  libswift_crypto.a                               │
│     └─ crypto_bridge.swift  CryptoKit Curve25519 │
│                                                  │
│  WireGuardCore.xcframework                       │
│     = libwg.a + libswift_crypto.a + module.modulemap │
└──────────────────────────────────────────────────┘

           ▲
           │   sendto / recvfrom   (CLI only)
           │
  wg_core (CLI: utun + select loop, ~1800 LOC) ─→ same wg_session API
```

The C library does **no I/O**. `wg_session.c` exposes six hot-path functions (`create`, `destroy`, `handle_udp`, `handle_tun`, `tick`, `kick`) plus introspection getters. Three C callback pointers (`send_udp`, `deliver_ip`, `log_line`) let the host (Swift NE, JNI on Android, or `select()` loop in the CLI) own all packet plumbing. This is what makes the same `libwg.a` drive both a sandboxed PacketTunnelProvider and a debuggable command-line VPN.

## Repository layout

```
src/                          ← C protocol core + CLI client + KAT suite
  wg_noise.{c,h}              Noise_IKpsk2 state machine (FreeBSD, unmodified)
  wg_cookie.{c,h}             MAC1/MAC2 + cookie reply (FreeBSD, unmodified)
  wg_crypto.c                 Blake2s + ChaCha20-Poly1305 mbuf path (FreeBSD + COMPAT_NEED_BLAKE2S)
  wg_crypto_impl.c            Pure-C RFC 8439 ChaCha20-Poly1305 + XChaCha + crypto_dispatch
  allowedips.{c,h}            IPv4/IPv6 longest-prefix-match bit trie
  wg_session.{c,h}            I/O-free session API (20 exports, the NE entry point)
  wg_core.c                   CLI VPN client: utun + select + multi-peer + timers + UAPI
  crypto_bridge.swift         Curve25519 via Apple CryptoKit
  curve25519_portable.c       Portable fallback for non-Apple platforms
  crypto_vector_test.c        27-test KAT + loopback + integration suite
  macos_stubs/                FreeBSD kernel-header shims (see table below)

NetworkExtension/
  WireGuardKit/module.modulemap
  Sources/PacketTunnelProvider.swift   ← reference Swift entry point

WireGuardSampleApp/           ← macOS + iOS host app + extension target
  project.yml                 xcodegen spec; produces .xcodeproj
  project-ios.yml             iOS variant
  WireGuardSampleApp/         SwiftUI host app
  WireGuardTunnelExtension/   PacketTunnelProvider .appex
  WireGuardSampleApp-iOS/     iOS variant
  WireGuardTunnelExtension-iOS/

WireGuardSysExt/              ← macOS System Extension variant (alternate to .appex)
WireGuardAndroid/             ← Android port (gradle, JNI bridge to libwg)

scripts/
  build-xcframework.sh        Multi-platform xcframework producer (arm64 + x86_64)
  join.sh                     One-shot onboarding via a polar_wg_ token

Makefile                      libwg.a / wg_core / crypto_vector_test / xcframework
```

## Build

### Quickstart (CLI)

```bash
make              # → build/libwg.a, build/wg_core, build/crypto_vector_test
make test         # runs the 27 KATs
sudo ./build/wg_core src/client.conf  # bring up a tunnel against a real peer
```

### xcframework

```bash
make xcframework
# → build/xcframework/WireGuardCore.xcframework
```

Drop the resulting xcframework into your NetworkExtension target — see [NE_INTEGRATION.md](./NE_INTEGRATION.md) for entitlements, provider configuration, and the Swift trampoline pattern.

### macOS / iOS sample app

```bash
cd WireGuardSampleApp
# Generate the Xcode project (requires xcodegen)
xcodegen generate -s project.yml          # macOS
xcodegen generate -s project-ios.yml      # iOS
# Open WireGuardSampleApp.xcodeproj in Xcode and build.
```

Bundle IDs default to `com.change.wg` (host) and `com.change.wg.tunnel` (extension). Update the team + provisioning profile, then run.

### Android

```bash
cd WireGuardAndroid
./gradlew assembleDebug
```

### Requirements

| Tool | Version | Used for |
|---|---|---|
| macOS | 11.0+ | base build target |
| Xcode CLT | any recent | clang, swiftc |
| `xcodegen` | latest | generating sample app's `.xcodeproj` |
| Apple Developer account | — | end-to-end NE tunnel bring-up (entitlement signing) |

## Cryptography

All AEAD / Noise crypto is built into the library — no OpenSSL, no CommonCrypto, no external dependencies for the protocol core.

- **ChaCha20** — 20-round block function, keystream XOR.
- **Poly1305** — 26-bit limb arithmetic, constant-time finalize. Multi-segment `update` correctly buffers partial blocks (see PORTING_LOG.md Round 2 for the bug that bit us).
- **HChaCha20** — subkey derivation for XChaCha20.
- **Blake2s** — RFC 7693, with `COMPAT_NEED_BLAKE2S` gating the in-tree implementation when the system header is gated.
- **Curve25519** — `CryptoKit.Curve25519` via `crypto_bridge.swift` on Apple platforms, `curve25519_portable.c` elsewhere.

Verified against:
- RFC 7693 Blake2s test vectors (3 known answers + a streaming-consistency regression)
- RFC 7748 §6.1 Curve25519 KAT
- RFC 8439 §2.8.2 ChaCha20-Poly1305 KAT
- Noise IKpsk2 handshake + transport loopback
- Linux peer interop: `wg-quick` server, 200/200 ping 0% loss across a 120s rekey

## macOS stub headers (`src/macos_stubs/`)

Each FreeBSD kernel API is mapped to its nearest macOS userspace equivalent. Headers that exist on macOS but need extras use `#include_next`.

| FreeBSD kernel API | macOS replacement |
|---|---|
| `struct mtx` / `mtx_*` | `pthread_mutex_t` |
| `struct rwlock` / `rw_*` | `pthread_rwlock_t` |
| `refcount_*` | `__atomic` builtins |
| `CK_LIST_*` | `sys/queue.h` `LIST_*` |
| `NET_EPOCH_ENTER/EXIT` | no-op (single-threaded adapter) |
| `malloc(s, type, flags)` | `calloc(1, s)` macro |
| `zfree(ptr, type)` | `free(ptr)` |
| `uma_zcreate` / `uma_zalloc` / `uma_zfree` | `calloc` / `free` |
| `struct callout` / `callout_reset` | `dispatch_after` + atomic generation counter |
| `struct mbuf` / `m_append` / `m_adj` | flat `{m_data, m_len, m_pkthdr.len}` with `realloc` |
| `crypto_newsession` / `crypto_dispatch` | pure-C RFC 8439 in `wg_crypto_impl.c` |
| `sbintime_t` / `SBT_1S` | `int64_t` nanoseconds, `CLOCK_MONOTONIC` |
| `getnanotime()` | `clock_gettime(CLOCK_REALTIME, …)` |
| `SipHashX` | self-contained SipHash-c-d in `siphash.h` |
| `explicit_bzero` | volatile-loop macro (avoids SDK visibility gates) |

The FreeBSD `wg_noise.c` and `wg_cookie.c` are compiled **unmodified** — every adaptation lives in `macos_stubs/`.

## Testing

```
$ make test
... 27 tests ...
27/27 PASS
```

Coverage:

| # | Test | Type |
|---|---|---|
| 1–3 | Blake2s KAT (abc / empty / fox) | RFC 7693 |
| 4 | Blake2s streaming consistency (200B × 12 chunkings) | regression |
| 5 | Curve25519 RFC 7748 §6.1 (pubkey + DH) | RFC |
| 6 | ChaCha20-Poly1305 RFC 8439 §2.8.2 | RFC |
| 7–14 | mbuf path vs buffer path (8 lengths) | crossvalidation |
| 15–16 | ChaCha20 / XChaCha roundtrip + tamper | self-consistency |
| 17 | Noise loopback (handshake + transport) | end-to-end |
| 18–22 | allowedips trie (v4 LPM, default route, replace/remove, v6, edge) | unit |
| 23 | `wg_session` UAPI GET round-trip | integration |
| 24 | `wg_session` UAPI SET (endpoint + keepalive + aips + reject paths) | integration |
| 25 | PSK config parse + GET + SET + clear | integration |
| 26 | Peer add via UAPI SET | integration |
| 27 | Peer remove (tombstone) + re-add | integration |

Lessons from getting to 27/27 — silent-drop debugging, KAT-first discipline, wire-dump primacy — are in [PORTING_LOG.md](./PORTING_LOG.md) and [WORK_LOG.md](./WORK_LOG.md). Tl;dr: roundtrip self-tests are not KATs, and three of four debug rounds went "handshake OK → data plane silently broken" before we learned to dump wire bytes first.

## UAPI compatibility

`wg(8)`-format text frames travel over `sendProviderMessage` (NE) or directly into `wg_session_set_uapi` / `wg_session_get_uapi` (CLI). Wire format matches the kernel UAPI — `wg show <iface>` output works as-is.

| Operation | Status |
|---|---|
| `get=1` (full state dump) | ✅ canonical text |
| `set=1` endpoint | ✅ re-resolves DNS, updates `sockaddr` |
| `set=1` persistent_keepalive | ✅ |
| `set=1` replace_allowed_ips + allowed_ip | ✅ trie rebuild |
| `set=1` preshared_key | ✅ |
| `set=1` peer add (unknown public_key) | ✅ runtime allocation |
| `set=1` peer remove | ✅ tombstone semantics |
| `set=1` listen_port | ✅ |
| `set=1` private_key | ❌ rejected (security choice — would invalidate every keypair) |

## Platform-node sync (Latch integration)

When run as part of Polar (logged-in user), the app pulls a list of available WG servers from Latch:

```
APIClient.getLatchProfiles() → [LatchProfile]
    │
    ▼
LatchProxy.toWGQuickConfig()  → wg-quick text
    │
    ▼  (merge by platformProxyId; Manual peers untouched)
    ▼
TunnelManager.merge(updated)
```

🔒 platform-sourced configs are read-only in the UI; manual configs are user-editable. Country flag emojis come from the profile metadata or are guessed from server name.

## Relationship to Polar

This repo ships the **client side** of Polar's WireGuard story:
- Mesh control plane (Latch) and node lifecycle live in [polar-wg](https://github.com/networkextension/polar-wg).
- Agent-side WG bring-up / monitoring (for non-app deployments) is a skill in [polar-agent](https://github.com/networkextension/polar-agent).
- The `wg-mac-install.skill` bundle shipped in `polar-agent` releases drives the same `wg_core` CLI on macOS hosts that aren't running this app.

## License

Source files inherit FreeBSD's MIT/ISC (see per-file SPDX headers). Stub headers and net-new code (`wg_crypto_impl.c`, `wg_session.c`, `allowedips.c`, `wg_core.c`, Swift bridges, sample app) are ISC.

## See also

- [NE_INTEGRATION.md](./NE_INTEGRATION.md) — drop-in guide for NetworkExtension projects
- [WORK_LOG.md](./WORK_LOG.md) — what got built, in chronological order
- [PORTING_LOG.md](./PORTING_LOG.md) — debug post-mortems (Poly1305 partial-block, `r_idx` direction, NE routing loopback)
- [REVIEW.md](./REVIEW.md) — code review checklist
- [SECURITY.md](./SECURITY.md) — threat model + reporting
- [NEXT_STEPS.md](./NEXT_STEPS.md) — historical milestone plan (most of M1/M2/M3/M4 is done; some long-term items remain)
