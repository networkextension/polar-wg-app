# wg – WireGuard Noise on macOS (userspace port)

Porting the FreeBSD kernel WireGuard implementation (`if_wg`) to macOS userspace,
targeting the **Network Extension / PacketTunnelProvider** architecture.

---

## Repository layout

```
wg/
├── Makefile
├── README.md
├── works.md                    # Architecture notes (CN)
├── todo.md                     # Next-step planning notes (CN)
└── src/
    ├── wg_noise.c              # Noise IKpsk2 state machine      ✓ ported
    ├── wg_cookie.c             # Anti-DDoS cookie mechanism      ✓ ported
    ├── wg_crypto.c             # Blake2s + ChaCha20-Poly1305     ✓ ported
    ├── wg_crypto_impl.c        # Pure-C RFC 8439 + crypto_dispatch ✓ new
    ├── crypto.h                # Inline crypto wrappers
    ├── if_wg.c / .h            # Interface logic                 (pending)
    ├── compat.h                # Compat flag (COMPAT_NEED_BLAKE2S)
    ├── version.h
    ├── opt_inet.h              # #define INET  1
    ├── opt_inet6.h             # #define INET6 1
    └── macos_stubs/            # FreeBSD → macOS header shims
        ├── sys/
        │   ├── param.h         # sbintime, atomics, compiler hints
        │   ├── systm.h         # getnanotime, explicit_bzero, queue + callout pulls
        │   ├── callout.h       # struct callout → GCD dispatch_after
        │   ├── ck.h            # CK_LIST → sys/queue.h LIST
        │   ├── endian.h        # wraps real macOS endian.h
        │   ├── epoch.h         # NET_EPOCH_* no-ops
        │   ├── kernel.h        # MALLOC_DEFINE
        │   ├── lock.h          # RA_* assertion flags
        │   ├── malloc.h        # 3-arg malloc → calloc
        │   ├── mbuf.h          # struct mbuf flat-buffer + m_append/m_adj
        │   ├── mutex.h         # struct mtx → pthread_mutex_t
        │   ├── refcount.h      # atomic refcount helpers
        │   └── rwlock.h        # struct rwlock → pthread_rwlock_t
        ├── netinet/
        │   └── in.h            # #include_next + satosin/satosin6
        ├── vm/
        │   └── uma.h           # UMA allocator → calloc/free
        ├── opencrypto/
        │   └── cryptodev.h     # crypto session types + POLY1305_HASH_LEN
        └── crypto/
            ├── siphash/
            │   └── siphash.h   # self-contained SipHash-c-d
            ├── chacha20_poly1305.h  # prototypes (impl in wg_crypto_impl.c)
            └── curve25519.h        # prototypes (impl pending)
```

---

## Architecture

The port follows the three-layer model described in `works.md`:

```
┌─────────────────────────────────────────────────────┐
│  C  Swift / Objective-C  (NetworkExtension layer)   │
│     PacketTunnelProvider                             │
│     packetFlow ↔ NWUDPSession                        │
├─────────────────────────────────────────────────────┤
│  B  Bridging / Adaptation layer                     │
│     mbuf → flat buffer, callout → dispatch_after    │
│     taskqueue → GCD queues                          │
├─────────────────────────────────────────────────────┤
│  A  Core protocol (C, ported from FreeBSD)          │
│     wg_noise.c      – Noise IKpsk2 handshake  ✓    │
│     wg_cookie.c     – Anti-DDoS cookies       ✓    │
│     wg_crypto.c     – ChaCha20-Poly1305 mbuf  ✓    │
│     wg_crypto_impl.c – RFC 8439 pure-C impl   ✓    │
└─────────────────────────────────────────────────────┘
```

---

## Build

### Requirements

| Tool | Version |
|------|---------|
| macOS | 11.0 + |
| Xcode Command Line Tools | any recent |
| `cc` (Apple Clang) | bundled with Xcode CLT |

### Compile

```bash
make          # builds build/libwg.a
make clean    # remove artefacts
make help     # show targets and variables
```

The Makefile passes these key flags:

| Flag | Purpose |
|------|---------|
| `-I src/macos_stubs` | FreeBSD kernel header shims (highest priority) |
| `-I src` | local project headers |
| `-DCOMPAT_NEED_BLAKE2S` | enable `blake2s_state` struct in `crypto.h` |
| `-mmacosx-version-min=11.0` | ensure modern libc symbols visible |

---

## macOS stub headers (`src/macos_stubs/`)

Each FreeBSD kernel API is mapped to the nearest macOS userspace equivalent.
Headers that exist in macOS but need extras use `#include_next`.

| FreeBSD API | macOS replacement |
|---|---|
| `struct mtx` / `mtx_*` | `pthread_mutex_t` |
| `struct rwlock` / `rw_*` | `pthread_rwlock_t` |
| `refcount_*` | `__atomic` builtins |
| `CK_LIST_*` | `sys/queue.h` `LIST_*` |
| `NET_EPOCH_ENTER/EXIT` | no-op (single-threaded stub) |
| `malloc(s, type, flags)` | `calloc(1, s)` macro |
| `zfree(ptr, type)` | `free(ptr)` |
| `uma_zcreate` / `uma_zalloc` / `uma_zfree` | `calloc` / `free` |
| `struct callout` / `callout_reset` | `dispatch_after` + atomic generation counter |
| `struct mbuf` / `m_append` / `m_adj` | flat `{m_data, m_len, m_pkthdr.len}` with `realloc` |
| `crypto_newsession` / `crypto_dispatch` | pure-C RFC 8439 in `wg_crypto_impl.c` |
| `sbintime_t` / `SBT_1S` | `int64_t` nanoseconds, `CLOCK_MONOTONIC` |
| `getnanotime()` | `clock_gettime(CLOCK_REALTIME, …)` |
| `atomic_load_ptr` etc. | `__atomic_load_n` / `__atomic_store_n` |
| `SipHashX` | self-contained SipHash-c-d in `siphash.h` |
| `explicit_bzero` | volatile-loop macro (avoids SDK visibility gates) |
| `satosin` / `satosin6` | cast macros in `netinet/in.h` via `#include_next` |

---

## Crypto implementation (`wg_crypto_impl.c`)

`wg_crypto.c` uses the FreeBSD opencrypto session/dispatch framework.
The userspace port replaces it with a self-contained RFC 8439 implementation:

- **ChaCha20** – 20-round block function, keystream XOR
- **Poly1305** – 26-bit limb arithmetic, constant-time finalise
- **HChaCha20** – subkey derivation for XChaCha20
- **`crypto_dispatch`** – reads `struct cryptop` fields (mbuf, key, nonce), encrypts or decrypts in-place, writes/verifies the 16-byte Poly1305 tag
- **Buffer API** – `chacha20_poly1305_encrypt/decrypt` and `xchacha20_poly1305_encrypt/decrypt` called from `crypto.h` inlines

No external crypto dependency; no CommonCrypto; no OpenSSL.

---

## Status

| File | Compiles | Notes |
|------|----------|-------|
| `wg_noise.c` | **yes** | Noise IKpsk2 state machine |
| `wg_cookie.c` | **yes** | Anti-DDoS cookie + rate-limit GC timer |
| `wg_crypto.c` | **yes** | Blake2s + mbuf encrypt/decrypt |
| `wg_crypto_impl.c` | **yes** | Pure-C RFC 8439 + crypto_dispatch bridge |
| `if_wg.c` | no | needs full NE bridging layer |

---

## Next steps

1. **Curve25519 implementation**: provide `curve25519` / `curve25519_generate_public`
   in C (vendor `donna_c64.c`, or call Apple CryptoKit via a Swift bridge).
2. **`if_wg.c` port**: interface management logic, depends on the full NE layer.
3. **Swift / PacketTunnelProvider layer**: wire `packetFlow` ↔ `struct mbuf` ↔
   `noise_create_initiation` / `noise_consume_response` / encrypt / decrypt.
4. **Integration test**: perform a live handshake against a Linux `wg-quick` peer.

---

## License

Source files are MIT/ISC-licensed (see per-file SPDX headers).  
Stub headers are original macOS adaptation code, also ISC.
