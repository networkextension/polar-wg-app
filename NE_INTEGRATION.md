# NetworkExtension integration guide

This directory contains everything needed to drop the WireGuard port into
a real macOS NetworkExtension app — **as a packaged xcframework**, not a
sprawling Xcode project. The CLI client in `src/wg_core.c` stays the
reference implementation and the test/debug vehicle; the NE path uses
the I/O-agnostic library layer in `src/wg_session.{h,c}`.

## Repository layout

```
src/
  wg_session.h                    ← public C API (16 fns, all extern "C")
  wg_session.c                    ← library implementation
  ...
NetworkExtension/
  WireGuardKit/module.modulemap   ← Swift import surface
  Sources/PacketTunnelProvider.swift  ← reference NEPacketTunnelProvider subclass
scripts/
  build-xcframework.sh            ← produces build/xcframework/WireGuardCore.xcframework
```

## The architectural split

The CLI `wg_core` binary owns all I/O itself: it opens `utun` via
`PF_SYSTEM`, binds its own UDP socket, runs a `select()` loop, uses
`signal()` for SIGINFO. That's fine for a userspace tool but is not
how a PacketTunnelProvider looks.

In a NetworkExtension, Apple owns all I/O:

| What you want to do       | How NE gives it to you                     |
|---------------------------|--------------------------------------------|
| Read packets from utun    | `NEPacketTunnelFlow.readPackets`           |
| Write packets to utun     | `packetFlow.writePackets`                  |
| Open outer UDP to peer    | `createUDPSession(to:from:)`               |
| Write UDP datagram        | `NWUDPSession.writeDatagram`               |
| Periodic tick             | `DispatchSource.makeTimerSource`           |
| Log                       | `os.log`                                   |
| Network settings (IP/DNS) | `setTunnelNetworkSettings(NEPacketTunnelNetworkSettings)` |

So the C library must not do any of those things itself. Instead it
exposes three entry points (`handle_udp`, `handle_tun`, `tick`) and
three callbacks (`send_udp`, `deliver_ip`, `log_line`) — the Swift side
handles the NE-specific plumbing and the C side handles all the noise
state, allowedips routing, handshake timer wheel, crypto, and
per-peer bookkeeping.

## The C API (`wg_session.h`)

Sixteen functions. The hot path is just six of them:

```c
wg_session_t *wg_session_create(const char *config_text, size_t len,
                                wg_session_callbacks cb);
void          wg_session_destroy(wg_session_t *);

int  wg_session_handle_udp(wg_session_t *, const uint8_t *bytes, size_t len,
                           const struct sockaddr *from, socklen_t from_len);
int  wg_session_handle_tun(wg_session_t *, const uint8_t *bytes, size_t len);
void wg_session_tick(wg_session_t *);
int  wg_session_kick(wg_session_t *);
```

Callbacks are three C function pointers in `wg_session_callbacks`:

```c
typedef struct {
    wg_send_udp_fn   send_udp;
    wg_deliver_ip_fn deliver_ip;
    wg_log_fn        log_line;   /* nullable */
    void            *user_ctx;
} wg_session_callbacks;
```

Everything the library wants to introspect from Swift (for
`NEPacketTunnelNetworkSettings`) is available through
`wg_session_iface_addr_*` and `wg_session_peer_*` getters.

## Building the xcframework

```
make xcframework
```

or directly:

```
./scripts/build-xcframework.sh
```

Output:

```
build/xcframework/WireGuardCore.xcframework/
  Info.plist
  macos-arm64_x86_64/
    WireGuardCore.framework/
      WireGuardCore                ← universal static binary (arm64 + x86_64)
      Headers/
        wg_session.h
      Modules/
        module.modulemap
      Resources/
        Info.plist
```

The build script:
1. Compiles the six C sources (`wg_noise`, `wg_cookie`, `wg_crypto`,
   `wg_crypto_impl`, `allowedips`, `wg_session`) for each architecture.
2. Compiles `crypto_bridge.swift` as a static lib for each architecture.
3. `ar x`'s the Swift bridge archive and `ar rcs`'s everything into a
   single static archive per arch.
4. `lipo`'s the per-arch archives into one universal binary.
5. Lays out the `.framework` bundle around it with the module map and
   headers, then wraps the whole thing in a `.xcframework` wrapper with
   a valid `Info.plist`.

Verified outputs:

```
$ lipo -info build/.../WireGuardCore
Architectures in the fat file: x86_64 arm64

$ nm -g build/.../WireGuardCore | grep "T _wg_session_" | wc -l
13
```

## Dropping it into an Xcode project

1. **Create a new macOS App** with a **NetworkExtension → Packet Tunnel
   Provider** target. Xcode will scaffold a `PacketTunnelProvider.swift`
   stub in the extension target — replace it with
   `NetworkExtension/Sources/PacketTunnelProvider.swift` from this repo.

2. **Add the xcframework** to the extension target. In Xcode: General →
   Frameworks and Libraries → + → Add Other → Add Files → select
   `build/xcframework/WireGuardCore.xcframework`. Set "Embed" to
   "Do Not Embed" (it's a static framework).

3. **Import** in your Swift code:
   ```swift
   import WireGuardCore
   ```

4. **Entitlements** — the extension target needs:
   - `com.apple.developer.networking.networkextension` with value
     `packet-tunnel-provider`
   - App groups if you want the host app and the extension to share
     configuration state via `UserDefaults(suiteName:)`

5. **Provider configuration**: the host app installs an
   `NETunnelProviderManager`; the provider configuration dictionary
   is where you stash the wg-quick config text:
   ```swift
   let proto = NETunnelProviderProtocol()
   proto.providerBundleIdentifier = "com.example.wireguard.extension"
   proto.serverAddress = "wg server"
   proto.providerConfiguration = [
       "config":   wgQuickText,
       "endpoint": "172.16.203.128:51820",
   ]
   manager.protocolConfiguration = proto
   ```

   **`providerConfiguration` keys** read by the reference provider (all
   string values; read once at `startTunnel`):

   | key | meaning |
   |-----|---------|
   | `config` | wg-quick text (required) |
   | `routeMode` | `full` \| `split` |
   | `dnsMode` | `system` \| `plain` \| `doh` |
   | `splitInjectedRoutes` | CSV of extra CIDRs (split mode) |
   | `dnsServers` | CSV — operator DNS push; overrides the config's `DNS =` line in `plain` mode |
   | `dnsMatchDomains` | CSV — split-DNS scoping (applied to `plain`/`doh`) |
   | `dnsSearchDomains` | CSV — search domains appended to bare hostnames |
   | `kcp*` | KCP transport (see `KCP-TRANSPORT.md`) |

   The `dns*` keys carry the control-plane policy (`wg_hubs.policy_json` →
   `/v1/register` → host-app reconciler → here). Empty/absent = legacy
   behavior (DNS from the config's `DNS =` line). See
   `doc/wg-dns-proxy-push-design.md`. Updating them requires re-saving the
   profile + restarting the tunnel (v1; v3 = `sendProviderMessage`, no blip).

6. **Code sign** the host app and the extension with a provisioning
   profile that includes the NE entitlement. Development profiles need
   to be created in App Store Connect or the free personal team.

7. **Trigger**: the host app calls
   `manager.connection.startVPNTunnel()`. macOS launches the extension
   process in a sandbox, which calls into
   `PacketTunnelProvider.startTunnel`, which creates the `wg_session`
   and starts the read loops.

## What the reference `PacketTunnelProvider` does

See `NetworkExtension/Sources/PacketTunnelProvider.swift` for the full
code. Outline:

```
startTunnel:
  1. Read config text from protocolConfiguration.providerConfiguration
  2. Build wg_session_callbacks with C trampolines that recover `self`
     via Unmanaged.passUnretained
  3. wg_session_create(configText, callbacks)
  4. Build NEPacketTunnelNetworkSettings from wg_session_iface_addr_*
  5. setTunnelNetworkSettings(...)
  6. createUDPSession(to: peerEndpoint, from: nil) and install a
     setReadHandler that forwards every datagram to wg_session_handle_udp
  7. Start packetFlow.readPackets loop, forwarding each packet to
     wg_session_handle_tun
  8. wg_session_kick(session) for the initial handshake
  9. DispatchSource timer at 1 Hz calling wg_session_tick

stopTunnel:
  cancel timer, cancel UDP session, wg_session_destroy
```

The three C callback trampolines (`sendUDPCallback`, `deliverIPCallback`,
`logCallback`) are free functions (C-calling-convention) that recover
the Swift `PacketTunnelProvider` from the `user_ctx` pointer and dispatch
to methods on it. Standard Swift↔C interop pattern.

## What's verified by this repo

- [x] `scripts/build-xcframework.sh` produces a valid
      `WireGuardCore.xcframework` with arm64 + x86_64 slices
- [x] `lipo -info` shows both architectures
- [x] `nm -g` shows all 13 `wg_session_*` exports
- [x] `swiftc -parse` against the framework confirms the Swift reference
      code type-checks and resolves `import WireGuardCore`
- [x] The existing 22-test KAT suite still passes with `wg_session.c`
      linked into libwg.a
- [x] The CLI `wg_core` client still works against a real Linux peer

## What's NOT verified (and can't be without Xcode + signing)

- End-to-end NE tunnel bring-up (requires code signing, provisioning
  profile, NetworkExtension entitlement, a host app container)
- `NEPacketTunnelFlow` actually reading packets
- `NWUDPSession` actually writing datagrams to the peer
- The `startTunnel` → `setTunnelNetworkSettings` → `startVPNTunnel`
  handshake with the NE daemon

These are all wired up in the reference code, but you need an Apple
Developer account and Xcode on your machine to run the integration
test. The C library has been exercised end-to-end via the CLI
`wg_core` client (ping 200/200 0% loss across a 120s rekey boundary),
so the underlying state machine is known-good — what the NE path adds
is just the I/O plumbing.

## Next steps

If you want to go further:
- **Host app** with an `NETunnelProviderManager` UI for installing /
  starting / stopping the tunnel
- **Connect-on-demand rules** via `onDemandRules`
- **DNS configuration** via `NEDNSSettings` on the network settings
- **Per-peer endpoint updates** via a new `wg_session_peer_endpoint_set`
  API so Swift can push endpoint changes back into the C library
  (currently the library only learns endpoints at startup via the
  config and via roaming on successful decap)
