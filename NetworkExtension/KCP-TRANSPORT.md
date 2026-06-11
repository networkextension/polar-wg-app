# WireGuard-over-KCP on iOS/macOS (PacketTunnelProvider)

The reference `PacketTunnelProvider` can optionally carry wg_core's UDP through
**KCP** (ARQ + Reed-Solomon FEC + AES obfuscation) instead of a plain
`NWUDPSession` — useful when the WG path is lossy / QoS'd / cross-border. Same
mechanism as the Linux/FreeBSD `kcpfwd` sidecar, but **in-process** (iOS has no
separate process and no kernel WG).

Proven on Linux hub-to-hub: a raw cross-border path at 10% loss became **0% loss**
through the tunnel — KCP's ARQ alone, before FEC.

## How it's wired
All KCP code in `NetworkExtension/Sources/PacketTunnelProvider.swift` is behind
`#if canImport(Shanghai)`. Linking the **Shanghai** KCP package into the extension
target turns it on; without it the provider compiles unchanged (NWUDPSession). The
splice: wg_core's `send_udp` callback → `KcpSession.send()`, and `KcpSession.onReceive`
→ `wg_session_handle_udp` — KCP sits between the wg_core seams and the wire.

`WireGuardSampleApp/project.yml` (+ `project-ios.yml`) already add the dependency:
```yaml
packages:
  Shanghai:
    url: https://github.com/yarshure/Shanghai.git
    branch: feat/kcpfwd-wg-over-kcp
# … and on the extension target:
      - package: Shanghai
        product: Shanghai
```

## Enabling per tunnel (providerConfiguration keys)
Set these in the `NETunnelProviderProtocol.providerConfiguration` dict (alongside
the existing `config`, `routeMode`, `dnsMode`). All values are strings. **Every one
must match the remote `kcpfwd`.**

| key              | meaning                                          | default |
|------------------|--------------------------------------------------|---------|
| `kcpEnable`      | `"1"`/`"true"`/`"yes"` to route through KCP       | off     |
| `kcpConv`        | KCP conversation id (UInt32)                      | 0       |
| `kcpKey`         | pre-shared key for AES obfuscation                | ""      |
| `kcpCrypt`       | `none` \| `aes` \| `aes-128` \| `aes-192`         | `aes`   |
| `kcpDatashard`   | FEC data shards (0 = FEC off)                     | 0       |
| `kcpParityshard` | FEC parity shards (0 = FEC off)                   | 0       |
| `kcpMtu`         | KCP mtu                                           | 1350    |

**The WG conf's peer `Endpoint` = the remote kcpfwd's public ip:port.** The provider
already adds each peer endpoint as an `excludedRoute /32|/128`, so KcpSession's socket
to that address stays off the tunnel (no loop). Keep the inner WG MTU ~1280 and set
`PersistentKeepalive` (pre-warms the KCP path, avoids cold-start latency).

## Server side
iOS is always behind NAT (cellular CGNAT / WiFi NAT), so the **hub runs
`kcpfwd --server`** (binds `--kcp-port`, learns the client); the iOS device is the
client and dials it. See the `kcpfwd` release (`github.com/yarshure/Shanghai` →
`kcpfwd-snapshot-20260611`) and its README for the hub setup.

## Known limitations (this pass)
- **Network migration**: KcpSession uses a BSD socket; unlike `NWUDPSession` it does
  not transparently migrate on WiFi↔cellular. v1 recovers by tunnel reconnect.
  Follow-up: make the KCP transport `NWConnection`-backed.
- **NE memory cap (~50 MB)**: validate the extension's footprint under load
  (Instruments). The KCP buffers + Foundation must fit; see `Sources/Shanghai/TODO.md`
  for the perf levers (os_unfair_lock, autoreleasepool, less Data churn) if needed.
