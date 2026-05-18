# WireGuard macOS 用户态移植 — 工作日志

> 完整记录从「FreeBSD 内核代码搬到 macOS」到「能跑、能用、能上架」的全过程。

---

## 一、项目起点

**输入**：FreeBSD 内核 WireGuard 实现（`wg_noise.c` / `wg_cookie.c` / `wg_crypto.c`），通过 `macos_stubs/` 头文件仿真层在 macOS 用户态编译通过，产出 `libwg.a`。

**目标**：让这套 C 代码在 macOS 上真正跑起来 —— 先作为命令行 VPN 客户端验证协议正确性，最终封装为 NetworkExtension xcframework + SwiftUI 应用。

**起始状态**：`make` 能通过，但从未对真实 WireGuard server 跑过任何握手或数据包。

---

## 二、解决的问题（按时间线）

### Round 1：编译级修复

| 问题 | 修复 |
|---|---|
| `wg_core.c` 包头字节序用 host order 而非 LE | 改用 `htole32/htole64` 宏，与 FreeBSD `if_wg.c` 对齐 |
| Keepalive 包缺 16 字节 padding | `m_devget(zero_pad, WG_PKT_PADDING)` |
| `wg_pkt_*` 结构体无大小保护 | 加 `_Static_assert(sizeof(...) == N)` |
| Makefile 不含 Swift bridge / 测试目标 | 加 `libswift_crypto.a` + `wg_core` + `crypto_vector_test` 构建规则 |
| `crypto_dispatch` 注释不清 | 标注"仅用于 transport，AAD 硬编码为 0" |

### Round 2：Poly1305 partial-block buffering bug

**症状**：握手成功但 server 静默丢包。`crypto_vector_test` 的 roundtrip 测试绿灯。

**根因**：`poly1305_update()` 把任何 `len < 16` 的尾部当成最终块处理（append `0x01` + `hibit=0`），破坏了 RFC 8439 AEAD 的多段 update 构造。`encrypted_static`（32+32，16 倍数对齐）偶然躲过 bug；`encrypted_timestamp`（32+12）必踩。

**发现方式**：加入 RFC 8439 §2.8.2 Known-Answer Test（"Ladies and Gentlemen..."），密文正确但 tag 错。

**修复**：给 `poly1305_ctx` 加 16 字节 `buf` + `buflen` 成员，`update` 只缓存尾部，`finish` 才写 `0x01` 标记。

**教训**：
- Roundtrip 自测 ≠ KAT。自洽性 ≠ 正确性。
- 自写 crypto 必须第一行代码就配 RFC 向量。
- "对齐偶然帮了 bug" 是最隐蔽的一类问题。

### Round 3：`r_idx` 字段方向写反

**症状**：Poly1305 修完后握手 OK，crypto KAT 全绿，但 200/200 ping 全超时。Server tcpdump 显示我们的 data 包全部到达，但 `wg show transfer` 的 `rx_bytes` 只涨 148（= handshake init 大小）。

**根因**：`wait_for_response()` 把我们自己的 `s_idx` 传给了 `noise_consume_response()` 的 responder-`s_idx` 参数槽。Noise 状态机把这个错误值存进 `kp_index.i_remote_index`，导致每个 data 包的 `r_idx` 字段填的是我们自己的 index 而不是 server 的。Server 查自己的索引哈希 → 找不到 → `SKB_DROP_REASON_WIREGUARD_NO_KEYPAIR_FOUND` 静默丢弃。

**发现方式**：hex dump 第一个 data 包的 wire bytes，对照 FreeBSD `if_wg.c:1448` 参考调用 → 一秒命中。

**修复**：`noise_consume_response(local, &matched, pkt.s_idx, pkt.r_idx, ...)` — 一个参数交换。

**教训**：
- 现代 Linux 的 silent drop 不走 dmesg，要靠 `bpftrace` 或 `wg show transfer` 计数器。
- Wire dump 比抽象测试更适合调 wire protocol。
- `noise_consume_response(s_idx, r_idx)` 看起来对称但语义不对称 — API 参数 footgun。

### Round 4：NE 路由回环 + udpSession 未创建

**症状**：NE app 状态绿灯 "connected"，但 ping 超时，UAPI GET 显示 `tx_bytes=0 / rx_bytes=0`。

**根因（双 bug）**：
1. `firstPeerEndpoint()` 只从 `providerConfiguration["endpoint"]` 取值，但 host app 从未写入该 key → `udpSession` 为 nil → 所有 `writeDatagram` 静默 no-op → 握手从未开始。
2. `includedRoutes = [NEIPv4Route.default()]` 把 0.0.0.0/0 路由进 utun，包括 extension 自己到 server 的 outer UDP → 路由回环。

**修复**：
1. 改用 `wg_session_peer_endpoint()` introspection API 取 peer 地址，创建 `NWUDPSession`。
2. 从每个 peer 的 AllowedIPs 构建 `includedRoutes`，从每个 peer 的 endpoint 构建 `excludedRoutes`（/32）。

---

## 三、构建的功能层

### C 库层（`libwg.a`）

| 模块 | 来源 | 说明 |
|---|---|---|
| `wg_noise.c` | FreeBSD 原样 | Noise_IKpsk2 状态机 |
| `wg_cookie.c` | FreeBSD 原样 | MAC1/MAC2 + cookie reply |
| `wg_crypto.c` | FreeBSD + 本地 Blake2s | HKDF + Blake2s（`COMPAT_NEED_BLAKE2S`） |
| `wg_crypto_impl.c` | 全新 | 纯 C ChaCha20-Poly1305 / XChaCha / crypto_dispatch |
| `crypto_bridge.swift` | 全新 | CryptoKit Curve25519 DH bridge |
| `allowedips.c` | 全新 | 二叉位 trie，IPv4/IPv6 最长前缀匹配 |
| `wg_session.c` | 全新 | I/O-free 会话库（NE 用），20 个导出函数 |

### CLI 客户端（`wg_core.c`）

- 约 1800 行的用户态 VPN 进程
- utun 设备 + select() 双 fd 循环 + sendto/recvfrom
- 多 peer 支持 + per-peer 状态机 + allowedips 路由
- M3 定时器：handshake retransmit (5s) / rekey (120s) / persistent-keepalive
- 响应者模式：cookie_checker + WG_PKT_INITIATION 处理
- SIGINFO（Ctrl-T）wg-show 风格状态快照
- IPv6 inner + dual-stack Address 解析
- **验证**：200/200 ping 0% loss across 120s rekey boundary

### NE xcframework

- `WireGuardCore.xcframework`：arm64 + x86_64 通用框架
- `framework module WireGuardCore` modulemap
- `wg_session.h` 为唯一公开头
- `make xcframework` 一键构建
- 支持 macOS / iOS / tvOS / visionOS 多平台

### UAPI（wg(8) 兼容）

| 操作 | 状态 |
|---|---|
| `get=1`（wg show） | ✅ 完整 canonical text 格式 |
| `set=1` endpoint | ✅ re-resolve + sockaddr 更新 |
| `set=1` persistent_keepalive | ✅ |
| `set=1` replace_allowed_ips + allowed_ip | ✅ trie 重建 |
| `set=1` preshared_key | ✅ noise_remote_set_psk |
| `set=1` peer add（unknown public_key） | ✅ noise_remote 运行时分配 |
| `set=1` peer remove（remove=true） | ✅ tombstone semantics |
| `set=1` listen_port | ✅ stored value |
| `set=1` private_key | ❌ 拒绝（安全设计） |

传输层：NE 下走 `sendProviderMessage`（替代 unix socket），wire format 不变。

### SwiftUI 应用

- **Bundle**: `com.change.wg` (host) + `com.change.wg.tunnel` (extension)
- **Tab 1 — Connection**：
  - Hero server card + 大 Connect 按钮
  - Node list 分 Platform / Manual 两栏
  - 🔒 Platform 节点不可查看配置
  - Country emoji 支持（平台下发 or 名字猜测）
  - 🔄 Sync 按钮拉取平台配置
- **Tab 2 — Servers**：
  - Config editor（仅 manual 节点）
  - Route mode（Full / Split + injected CIDRs）
  - UAPI status 面板 + demo 按钮
  - Keychain 持久化 + iCloud sync
- **Login/Register**：APIClient → Latch 平台认证
- **macOS 侧边栏 + iOS 底部 tab bar**
- **Config 验证**：Save/Connect 时检查格式，Alert 提示具体错误

### 平台节点同步

- `APIClient.getLatchProfiles()` → `[LatchProfile]`
- 每个 `LatchProxy` 通过 `toWGQuickConfig()` 转为 wg-quick 文本
- JSON config dict 直接用 WG 标准 key 名（不做 mapping），缺 PrivateKey/PublicKey 自动丢弃
- Merge 逻辑：按 `platformProxyId` 匹配，新增/更新/删除，Manual 节点不受影响
- Tombstone semantics 避免 noise_remote arg 指针失效

### 测试矩阵

| # | 测试 | 类型 |
|---|---|---|
| 1-3 | Blake2s KAT（abc + empty + fox） | RFC 7693 |
| 4 | Blake2s streaming consistency（200B × 12 chunkings） | 回归 |
| 5 | Curve25519 RFC 7748 §6.1（pubkey + DH） | RFC 向量 |
| 6 | ChaCha20-Poly1305 RFC 8439 §2.8.2 | RFC 向量 |
| 7-14 | mbuf path == buffer path（8 个长度） | 交叉验证 |
| 15-16 | ChaCha20/XChaCha roundtrip + tamper | 自洽 |
| 17 | Noise loopback（handshake + transport） | 端到端 |
| 18-22 | Allowedips trie（v4 LPM, default route, replace/remove, v6, edge） | 单元 |
| 23 | wg_session UAPI GET round trip | 集成 |
| 24 | wg_session UAPI SET round trip（endpoint + keepalive + aips + rejects） | 集成 |
| 25 | PSK config parse + GET + SET + clear | 集成 |
| 26 | Peer add via UAPI SET | 集成 |
| 27 | Peer remove (tombstone) + re-add | 集成 |

全部 **27/27 PASS**。

---

## 四、架构图

```
┌──────────────── macOS / iOS App ──────────────────┐
│                                                    │
│  SwiftUI (ContentView + TunnelManager)             │
│     │                                              │
│     ├─ NETunnelProviderManager                     │
│     │     install / save / start / stop            │
│     │                                              │
│     └─ sendProviderMessage("get=1" / "set=1")      │
│           │                                        │
│  ┌────────┼── Extension (.appex) ──────────────┐   │
│  │        ▼                                    │   │
│  │  PacketTunnelProvider                       │   │
│  │     │                                       │   │
│  │     ├─ wg_session_t (C, I/O-free)           │   │
│  │     │     ├─ handle_tun(inner_pkt)          │   │
│  │     │     ├─ handle_udp(wire_pkt, from)     │   │
│  │     │     ├─ tick()  (1Hz timer)            │   │
│  │     │     ├─ get_uapi() / set_uapi()        │   │
│  │     │     └─ kick() (initial handshake)      │   │
│  │     │                                       │   │
│  │     ├─ NEPacketTunnelFlow                   │   │
│  │     │     readPackets → handle_tun          │   │
│  │     │     deliver_ip callback → writePackets │   │
│  │     │                                       │   │
│  │     ├─ NWUDPSession                         │   │
│  │     │     setReadHandler → handle_udp       │   │
│  │     │     send_udp callback → writeDatagram │   │
│  │     │                                       │   │
│  │     └─ DispatchSourceTimer @1Hz → tick()     │   │
│  └─────────────────────────────────────────────┘   │
│                                                    │
│  libwg.a (C, static)                               │
│     ├─ wg_noise.c    (FreeBSD, Noise_IKpsk2)       │
│     ├─ wg_cookie.c   (FreeBSD, MAC1/MAC2)           │
│     ├─ wg_crypto.c   (Blake2s + mbuf encrypt)       │
│     ├─ wg_crypto_impl.c (ChaCha20-Poly1305 纯 C)    │
│     ├─ allowedips.c  (IPv4/IPv6 bit trie)           │
│     └─ wg_session.c  (session API, 20 exports)      │
│                                                    │
│  libswift_crypto.a (Swift)                          │
│     └─ crypto_bridge.swift (CryptoKit Curve25519)   │
│                                                    │
│  WireGuardCore.xcframework                          │
│     = libwg.a + libswift_crypto.a + module.modulemap│
└────────────────────────────────────────────────────┘
```

---

## 五、域名支持

**问题**：Endpoint 字段能否写域名（如 `vpn.example.com:51820`）？

**结论**：两端都已支持，不需要改代码。

| 层 | 实现 | 说明 |
|---|---|---|
| C 库 | `getaddrinfo(host, port, AF_UNSPEC)` | 域名 / IPv4 / IPv6 都行；session create 时一次性解析 |
| Swift NE | `NWHostEndpoint(hostname:port:)` → `createUDPSession` | Apple Network.framework 内部 DNS，网络切换自动 re-resolve |
| UAPI SET | `peer_set_endpoint_str()` → `getaddrinfo` | 运行时更新也支持域名 |

C 库侧是一次性解析（IP 锁死在 sockaddr），Swift 侧持续跟踪 DNS。实际发包走 Swift 的 `NWUDPSession`，所以域名变更能被 Apple 自动追踪。

---

## 六、PR 历史

| PR | 分支 | 标题 | 测试 |
|---|---|---|---|
| #1 ✅ merged | — | Crypto fix + utun data plane + M3 timers | 17 |
| #3 | feat/allowedips-trie | M2a: allowedips trie + 5 tests | +5 (22) |
| #4 | feat/allowedips-integration | M2b.1: anti-spoofing on decap | 22 |
| #5 | feat/wg-show-status | SIGINFO + wg-show snapshot | 22 |
| #6 | feat/ipv6-inner | IPv6 Address parser + inet6 ifconfig | 22 |
| #7 | feat/responder-role | cookie_checker + initiation handler | 22 |
| #8 | feat/multi-peer | peer_state + N peers + aips routing | 22 |
| #9 | feat/ne-xcframework | WireGuardCore xcframework + PacketTunnelProvider | 22 |
| #10 | feat/uapi-get | wg_session_get_uapi + handleAppMessage | +1 (23) |
| #11 | feat/uapi-set | wg_session_set_uapi (endpoint/keepalive/aips) | +1 (24) |
| #12 | feat/psk-and-runtime-peers | PSK + peer add/remove + listen_port | +3 (27) |
| #13 | feat/sample-app | Xcode project + SwiftUI + platform nodes + validation | 27 |

---

## 七、调试方法论总结

### 五条横跨全项目的教训

1. **静默丢包是这个栈的默认失败方式。** WireGuard 的 anti-DoS 设计 + Linux 的 `SKB_DROP_REASON` framework 一起，让 silent drop 成了所有 bug 的默认表现。每次 "no error, no result" 时，先找一个 ground-truth 源头 — counter / KAT / tcpdump / bpftrace — 不要盯代码看。

2. **测试基础设施先于实现。** Roundtrip 测试 ≠ KAT 测试。每条新 code path 先写 RFC 向量再写代码。自洽性不等于正确性 — 一个 buggy-but-symmetric 实现能永远通过 roundtrip。

3. **握手成功 ≠ 数据面成功。** 三轮调试都是 "握手 OK → 数据包挂" 的模式。握手 path 和 data path 走不同字段、不同代码路径，互不背书。**协议正确性必须 ping 通才算数。**

4. **Wire dump 比抽象测试更适合调 wire protocol。** Round 2 + Round 3 都是 hex dump 一秒命中，KAT 反而是耗时的二选项。调 wire protocol 的第一动作是 hexdump 实际字节，再写抽象测试。

5. **不对称参数 API 是 footgun。** `noise_consume_response(s_idx, r_idx)` 看起来对称实际不是。修复点留了一行 sanity check 防回归。

### 调试时间分配

| Round | 总耗时 | 浪费 | 原因 |
|---|---|---|---|
| R1 (字节序) | 20 min | 0 | 静态分析 + 文档对照 |
| R2 (poly1305) | 70 min | 40 min (57%) | roundtrip 假绿灯误导 |
| R3 (r_idx) | 65 min | 30 min (46%) | mbuf KAT 在错方向上 |
| R4 (NE routing) | 30 min | 0 | 用户直接定位 |

**70% 的调试浪费来自"相信了不够好的测试"。** KAT first, roundtrip never alone。

---

## 八、可能的后续

### 短期（代码层面）

| 项 | 难度 | 说明 |
|---|---|---|
| `replace_peers=true` 支持 | 中 | UAPI SET 清空所有 peer 并重建；需要批量 noise_remote 生命周期管理 |
| `private_key` 运行时更换 | 高 | noise_local_private 重新调用 → 所有 keypair 失效 → 强制 rekey |
| `listen_port` 主动 rebind callback | 低 | C 库加一个 `on_config_change` callback，Swift 收到后 rebind NWUDPSession |
| DNS resolver 定期刷新 | 中 | C 侧加 `wg_session_re_resolve_endpoints()`，Swift 定时调用 |
| 多 Peer 初始握手并行化 | 低 | tunnel_tick 已经遍历所有 peer，只需要在 startup 时也遍历发 initiation |
| App Store 审核合规 | — | NE entitlement 需要通过 Apple 审批流程 |

### 中期（产品层面）

| 项 | 说明 |
|---|---|
| On-Demand Rules | `NEOnDemandRuleConnect` / `NEOnDemandRuleDisconnect`，按 SSID / 接口类型自动连断 |
| DNS 配置 | `NEDNSSettings` 推送 DoH/DoT 或自定义 DNS 到系统 |
| 平台下发规则（LatchRule） | `rule.content` 解析成路由规则 → 动态 split tunnel |
| 节点健康检查 / 延迟测量 | 定期 ping 或 handshake probe → 自动切换最优节点 |
| Widget / Menu Bar | macOS menu bar 小图标 + iOS widget 显示连接状态 |
| 多语言 | i18n for UI strings |

### 长期（架构层面）

| 项 | 说明 |
|---|---|
| wireguard-go 替代 | 当前是 FreeBSD C 移植；如果性能或维护成本高，可以考虑直接用 wireguard-go 的 Go 库通过 CGo bridge |
| Apple 原生 WireGuard | Apple 在 iOS 15.4+ 有 `NEVPNProtocolWireGuard`，但功能受限（不支持自定义路由规则）。如果 Apple 后续开放更多控制，可以迁移 |
| 内核态 sysext | macOS 12+ 支持 System Extension 替代 kext；如果需要极致性能（>1Gbps），可以考虑内核态数据面 + 用户态控制面的混合架构 |

---

## 九、文件清单

```
src/
├── wg_noise.c / .h          FreeBSD Noise_IK 状态机（原样）
├── wg_cookie.c / .h          FreeBSD cookie MAC/checker（原样）
├── wg_crypto.c               Blake2s + chacha20poly1305_mbuf
├── wg_crypto_impl.c          纯 C ChaCha20-Poly1305 + crypto_dispatch
├── crypto_bridge.swift        CryptoKit Curve25519 bridge
├── allowedips.c / .h          IPv4/IPv6 bit trie
├── wg_session.c / .h          I/O-free session API（NE 用）
├── wg_core.c                  CLI VPN 客户端（utun + select）
├── crypto_vector_test.c       27 个 KAT / loopback / 集成测试
├── macos_stubs/               内核头仿真层
│   ├── sys/{mbuf,rwlock,mutex,callout,epoch,...}.h
│   ├── crypto/{chacha20_poly1305,curve25519}.h
│   └── opencrypto/cryptodev.h
└── module.modulemap, compat.h, version.h, if_wg.{c,h}

NetworkExtension/
├── WireGuardKit/module.modulemap
└── Sources/PacketTunnelProvider.swift

WireGuardSampleApp/
├── project.yml                      xcodegen spec
├── WireGuardSampleApp.xcodeproj/    生成的 Xcode project
├── WireGuardSampleApp/
│   ├── WireGuardSampleAppApp.swift
│   ├── ContentView.swift            SwiftUI（Connection + Servers tabs）
│   └── TunnelManager.swift          NE wrapper + API + 平台同步 + 验证
└── WireGuardTunnelExtension/
    ├── Info.plist
    └── *.entitlements

scripts/
└── build-xcframework.sh             多平台 xcframework 构建

Makefile                             libwg.a + wg_core + crypto_vector_test + xcframework
REVIEW.md                            Code review（7 项 + poly1305 + r_idx 复盘）
PORTING_LOG.md                       三轮调试工作日志
NEXT_STEPS.md                        里程碑计划（M1-M4）
NE_INTEGRATION.md                    NetworkExtension 集成指南
```

---

*文档生成时间：2026-04-12*
*总代码量：~15000 行（C + Swift + 构建脚本 + 文档）*
*测试：27/27 PASS*
*端到端验证：CLI 200/200 ping 0% loss；NE app xcodebuild BUILD SUCCEEDED*
