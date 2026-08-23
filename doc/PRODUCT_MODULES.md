# wg-mac · 产品模块文档

> macOS WireGuard userspace 移植 + Network Extension + 自建入网控制面。本文档串起整个仓库的每个模块，每节给出对应源文件:行号引用。新接手工程师靠它定位代码。
>
> 涵盖三大组件：
> 1. C 核心（FreeBSD `if_wg` 移植 + macOS POSIX stub）
> 2. Swift 桥 / NetworkExtension PacketTunnelProvider / 宿主 App
> 3. 部署运营（CLI、launchd、xcframework、入网控制面）

---

## 1. 产品定位

仓库 `/Volumes/Tahoe/Users/apple/Codex/wg`。把 FreeBSD 内核的 `if_wg`（Jason Donenfeld 上游 WireGuard）移植到 macOS userspace，目标承载形态有三种，复用同一份 C 内核：

| 形态 | 进程 | 用途 |
|---|---|---|
| **`wg_core`** CLI 守护 | userspace daemon | 开发 / 测试 / 调试参考实现，自带 `select` loop + utun 直驱 |
| **`wgctl`** CLI 工具 | userspace 短任务 | `genkey` / `pubkey` / `genpsk` + daemon 生命周期 |
| **NetworkExtension `PacketTunnelProvider`** | App Extension 进程 | 苹果三端（macOS / iOS / tvOS / visionOS）正式发布形态 |

控制面（入网注册 / 心跳 / 拉对端表）走自建 HTTP API（`doc/JOIN_PROTOCOL.md`），launchd agent 每 60s 轮询。

**license / 上游**：核心算法 / 状态机来自 FreeBSD（Donenfeld + ix Systems / Aymeric Wibo 等），版权声明在 `src/wg_noise.c:1-6`、`src/wg_cookie.c:1-5`、`src/allowedips.c` 头部。macOS stub / wg_session 库 / Swift 桥 / 控制面是新写。

---

## 2. 总体架构

```
┌──────────────── userspace ──────────────────┐
│                                              │
│   wg_core (CLI daemon)                       │
│   ┌──────────────────────────────────────┐   │
│   │ select() loop + utun device          │   │
│   │   ↓                                   │   │
│   │ libwg.a:  wg_noise / wg_cookie       │   │
│   │           wg_crypto / wg_crypto_impl │   │
│   │           allowedips / wg_session    │   │
│   │   ↓                                   │   │
│   │ macOS stubs → pthread / GCD / malloc │   │
│   │ libswift_crypto.a (Curve25519 via    │   │
│   │   CryptoKit)                         │   │
│   └──────────────────────────────────────┘   │
│                                              │
│   PacketTunnelProvider (NE 进程)             │
│   ┌──────────────────────────────────────┐   │
│   │ Swift: NEPacketTunnelProvider         │   │
│   │   ↓                                   │   │
│   │ WireGuardCore.xcframework (libwg.a)  │   │
│   │   ↓                                   │   │
│   │ I/O callback bridge                  │   │
│   │   ↑       ↑          ↑                │   │
│   │ NEPacketTunnelFlow  NWUDPSession     │   │
│   └──────────────────────────────────────┘   │
│                                              │
│   wgctl-agent (launchd 60s)                  │
│   ┌──────────────────────────────────────┐   │
│   │ → POST /v1/heartbeat                 │   │
│   │ → GET /v1/peers → diff → rewrite     │   │
│   │   wg0.conf → launchctl kickstart     │   │
│   └──────────────────────────────────────┘   │
│                                              │
└──────────────────────────────────────────────┘
       ▲                              ▲
       │                              │
   wg control plane                Apple App Store
   (JOIN API)                      (TestFlight / 公网)
```

**端到端 handshake 数据流**：详见 §6 数据流时序。

---

## 3. C 核心模块清单

`src/` 下的 C 代码。除非另注，所有 `.c` 都通过 `src/macos_stubs/` 头文件适配编译。

### 3.1 协议状态机（直接复用上游 FreeBSD）

| 文件 | 行 | 职责 |
|---|---:|---|
| `src/wg_noise.c` `.h` | 36K | Noise_IKpsk2 完整状态机：handshake 创建/消费、密钥派生、nonce 计数器、重放窗口、rekey。`noise_consume_initiation` `wg_noise.c:1119`、`noise_create_response` `:1244`、`noise_keypair_encrypt` `:1370`、`noise_keypair_decrypt` `:1401` |
| `src/wg_cookie.c` `.h` | 13K | Anti-DDoS cookie：SipHash-c-d 验签 + 速率限制。在握手洪流时挡 |
| `src/allowedips.c` `.h` | 3.3K | 二叉位 trie 做 LPM：IPv4/IPv6 CIDR → peer 查找。`aips_lookup` `allowedips.c:81` 用在 encap（按 dst 找 peer）和 decap 后反欺骗（验证内层源 IP 属于对方 AllowedIPs） |
| `src/wg_crypto.c` | 7.3K | ChaCha20-Poly1305 mbuf 包装 + Blake2s init/update/final |
| `src/curve25519_portable.c` | 11K | Bernstein 参考 Curve25519 + clamping，作为 CryptoKit 失效时的 fallback |

### 3.2 macOS 新写（应用层 + 控制 + 桥）

| 文件 | 行 | 职责 |
|---|---:|---|
| `src/wg_crypto_impl.c` | 21K | 纯 C RFC 8439 ChaCha20-Poly1305（含 XChaCha 变体） + crypto_dispatch for mbuf。无外部依赖 |
| `src/wg_session.c` `.h` | 56K | **NetworkExtension 用的 I/O-agnostic 库**。三个入口：`wg_session_handle_udp` / `_handle_tun` / `_tick`；三个回调：`send_udp` / `deliver_ip` / `log_line`。配置解析 (wg-quick INI)、encap/decap、allowedips 路由、UAPI get/set introspection 全在这层 |
| `src/wg_core.c` | 86K | **standalone CLI daemon**。select loop + utun + 真 socket + wire format 完整流。`REKEY_AFTER_TIME_SEC = 120`、`REJECT_AFTER_TIME_SEC = 180`、`MAX_HANDSHAKE_ATTEMPTS = 18`、`KEEPALIVE_TIMEOUT_SEC = 10` 等关键常数 |
| `src/wgctl.c` | 15K | CLI：`genkey` / `pubkey` / `genpsk` 子命令 + daemon up/down/show |
| `src/crypto_bridge.swift` | 116 | Swift → C 桥。导出 4 个 `@_cdecl` 函数（curve25519、curve25519_generate_public/secret、curve25519_clamp_secret），用 CryptoKit `Curve25519.KeyAgreement.PrivateKey`。**缓存 PrivateKey** 对象（`crypto_bridge.swift:20-26`）规避 `rawRepresentation ↔ PrivateKey(rawRep:)` 偶发失败 |
| `src/crypto_vector_test.c` | 47K（1268 行） | KAT 套件：Blake2s / Curve25519 / ChaCha20-Poly1305 RFC 向量、UAPI 往返、AllowedIPs trie、Noise IK 进程内回环 |

### 3.3 不被编译进 macOS 端的文件（参考资料）

| 文件 | 状态 |
|---|---|
| `src/if_wg.c` `.h`（85K） | FreeBSD 内核接口层（sysctl / ioctl / netisr）。在 macOS 上 NetworkExtension 接管所有 interface 责任；`Makefile:50` 不编。保留作 wire format struct 与上游差异对照 |
| `src/wg_client.c` `wg_client2.c` `wg_client3.c` | 实验客户端，中文注释，握手集成未完成，**已弃**。Makefile 不编 |

### 3.4 Build artifacts

`Makefile:55-65` 编出：

| Artifact | 内容 | 链接者 |
|---|---|---|
| `build/libwg.a` | wg_noise + wg_cookie + wg_crypto + wg_crypto_impl + allowedips + wg_session | wg_core / wgctl / xcframework |
| `build/libswift_crypto.a` | crypto_bridge.swift 编出来的 Curve25519 wrap | 同上 |
| `build/wg_core` | daemon | dev/test/参考实现 |
| `build/wgctl` | CLI | 用户 / launchd |
| `build/crypto_vector_test` | KAT runner | `make test` |
| `build/xcframework/WireGuardCore.xcframework/` | 7 平台静态库 + module.modulemap | iOS/macOS/tvOS/visionOS NE 应用 |

**Apple `/usr/bin/ar` 强 pin**（`Makefile:7`）：Homebrew binutils 的 ar 输出 GNU 格式归档，Apple linker 拒收（`archive member '/' not a mach-o file`）。

**`-mmacosx-version-min=11.0`**（`Makefile:32`）：CryptoKit 可用性下限。

---

## 4. macOS Stubs 适配层

`src/macos_stubs/` 18 个头，把 FreeBSD 内核 API 翻成 POSIX / macOS。整个 stub 集是这次移植的核心创新。

| Stub 头 | 替代 FreeBSD facility | 行为 |
|---|---|---|
| `sys/mutex.h` | `struct mtx` | `pthread_mutex_t` |
| `sys/rwlock.h` | `struct rwlock` | `pthread_rwlock_t` |
| `sys/refcount.h` | `refcount_*` | `__atomic_*` builtins |
| `sys/callout.h` | `callout_*` softclock | **GCD `dispatch_after` + 代次计数器**（macOS） / no-op + 外部 tick（其他平台） |
| `sys/epoch.h` | `NET_EPOCH_*` RCU | no-op，userspace 单线程假设 |
| `sys/mbuf.h` | 链式 mbuf | **单 flat malloc'd buffer**（无 scatter-gather；crypto copy 数据） |
| `sys/malloc.h` | `MALLOC_*` 三参宏 | calloc/free |
| `sys/queue.h` | TAILQ/LIST | 直接用 macOS 自带 sys/queue.h |
| `sys/endian.h` | `htobe*` | wrap OSByteOrder.h |
| `sys/ck.h` | CK lock-free list | 转 LIST_* |
| `sys/kernel.h` | `MALLOC_DEFINE` | no-op |
| `sys/lock.h` | `RA_*` 锁断言 | no-op flags |
| `sys/param.h` | `sbintime` 等 | userspace stub |
| `sys/systm.h` | `getnanotime` `explicit_bzero` | clock_gettime + memset_s |
| `crypto/curve25519.h` | curve25519 原型 | 转向 crypto_bridge.swift 或 curve25519_portable.c |
| `crypto/chacha20_poly1305.h` | chacha20poly1305 原型 | 转向 wg_crypto_impl.c |

**对称性破缺**：macOS `callout.h` 走 GCD；Android / Linux 端 stub 是 no-op，要求宿主提供外部 ~1Hz tick 回调（这就是 `wg_session_tick` 存在的原因）。`wg_core` 自己跑 callout；`wg_session` 让 Swift 端定时 dispatch tick。

---

## 5. Swift / NetworkExtension

### 5.1 三个 target

| Target | 路径 | 作用 |
|---|---|---|
| **WireGuardCore.xcframework** | 由 `scripts/build-xcframework.sh` 产出 | C + Curve25519 桥的多平台静态库，对外暴露 `wg_session.h` |
| **WireGuardTunnelExtension** | `NetworkExtension/Sources/PacketTunnelProvider.swift` (1066 行) | NEPacketTunnelProvider 子类。`com.change.wg.tunnel` |
| **WireGuardSampleApp** | `WireGuardSampleApp/WireGuardSampleApp/` | SwiftUI 宿主 App + TunnelManager。`com.change.wg` |

`NetworkExtension/WireGuardKit/` 只是一个 `module.modulemap`（20 行），把 `wg_session.h` 暴露成 `import WireGuardCore`。**不是** WireGuard 官方 Swift 包的 fork。

### 5.2 PacketTunnelProvider 关键路径

`NetworkExtension/Sources/PacketTunnelProvider.swift`：

```
startTunnel(options)                              // 入口
  → 解析 NETunnelProviderProtocol.providerConfiguration["config"]
    （wg-quick INI 文本明文存 Keychain）
  → wg_session_create(config_text, user_ctx=Unmanaged<self>)
  → 注册 3 个 C 回调：
      send_udp     → NWUDPSession.writeDatagram   :39
      deliver_ip   → packetFlow.writePackets       :39
      log_line     → emitLog                       :39
  → packetFlow.readPackets { ip → wg_session_handle_tun(ip) }
  → createUDPSession                               :142
    → NWUDPSession.setReadHandler { datagrams → wg_session_handle_udp }
  → 1Hz dispatch: wg_session_tick
  → wg_session_kick (立即触发握手)
  → setTunnelNetworkSettings(buildSettings)        :239-482
    (interface 地址、AllowedIPs → includedRoutes / excludedRoutes)
```

`Unmanaged<PacketTunnelProvider>` 当 `user_ctx`（`PacketTunnelProvider.swift:91-97`）传给 C 侧；C 回调取出 self 再转 Swift method。

**handlerAppMessage(_:completionHandler:)**：宿主 App 通过 `NETunnelProviderSession.sendProviderMessage` 发 UAPI GET/SET，PacketTunnelProvider 转给 `wg_session_uapi_get/set`，回返序列化结果（`TunnelManager.swift:470-510` 的对端）。

### 5.3 TunnelManager（宿主 App）

`WireGuardSampleApp/WireGuardSampleApp/TunnelManager.swift` 1130 行。围绕 **`NETunnelProviderManager`**（不是 NEVPNManager）：

| 能力 | 实现 |
|---|---|
| 启动 | `start()` `:456-464` → `manager.connection.startVPNTunnel()` |
| 停止 | `stop()` `:466-468` |
| 保存配置 | `save(config:, ...)` `:425-454` 写 `providerConfiguration["config"]` |
| 状态观察 | `:514-529` 监听 `.NEVPNStatusDidChange` |
| UAPI | `uapiGet()` / `uapiSet()` `:470-510` → `sendProviderMessage` |
| 配置持久 | Keychain via `KeychainStore` `:641-713`，支持 iCloud sync via `ProfileStorageMode` `:56-71` |
| 控制面集成（Latch） | `syncFromPlatform()` `:715-1130` pull JSON → 转 wg-quick INI |

### 5.4 Crypto bridge 契约

`src/crypto_bridge.swift`：

| C 导出函数 | 行 | 实现 |
|---|---:|---|
| `curve25519(out, secret, peer_pubkey)` | 30-51 | `Curve25519.KeyAgreement.sharedSecret()` |
| `curve25519_generate_public(out, secret)` | 53-70 | `priv.publicKey.rawRepresentation`，命中缓存复用 |
| `curve25519_generate_secret(out)` | 72-83 | `PrivateKey()` + 缓存 |
| `curve25519_clamp_secret(secret_inout)` | 85-92 | RFC 7748 clamping 位操作 |

**线程局部 `_cachedPrivKey`** `:27-28` —— WireGuard 握手单线程，缓存 PrivateKey 对象绕开 CryptoKit raw→raw 偶发失败。ChaCha20-Poly1305 AEAD **不**走 Swift，全由 `wg_crypto_impl.c` 出。

### 5.5 Entitlements / bundle ID

`WireGuardSampleApp.entitlements` `:4-19` + `WireGuardTunnelExtension.entitlements`：

```
com.apple.developer.networking.networkextension = [packet-tunnel-provider]
com.apple.security.app-sandbox                  = true
com.apple.security.network.client               = true
com.apple.security.network.server               = true
```

**无 App Group**。Keychain 同步用 `com.apple.developer.icloud-container-identifiers`（空数组占位）。

---

## 6. 端到端数据流时序

**握手（responder 接收 initiation）**：

```
NWUDPSession.read → swift handler
  → wg_session_handle_udp(initiation_pkt)         wg_session.c
    → noise_consume_initiation                    wg_noise.c:1119
        check timestamp · decrypt ephemeral · re-derive hash chain
    → noise_create_response                       wg_noise.c:1244
        derive sending keypair · derive AEAD keys
  → send_udp callback                             PacketTunnelProvider.swift
    → NWUDPSession.writeDatagram (response)
```

**Encap（发出 IP 包）**：

```
NEPacketTunnelFlow.readPackets → swift handler
  → wg_session_handle_tun(ip)
    → aips_lookup(allowedips, dst_ip)             allowedips.c:81
        → peer
    → noise_keypair_encrypt(kp, nonce, pt, ad)    wg_noise.c:1370
        ChaCha20-Poly1305 AEAD (wg_crypto_impl.c)
  → send_udp callback
    → NWUDPSession.writeDatagram (data)
```

**Decap（收到加密 UDP）**：

```
NWUDPSession.read → swift handler
  → wg_session_handle_udp(data_pkt)
    → noise_keypair_decrypt(kp, nonce, ct, ad)    wg_noise.c:1401
        AEAD + nonce 重放窗口
    → aips_lookup(allowedips, src_inner_ip)
        validate(packet src ∈ peer.AllowedIPs)    // anti-spoof
  → deliver_ip callback
    → packetFlow.writePackets (inner IP)
```

**Tick（外部 1Hz）**：

```
Swift dispatch_after 1s
  → wg_session_tick                               wg_session.c:967
    foreach peer:
      if (needs_rekey OR needs_handshake):
        noise_create_initiation
        → send_udp callback
```

---

## 7. 部署形态

### 7.1 两条 deploy 路径

| 场景 | 流程 |
|---|---|
| **开发 / 测试** | `make all` → `scripts/install.sh wg0` 装 `/usr/local/bin` + 渲染 launchd plist；conf 手写在 `/etc/wireguard/wg0.conf` |
| **最终用户（CLI 单机）** | `scripts/make-bundle.sh` 出 `dist/wg-mac-<date>-<sha>.tar.gz`（含预编译 arm64 + 脚本）→ scp 到目标 → `tar xz && sudo scripts/install.sh wg0` |
| **NE App（公测 / 上架）** | `scripts/build-xcframework.sh` 出 7 平台 xcframework → Xcode 集成到 WireGuardSampleApp + TunnelExtension → archive → TestFlight |

### 7.2 脚本速查

| 脚本 | 作用 |
|---|---|
| `scripts/install.sh <iface>` | 编译 / 复制二进制 / 渲染 plist `com.wireguard.wg-mac.<iface>.plist` / `launchctl bootstrap` |
| `scripts/uninstall.sh <iface>` | `launchctl disable + bootout` / 删二进制（**留 conf 给用户自删**） |
| `scripts/wgctl-agent.sh` | launchd 60s 重拉：心跳 + GET /v1/peers（单 iface 时走 `?wait/?rev` 长轮询，近实时；自动降级）→ diff → rewrite conf + kickstart |
| `scripts/build-xcframework.sh` | 7 平台交叉编译 → `build/xcframework/WireGuardCore.xcframework/`（macOS arm64+x86_64 / iOS dev+sim / tvOS dev+sim / visionOS opt-in） |
| `scripts/make-bundle.sh` | 编译一次 + 打包 tarball；`WG_SKIP_BUILD=1` 跳过 |
| `scripts/join.sh` | v0.2 预留：一键入网（curl bash + token） |
| `run_tunnel.sh [conf]` | 开发临时跑：直接 `./build/wg_core --tunnel <conf>`，不走 launchd |

### 7.3 launchd agent (`wgctl-agent`)

`scripts/com.wireguard.wgctl-agent.plist` + `scripts/wgctl-agent.sh`：

- 装在 `/Library/LaunchDaemons/com.wireguard.wgctl-agent.plist`
- `StartInterval = 60`，独立于具体接口数（一台机一份）
- 流程：读 `/etc/wgctl/config.json`（server URL、device_id、token、role） → POST `/v1/heartbeat`（best-effort） → GET `/v1/peers` 或 `/v1/hub/peers` → render `/etc/wireguard/<iface>.conf` → 若 diff 则 `launchctl kickstart -k`
- **幂等**：任何阶段失败保持现有 conf，wg_core 继续旧对端运行

### 7.4 安装后文件布局

```
/usr/local/bin/
  wgctl, wg_core
/etc/wireguard/
  wg0.conf                                  (0600 root, 含私钥)
/etc/wgctl/
  config.json                               (0600 root, server + token)
/var/run/wireguard/
  wg0.{pid,name,sock}                       (runtime, 0700)
/var/log/
  wireguard.wg0.{out,err}.log
  wgctl-agent.{out,err}.log
/Library/LaunchDaemons/
  com.wireguard.wg-mac.wg0.plist
  com.wireguard.wgctl-agent.plist
```

---

## 8. 控制面：JOIN 协议

`doc/JOIN_PROTOCOL.md` 全文。简版：

| 端点 | 方法 | 用途 | 关键字段 |
|---|---|---|---|
| `/v1/register` | POST | 初次入网（token 消费） | req: pubkey, hostname, lan_addrs, wg_listen → resp: device_ip (10.88.x.y/32), site_id, role, hub {pubkey, endpoint, wg_ip}, peers[], keepalive_sec |
| `/v1/peers` | GET | device 轮询 / 长轮询 | req: Bearer token + `X-Device-Id` `[?wait&rev]` → resp: device_ip, peers[], hub, refresh_sec, **rev**；长轮询超时回 `{"not_modified":true,"rev"}`（rev 待服务端补） |
| `/v1/hub/peers` | GET | hub 专用，扁平 device 列表 | + rev 字段做 diff / 同样支持 `?wait&rev` 长轮询 |
| `/v1/heartbeat` | POST | 心跳（可选） | lan_addrs, wg_endpoint, stats |
| `/v1/token/refresh` | POST | 令牌轮换（过期前 80%） | — |
| `/v1/leave` | POST | 主动注销 | — |

**IP 规划**：`10.88.0.0/16` 单一空间，按 site 切 /24。hub = `10.88.0.0/24`，site S = `10.88.S.0/24`，device = `10.88.S.D/32`。**First-register-wins** 选 hub（v0.2 改善方案待定）。

**客户端持久状态** `/etc/wgctl/config.json`（0600）：server / device_id / token / token_expires / wg_ip / site_id / last_refresh。

---

## 9. 安全模型

`SECURITY.md` 全文。要点：

| 项 | 实现 |
|---|---|
| 密钥生成 | OS CSPRNG（macOS `arc4random_buf`，Linux `/dev/urandom`） |
| 密钥存储 | iOS Keychain（at-rest enc）；macOS Keychain；conf 0600 |
| 密钥导出 | **永不**。UAPI GET 返回 `private_key=none`，server 只见 pubkey |
| 运行时 | 仅 `noise_local` struct，不 log、不写盘 |
| 算法 | X25519（RFC 7748）、ChaCha20-Poly1305（RFC 8439）、Blake2s（RFC 7693）、Noise_IKpsk2 |
| **零自创加密** | 仅搬运 + KAT 验证 |
| 抗重放 | nonce + 滑动窗口（`wg_noise.c`） |
| 反源欺骗 | decap 后 src ∈ peer.AllowedIPs（`aips_lookup`） |
| 路由回环防 | NE setTunnelNetworkSettings excludedRoutes 含 peer /32 |
| 已知限制 | 无 mlock 内存保护、无 formal verification、Android 端无 KeyStore 加密、无 cert pinning |

---

## 10. 测试

### 10.1 KAT 套件（`make test`，秒级完成）

`src/crypto_vector_test.c` 1268 行：

- Blake2s 3 RFC 向量 + streaming 一致性（12 chunking 切法）
- Curve25519 pubkey derivation + DH
- ChaCha20-Poly1305 RFC 8439 完整 AEAD KAT
- mbuf 路径 vs flat buffer 路径交叉验证（8 长度）
- Noise IK 握手 + transport 进程内回环
- AllowedIPs trie 5 case（v4 LPM、default route、v6、边界）
- UAPI GET/SET 往返
- PSK 配置 + get/set/clear

### 10.2 完整测试栈（`test_plan.md`）

| Layer | 内容 |
|---|---|
| 0 | utun 创建/销毁、handle 不泄漏、重复启停 |
| 1 | C 单元 + RFC KAT |
| 2 | 本机回环（两进程通过 UDP 127.0.0.1） |
| 3 | **与 Linux wg / wireguard-go 互通**：握手 + ping + iperf3 + rekey |
| 4 | UAPI 兼容（`wg show`、`wg setconf` 输出格式） |
| 5 | 故障注入：丢包、延迟、损坏、重放、DoS |
| 6 | 24h soak：内存 / fd / CPU |
| 7 | 性能对标 |

---

## 11. 运营痛点 & 已知 caveats

来自 `OPERATIONS.md` + `PORTING_LOG.md` + `WORK_LOG*.md` + 源码 TODO：

| 项 | 位置 | 现状 / workaround |
|---|---|---|
| launchd 残留 | OPERATIONS.md | `bootout` 后 KeepAlive credit 拖 ~30s，先 `disable` |
| TCC 权限 | OPERATIONS.md | osascript 提权下 root 读不到 `/Volumes/...`；workaround 拷到 `/tmp` 再跑 |
| Stale handshake | OPERATIONS.md | 查 peer reachable + key match + `/var/log/wireguard.err.log` 看 encap/decap FAILED |
| Token 轮换 | JOIN_PROTOCOL | 过期前 80% 刷；旧 token 过期设备降级不停机，需人工重发 token |
| Hub 选举 | JOIN_PROTOCOL | First-register-wins；hub 离线 >24h 标记待手工接管避免 split-brain |
| Conf 0600 | OPERATIONS.md | 含私钥 + token，**绝不可** world-readable |
| Conf 被 agent 覆盖 | wgctl-agent.sh | 用户手改下一轮被冲；需要持久改动改 control plane |
| `if_wg.c` 未编 | src/if_wg.c | FreeBSD 内核模块，NetworkExtension 替代；仅留作 wire format 参考 |
| `wg_client*.c` 弃 | src/wg_client{,2,3}.c | 实验客户端中文注释，没接入；不编 |
| callout 平台分叉 | macos_stubs/sys/callout.h | macOS GCD vs 其他平台外部 tick；wg_session 端 1Hz 由 Swift driver 推 |
| epoch 简化 | macos_stubs/sys/epoch.h | RCU 转无延迟回收，单线程假设 |
| mbuf flat | macos_stubs/sys/mbuf.h | 无 scatter-gather；crypto copy 数据，性能可优化 |
| Curve25519 缓存 hack | crypto_bridge.swift:20-26 | CryptoKit raw 往返偶发失败，缓存 PrivateKey 对象规避 |
| Apple ar 强 pin | Makefile:7 | Homebrew ar 输 GNU 归档 → linker 拒；显式 `/usr/bin/ar` |
| min macOS 11.0 | Makefile:32 | CryptoKit 下限 |

---

## 12. 路线图（todo.md / NEXT_STEPS.md 提取）

- v0.1：单机部署、CLI 守护、launchd、xcframework MVP ✅
- v0.2：`scripts/join.sh` 一键入网 + 自动 token 申请 + hub 选举改善
- v0.3：iOS / iPadOS NE 公测
- v0.4：性能（mbuf scatter-gather + 减少 copy）、Linux 端 callout 替代
- V2：节假日 / 跨域 hub / 多 hub 网格 / Android KeyStore 加密

---

## 13. 索引

| 想找 | 看 |
|---|---|
| 协议状态机 | `src/wg_noise.c` + `wg_cookie.c` + Noise IKpsk2 RFC |
| 加密原语 | `src/wg_crypto_impl.c`（ChaCha20-Poly1305）+ `crypto_bridge.swift`（Curve25519）+ `wg_noise.c`（Blake2s） |
| 路由查找 | `src/allowedips.c` |
| C 库总入口 | `src/wg_session.h`（16 个 extern "C" 函数） |
| 标准 CLI 跑 | `src/wg_core.c` |
| NE 接入 | `NetworkExtension/Sources/PacketTunnelProvider.swift` |
| 宿主 App 管理 | `WireGuardSampleApp/WireGuardSampleApp/TunnelManager.swift` |
| FreeBSD → macOS 翻译 | `src/macos_stubs/sys/*.h` |
| 编译 | `Makefile` |
| 装 / 拆 / agent | `scripts/install.sh` `uninstall.sh` `wgctl-agent.sh` |
| 入网协议 | `doc/JOIN_PROTOCOL.md` |
| 安全 | `SECURITY.md` |
| 测试 | `src/crypto_vector_test.c` + `test_plan.md` |
| 运营 | `OPERATIONS.md` |
| 移植史 | `PORTING_LOG.md` |
