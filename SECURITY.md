# 安全架构文档

> 为什么要自建 VPN 协议栈，而不是用现成的 wireguard-go 或 Apple/Google 的内置 API？
> 答案是一个词：**可审计性**。

---

## 一、为什么自己移植 WireGuard C 代码

### 1. 供应链可控

| 方案 | 代码来源 | 可审计 | 可定制 |
|---|---|---|---|
| Apple `NEVPNProtocolWireGuard` | Apple 闭源 | ❌ | ❌ |
| wireguard-go | Go runtime + CGo | ⚠️ 大 | ⚠️ |
| **本项目 (FreeBSD C 移植)** | FreeBSD 开源 + 自写桥接 | ✅ 全部 | ✅ 全部 |

- Apple 的内置 WireGuard 是黑盒，不能加自定义路由规则、不能对接平台 API、不能做 split tunnel 策略
- wireguard-go 带整个 Go runtime (~10MB)，审计面大，CGo 交叉编译复杂
- 本项目的 C 代码总共 ~3000 行核心协议（`wg_noise.c` + `wg_crypto*.c`），可以逐行审计

### 2. 密钥生命周期完全可控

| 环节 | 本项目实现 | 安全属性 |
|---|---|---|
| 私钥生成 | `curve25519_generate_secret()` → `/dev/urandom` (Linux/Android) 或 `arc4random_buf` (macOS) | OS 级 CSPRNG |
| 私钥存储 | iOS: Keychain (at-rest 加密) / Android: SharedPreferences (app sandbox) | 进程隔离 |
| 私钥传输 | UAPI GET 返回 `private_key=none` — **永远不暴露给 host app** | NE extension 内存隔离 |
| 私钥运行时 | 仅在 `noise_local` 结构体内，不导出、不 log、不写磁盘 | 内存隔离 |
| PSK | `noise_remote_set_psk()` 后立即 zero 本地 copy | 最小暴露窗口 |

### 3. 平台节点配置隔藏

平台下发的节点（`source == .platform`）：
- Config 文本 **不在 UI 展示**（ContentView 条件渲染）
- UAPI GET 的 `private_key` 字段固定返回 `none`
- Host app 通过 `sendProviderMessage` 只能拿到公钥、端点、统计，**拿不到私钥**
- 用户只能看到节点名 + 国旗 + 连接状态

---

## 二、Crypto 审计路径

### 使用的算法（全部 RFC 标准）

| 算法 | 用途 | 实现 | 验证 |
|---|---|---|---|
| X25519 (Curve25519 ECDH) | 密钥交换 | macOS: Apple CryptoKit; Android/Linux: `curve25519_portable.c` (donna) | RFC 7748 §6.1 KAT |
| ChaCha20-Poly1305 | 数据加密 + 认证 | `wg_crypto_impl.c` (纯 C, RFC 8439) | RFC 8439 §2.8.2 KAT + mbuf-vs-buffer 交叉验证 (8 lengths) |
| Blake2s | 哈希 + HMAC + KDF | `wg_crypto.c` (FreeBSD 原版) | RFC 7693 KAT (3 vectors) + streaming consistency (12 chunkings) |
| HKDF-Blake2s | Noise 握手密钥派生 | `wg_noise.c` (FreeBSD 原版) | 隐含验证：握手成功 = KDF 输出一致 |

### 没有自己发明的算法

所有密码学原语直接来自：
1. FreeBSD 内核 WireGuard 实现（`sys/dev/wg/`）— 同样的代码运行在 FreeBSD 14.x 的生产内核里
2. Adam Langley 的 curve25519-donna（公共领域）— Android 用
3. Apple CryptoKit — macOS/iOS 用

**我们不做任何密码学创新。** 只做搬运 + 适配 + 验证。

### KAT 测试覆盖

```
27 tests, all PASS:
├── Blake2s: 3 RFC vectors + streaming consistency
├── Curve25519: RFC 7748 §6.1 (pubkey derivation + DH)
├── ChaCha20-Poly1305: RFC 8439 §2.8.2 (完整 AEAD KAT)
├── mbuf path == buffer path: 8 lengths (0/13/16/32/48/96/112/113)
├── ChaCha20/XChaCha roundtrip + tamper detection
├── Noise IK handshake + transport loopback (in-process)
├── Allowedips trie: 5 tests (v4 LPM, default route, v6, edge)
├── UAPI GET round trip
├── UAPI SET round trip (endpoint + keepalive + aips + rejects)
├── PSK config + GET + SET + clear
├── Peer add via UAPI SET
└── Peer remove (tombstone) + re-add
```

运行方式：`make test` — 1 秒内完成，CI 可集成。

---

## 三、网络安全

### WireGuard 协议本身的安全属性

| 属性 | 说明 |
|---|---|
| 前向保密 (PFS) | 每次握手生成新的 ephemeral DH，旧会话密钥不可恢复 |
| 身份隐藏 | 发起方的静态公钥在 `encrypted_static` 里加密传输 |
| 抗重放 | 每个数据包有单调递增 nonce + 滑动窗口检查 |
| 抗 DoS | mac1 + mac2 cookie 机制，高负载下要求 cookie 验证 |
| 静默丢包 | 未认证的包不回复任何内容（端口扫描看不到 WireGuard） |
| 定期 Rekey | 120 秒或 2^60 消息后自动换密钥 |

### 本项目的网络层加固

| 措施 | 实现位置 |
|---|---|
| Anti-spoofing | `aips_lookup_inner_src()` — 解密后验证内网源 IP 属于发送方 peer 的 AllowedIPs |
| 路由回环防护 | `excludedRoutes` 包含 peer endpoint /32，防止 outer UDP 经 utun 回环 |
| 本地网络保护 | `localPhysicalSubnets()` 动态检测物理网卡子网并排除，保留 LAN 可达性 |
| DNS 泄露防护 | `NEDNSSettings` / `NEDNSOverHTTPSSettings` 强制 DNS 走隧道 |
| DoH 选项 | 用户可选 Cloudflare 1.1.1.1 DoH，加密 DNS 查询 |

---

## 四、平台安全

### iOS / macOS (NetworkExtension)

| 层 | 安全机制 |
|---|---|
| 进程隔离 | Extension 是独立沙盒进程，host app 不能访问其内存 |
| 通信 | 唯一通道是 `sendProviderMessage` (XPC)，wire format 是 text UAPI |
| 密钥不出 extension | `private_key=none` in UAPI GET |
| Code signing | NE entitlement 需要 Apple 签名 |
| App Sandbox | `com.apple.security.app-sandbox` 强制 |

### Android

| 层 | 安全机制 |
|---|---|
| VPN 权限 | `VpnService.prepare()` 需要用户显式同意 |
| 进程沙盒 | App data 在 `/data/data/com.change.wg/`，其他 app 不可读 |
| NDK 库 | `libwg_session.so` 通过 JNI 加载，无全局状态泄露 |
| 16KB 对齐 | `-Wl,-z,max-page-size=16384` 满足 Google Play 2025 要求 |

---

## 五、已知限制 & 未来加固

### 当前限制

| 项 | 状态 | 风险 | 后续 |
|---|---|---|---|
| Android 密钥存储 | SharedPreferences (app sandbox) | Root 设备可读 | 迁移到 AndroidKeyStore + EncryptedSharedPreferences |
| 证书 pinning | 无 | API 调用可被 MITM（如果用户装了恶意 CA） | 加 OkHttp CertificatePinner |
| 私钥内存保护 | 无 mlock / 无 zero-on-free | 理论上 swap 可泄露 | 加 `mlock()` + `explicit_bzero()` on free |
| UAPI SET 无认证 | `sendProviderMessage` 不验证调用者 | 同设备其他 app 无法直接调用（NE sandbox 隔离） | 加 HMAC 验证 |
| Curve25519 side-channel | donna 实现是常数时间但未做 formal verification | 学术级攻击 | 可替换为 HACL* 或 libsodium |

### 建议的后续安全工作

1. **Android EncryptedSharedPreferences** — 用 AndroidKeyStore 的 AES-GCM 加密节点配置
2. **Certificate Pinning** — API client 加 TLS 证书 pin，防中间人
3. **内存安全审计** — 用 AddressSanitizer 跑一遍 C 代码（`-fsanitize=address`）
4. **Fuzz testing** — 用 libFuzzer 对 `wg_session_handle_udp` 做模糊测试
5. **Formal verification** — 对 Curve25519 + ChaCha20-Poly1305 做 CT-verif 常数时间验证
6. **Reproducible builds** — 确保 APK / xcframework 可从源码 deterministic 重建

---

## 六、合规参考

| 标准 | 本项目相关性 |
|---|---|
| NIST SP 800-175B | ChaCha20-Poly1305 是 IETF 标准 (RFC 8439)，NIST 认可 |
| FIPS 140-3 | 当前不合规（未使用 FIPS 认证模块）；如需合规可替换为 BoringSSL FIPS 模块 |
| GDPR | VPN 隧道加密传输数据；DNS 可走 DoH 防泄露；不收集用户流量日志 |
| Apple App Review 4.2 | NE VPN apps 需要合理用途说明 + 隐私政策 |
| Google Play VPN Policy | 需要声明 VPN 用途 + 隐私政策 + 不得用于广告/数据收集 |

---

*文档版本：2026-04-13*
*适用范围：libwg 项目全平台（macOS / iOS / tvOS / Android）*
