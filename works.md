既然你选择走 **Network Extension (NE)** 路径，这在现代 macOS 开发中是最明智的选择。在这种架构下，你不再是写一个驱动，而是写一个受 macOS 沙盒管理的 **App Extension**。

要把 FreeBSD 的 `if_wg` 内核逻辑移植到 `PacketTunnelProvider`，你需要构建一个"三层蛋糕"架构：

---

## 1. 架构设计：三层模型

### A. 核心协议层 (C/C++ - 移植自 FreeBSD)
这是你从 FreeBSD 仓库获取的代码。你需要剥离掉所有包含 `<sys/...>` 和 `if_wg.c` 中与 FreeBSD 内核虚假接口相关的部分，只保留：
* **Noise 状态机** (`wg_noise.c`): 处理握手、密钥交换。
* **Cookie 机制** (`wg_cookie.c`): 处理抗 DDoS 攻击。
* **加密算法实现** (`wg_crypto.c`): ChaCha20-Poly1305 (mbuf 路径) 和 Blake2s。

### B. 桥接适配层 (C / Objective-C)
这一层负责将 FreeBSD 的数据结构映射到 macOS 用户态：
* **mbuf -> Buffer**: FreeBSD 使用 `mbuf` 链表，用户态用单段平坦缓冲区（带 `m_append`/`m_adj`）模拟。
* **定时器**: 将 FreeBSD 的 `callout` 机制改为基于 `dispatch_after` + 原子代次计数器（用于取消）。
* **多线程**: 将内核的 `taskqueue` 替换为 **GCD (Grand Central Dispatch)** 并发队列。

### C. 接入层 (Swift / Objective-C - NetworkExtension)
这是 macOS 的入口，即 `PacketTunnelProvider` 的子类：
* **`packetFlow`**: 负责从 `utun` 获取和写入 IP 包。
* **`NWUDPSession`**: 负责发送和接收 WireGuard 封装后的加密 UDP 包（推荐用这个而非原生 Socket，因为它能更好地处理系统级网络切换）。

---

## 2. 关键对接点与工作流

### 第一步：读取 utun 包 (Ingress)
当你的 macOS 应用产生网络流量时，系统会将 IP 包丢进 `packetFlow`：
```swift
self.packetFlow.readPackets { (packets, protocols) in
    for packet in packets {
        // 1. 调用 C 函数: wg_encapsulate(packet)
        // 2. 该函数进行 Noise 加密，返回封装好的 UDP Payload
        // 3. 使用 NWUDPSession 发送出去
    }
}
```

### 第二步：解封装 (Egress)
当从互联网收到加密的 UDP 包时：
1.  在 `NWUDPSession` 的回调中拿到数据。
2.  调用 C 函数：`wg_decapsulate(data)`。
3.  该函数通过 Noise 状态机解密，如果校验通过，返回原始 IP 包。
4.  通过 `self.packetFlow.writePackets` 将明文包塞回系统。

---

## 3. 核心难点：FreeBSD 内核 API 的替换表

在移植 FreeBSD 源码时，你需要处理以下符号冲突和 API 缺失：

| 功能 | FreeBSD 内核 (src) | macOS NE (用户态) 替代品 |
| :--- | :--- | :--- |
| **内存分配** | `malloc(..., M_WAITOK)` | `calloc()` (3-arg macro) |
| **UMA 分配器** | `uma_zcreate` / `uma_zalloc` | `calloc` / `free` |
| **互斥锁** | `mtx_lock()` / `mtx_unlock()` | `pthread_mutex_t` |
| **读写锁** | `rw_rlock()` / `rw_wlock()` | `pthread_rwlock_t` |
| **引用计数** | `refcount_acquire()` | `__atomic` builtins |
| **CK 链表** | `CK_LIST_*` | `sys/queue.h` `LIST_*` |
| **epoch SMR** | `NET_EPOCH_ENTER/EXIT` | no-op（单线程适配层） |
| **定时器** | `callout_reset()` | `dispatch_after` + 代次原子计数 |
| **网络包** | `struct mbuf` | 平坦缓冲区（`m_data`/`m_len`/`m_pkthdr.len`） |
| **opencrypto** | `crypto_dispatch()` | 纯 C RFC 8439 实现（`wg_crypto_impl.c`） |
| **时间** | `getmicrotime()` / `sbintime_t` | `clock_gettime(CLOCK_MONOTONIC)` |
| **日志** | `log(LOG_INFO, ...)` | `os_log()` |
| **SipHash** | `<crypto/siphash/siphash.h>` | 自包含静态内联实现 |
| **explicit_bzero** | `<string.h>` (gated) | volatile 循环宏 |

---

## 4. 加密实现策略

`wg_crypto.c` 使用 FreeBSD opencrypto 框架（`crypto_newsession` / `crypto_dispatch`）做 mbuf 内加密。移植策略：

1. **`opencrypto/cryptodev.h`** 提供类型桩（`crypto_session_t`, `struct cryptop`），`crypto_dispatch` 声明为外部函数。
2. **`wg_crypto_impl.c`** 实现完整的 RFC 8439 ChaCha20-Poly1305：
   - ChaCha20 块函数（20 轮）
   - Poly1305（26-bit limb 算术，常数时间 finalize）
   - HChaCha20 子密钥派生（用于 XChaCha20 变体）
   - `crypto_dispatch`：从 `struct cryptop` 读取 mbuf / 密钥 / nonce，原地加密/解密并写入认证 tag。
3. 所有源文件**零修改**，仅通过 stub 头和同一 `-I` 优先级解决符号。

---

## 5. 为什么不直接用 `wireguard-go`？

目前官方 macOS 版 WireGuard 使用的是 Go 实现（用户态）。如果你执意要移植 FreeBSD 的 C 代码，通常理由只有两个：
1.  **极致性能**：C 语言在内存管理和加密指令集调用上比 Go 更直接。
2.  **代码复用**：你对 FreeBSD 的这套实现非常熟悉，且已经针对特定场景做了优化。

**专家提醒：**
在 `PacketTunnelProvider` 中，你拥有有限的内存（通常是 **15MB - 50MB**，取决于 macOS 版本和策略）。移植 C 代码时，务必检查是否存在内存泄漏，因为内核代码通常假设内存管理由 OS 托底，但在用户态进程中，一点点泄漏就会导致 Extension 被系统杀掉。

---

## 6. 进度记录

### ✅ 已完成

| 文件 | 状态 | 说明 |
| :--- | :--- | :--- |
| `wg_noise.c` | **编译通过** | Noise IKpsk2 握手状态机 |
| `wg_cookie.c` | **编译通过** | 抗 DDoS Cookie 机制 |
| `wg_crypto.c` | **编译通过** | Blake2s + ChaCha20-Poly1305 mbuf 路径 |
| `wg_crypto_impl.c` | **编译通过** | 纯 C RFC 8439 实现 + `crypto_dispatch` 桥接 |

新增 stub 头文件：

| Stub | 说明 |
| :--- | :--- |
| `sys/mbuf.h` | 平坦缓冲区 mbuf（`m_append` realloc，`m_adj` 头/尾裁剪） |
| `sys/callout.h` | GCD `dispatch_after` + 代次原子计数取消 |
| `vm/uma.h` | UMA 分配器 → `calloc`/`free` |
| `netinet/in.h` | `#include_next` + `satosin`/`satosin6` 宏 |
| `opencrypto/cryptodev.h` | opencrypto 类型桩 + `POLY1305_HASH_LEN` |
| `crypto/chacha20_poly1305.h` | 函数原型（实现在 `wg_crypto_impl.c`） |
| `crypto/curve25519.h` | 函数原型（实现待接入） |

### 🔲 下一步

1. **Curve25519 实现**：提供 `curve25519` / `curve25519_generate_public` 的 C 实现（可 vendor `donna_c64.c`，或调用 Apple CryptoKit via Swift 桥接）。
2. **`if_wg.c` 移植**：接口管理逻辑，依赖完整的 NE 桥接层。
3. **Swift / PacketTunnelProvider 层**：`packetFlow` ↔ mbuf ↔ C 函数的对接。
4. **集成测试**：与真实对端（Linux `wg-quick`）进行握手验证。
