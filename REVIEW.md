# WireGuard macOS 用户态移植 —— Code Review

**范围**：`wg/src/` 整个移植树，重点围绕 `wg_core.c` 这个端到端握手自测试客户端。
**目标形态**：用户态进程 + `utun` + UDP socket（类 wireguard-go 架构），核心复用 FreeBSD 的 `wg_noise.c` / `wg_cookie.c` / `wg_crypto.c`。

---

## 1. 当前进展

| 组件 | 状态 | 说明 |
|---|---|---|
| `macos_stubs/` 内核头仿真 | ✅ | `mbuf`、`rwlock`、`mutex`、`refcount`、`epoch`、`callout`、`malloc`、`uma` 等均已 stub |
| `wg_noise.c` / `wg_cookie.c` | ✅ | 原样编译通过，未改动 |
| `wg_crypto.c` (Blake2s) | ✅ | 通过 `COMPAT_NEED_BLAKE2S` 内联实现 |
| `wg_crypto_impl.c` (ChaCha20-Poly1305 + XChaCha) | ✅ | 纯 C 自实现，RFC 8439 |
| Curve25519 (`crypto_bridge.swift`) | ⚠️ | CryptoKit 实现，但未纳入 Makefile |
| `build/libwg.a` | ✅ | 自动构建通过（`make`） |
| `wg_core.c` 握手探针 | 🟡 | 能跑通 Linux wg 对端的 handshake，但存在下列 bug |
| utun 数据面 | ❌ | 未开始 |
| UAPI (`wg show/setconf`) | ❌ | 未开始 |
| allowedips / 定时器 / staged queue | ❌ | 未移植 |

对照 `test_plan.md` 的分层：**L1 的 noise/crypto 独立编译 ✅，L3 最小握手互通 🟡，其余未启动。**

---

## 2. 严重 Bug

### A. `wg_core.c` 包头字节序错误（阻塞性）

FreeBSD `if_wg.c:73-76`：
```c
#define WG_PKT_INITIATION htole32(1)
#define WG_PKT_RESPONSE   htole32(2)
#define WG_PKT_COOKIE     htole32(3)
#define WG_PKT_DATA       htole32(4)
```

`wg_core.c` 却用 host order：
```c
#define WG_PKT_INITIATION 1u
...
pkt.t = WG_PKT_INITIATION;          // 349
hdr.t = WG_PKT_DATA;                // 471
hdr.nonce = nonce;                  // 473 —— 也漏了 htole64
if (t == WG_PKT_COOKIE) ...         // 386
```

在 arm64 little-endian macOS 上表面能跑，但线协议语义错误，CI/大端目标/跨平台对拍立刻 broken。

### B. Keepalive 缺 16 字节 padding（阻塞 L2 数据面）

`send_keepalive_data()` 这样构造 mbuf：
```c
m = m_devget(&dummy, 0);              // 长度 0
noise_keypair_encrypt(kp, &r_idx, nonce, m);
```

`chacha20poly1305_encrypt_mbuf` 只 `m_append` 了 16 字节 tag，最终 transport payload 仅 16 字节（全是 tag）。但 WireGuard 要求 data 包 payload 按 `WG_PKT_PADDING = 16` 对齐（keepalive 为空 plaintext 时 padlen = 16）。见 `if_wg.c:1547 calculate_padding`：
```c
if (pkt->p_mtu == 0) {
    padded_size = (last_unit + 15) & ~15;
    return padded_size - last_unit;   // 0 + 16 → padlen = 16
}
```

Linux 对端会拒绝（或至少统计为 invalid packet）。对测试来说"握手 OK"看起来过了只是因为 data 包没被检查 —— 真跑 ping 就崩。

### C. `libswift_crypto.a` 未纳入 Makefile（`libwg.a` 不自包含）

`Makefile` 只产 `libwg.a`。而 `libwg.a` 通过 `wg_noise.c` 引用 `curve25519` / `curve25519_generate_public` —— 这些符号在 `crypto_bridge.swift` 里，靠手动 `buildclient.sh` 临时 swiftc 出来。结果：

- 任何外部使用者链接 `libwg.a` 都会 undefined symbol。
- `wg_core.c` 不在 Makefile 里，靠 `buildclient.sh` 编译 `wg_client3.c`（另一个过时的测试程序），而 `wg_core.c` **根本没有对应的构建规则**。

---

## 3. 次要问题

### D. `wg_pkt_*` 结构体无 static_assert

`wg_core.c` 自己定义了 `wg_pkt_initiation/response/cookie/data_hdr`，虽然自然对齐在 x86_64/arm64 下 sizeof 正确（148/92/64/16），但没有 `_Static_assert` 保护。FreeBSD 原版用 `CTASSERT`，建议对齐。

### E. mbuf stub 单段限制（已知约束，仅做标注）

`macos_stubs/sys/mbuf.h` 是单段平坦 buffer，没有 `m_next` / chain / pullup。`wg_noise.c` transport 路径只需一段，OK。但 `if_wg.c` 的 staged queue、`M_PREPEND`、chain walk 等逻辑**不可**直接复用。移植 utun 数据面时要注意这条约束，不要整块搬 `if_wg.c`。

### F. `wg_crypto_impl.c::crypto_dispatch` 硬编码 AAD=0

`crypto_dispatch` 在 ENCRYPT/DECRYPT 两分支里都写 `le64enc(len_buf, 0); /* aad_len = 0 */`。这在 WireGuard data 面是正确的（transport 包无 AAD），但从通用 `crypto_dispatch` 语义看是"偷懒"。注释里应该写明"仅用于 WireGuard transport，不支持 AAD"，免得未来误用。

### G. `wg_core.c` 没有 TAI64N 时钟保护与重传退避

对 noise 原语的调用是对的，但：
- 没有在握手失败后指数退避
- 没有处理 `noise_remote_initiation_expired`
- `wait_for_response` 收到 cookie reply 后返回 `1`，主循环把它当失败处理（`if (w == 0)`），下次重试时 `noise_create_initiation` 会重新生成 ephemeral —— 这没问题，但 cookie 没被用在 mac2 上（因为 `cookie_maker_mac` 下次还是会读 `cm_cookie_valid` 状态，这条路径依赖 `cookie_maker_consume_payload` 已经设置了）。OK，不算 bug，但建议补一条日志确认 mac2 实际被填。

这几条是 L3 互通测试阶段再处理，不阻塞当前修复。

---

## 4. 修复计划

本次 Review 附带修复以下项：

1. **[A] 字节序**：`wg_core.c` 改用 `htole32` / `le32toh` / `htole64`，并把 `WG_PKT_*` 宏与 FreeBSD 对齐。
2. **[B] Keepalive padding**：在 `send_keepalive_data` 中构造 16 字节零 padding 的 mbuf，使 transport payload = 16+16 = 32 字节。
3. **[C] Makefile**：增加 `libswift_crypto.a` 构建规则，并新增 `wg_core` 目标（把 `wg_core.c` 链到 `libwg.a` + `libswift_crypto.a`）。
4. **[D] static_assert**：给 `wg_pkt_*` 加 `_Static_assert(sizeof(...) == N, ...)`。
5. **[F] 注释**：在 `crypto_dispatch` 头上标注"AAD 固定为 0，仅用于 transport"。

E/G 留作后续任务，不动。

---

## 5. 修复后如何验证

```bash
cd /Users/apple/Codex/wg
make clean && make                  # 应同时产出 libwg.a / libswift_crypto.a / wg_core
./build/wg_core src/test.ini        # 观察输出
```

预期输出：
```
[info] pkt sizes: initiation=148 response=92
[handshake] attempt 1
[handshake] success
[data] keepalive packet sent
```

再用 tcpdump 核对：
- initiation 包第一字节是 `01 00 00 00`（LE 的 1）
- data 包 payload 长度 = 32（16 padding + 16 tag）
- data 包 header: `04 00 00 00 | r_idx(LE) | nonce(LE64)`

---

## 6. 🔥 跑真实 server 时暴露的 Bug（Round 2）

修完 A–D 后跑真实 server (`client.conf` → Linux `wg0` @ 172.16.203.128:51820)，UDP 连通但 **握手被 server 静默丢弃**。排查步骤：

1. **Dump 包内容**：第一字节 `01 00 00 00`，mac1 非零、mac2 全零，layout 正确。
2. **Dump 密钥派生**：`noise_local_keys` 返回的 pubkey 与 `wg pubkey` 对拍匹配，Curve25519 bridge (Swift CryptoKit) 正确。
3. **怀疑 ChaCha20-Poly1305**。原有 `crypto_vector_test.c` 只有 roundtrip（自己加密自己解密），不会发现"ciphertext 对但 tag 错"类型的 bug。加入 **RFC 8439 §2.8.2 Known-Answer Test**，立刻暴露：

   ```
   [FAIL] chacha20-poly1305 RFC 8439 KAT
     expected: ...61161ae10b594f09e26a7e902ecbd0600691
     actual  : ...6116a93b7aa55fabacdd333d19eae10f7885
   ```

   密文 byte-for-byte 一致，**只有最后 16 字节 tag 错**。

### Bug：`poly1305_update` 不缓存跨调用的部分块

`wg_crypto_impl.c` 原实现：
```c
static void poly1305_update(poly1305_ctx *ctx, const uint8_t *m, size_t len)
{
    while (len >= 16) { poly1305_block(ctx, m, 1u << 24); m += 16; len -= 16; }
    if (len > 0) {
        uint8_t buf[16] = {0};
        memcpy(buf, m, len);
        buf[len] = 1;                          // ← "last block" marker
        poly1305_block(ctx, buf, 0);           // ← hibit = 0, 终结块语义
    }
}
```

问题：**任何 `len % 16 != 0` 的 update 调用都被当成"最后一块"处理**，立刻 append `0x01` 并用 `hibit=0` 喂进状态。但 RFC 8439 AEAD 构造（`AAD || pad16 || CT || pad16 || len(AAD) || len(CT)`）天然会多次调用 update，且每段的末尾大概率不是 16 字节对齐。举例：

- `poly1305_update(aad, 12)` — 被当成最后一块，写死 hibit=0 ❌
- `poly1305_pad16(ctx, 12)` — 再 update 4 字节零，又被当成最后一块 ❌
- `poly1305_update(ciphertext, 114)` — 96 字节 OK，剩 18？不，剩 2 字节又是"最后一块" ❌
- ...

结果：ChaCha20 流正确（所以密文对），但 Poly1305 累加器被多次"终结"，MAC 值完全错乱。

在 WireGuard 握手包场景：
- `chacha20_poly1305_encrypt(encrypted_static, 32, hash, 32, ...)` → AAD=32 (16 的倍数 ✓)、PT=32 (16 的倍数 ✓) → 单块正好 16 对齐，**偶然不踩坑**。
- `chacha20_poly1305_encrypt(encrypted_timestamp, 12, hash, 32, ...)` → AAD=32 ✓、PT=12 → **踩坑**，timestamp 的 tag 错误，server 解密失败、静默丢弃。

这解释了为什么 initiation 包看起来正确但 server 不回应。

### 修复

给 `poly1305_ctx` 加 16 字节 `buf` + `buflen`，改写 `poly1305_update` 先消化 buffered partial，再跑满块，最后把 tail 存回 buf；`poly1305_finish` 里才做真正的"最后一块 + 0x01 marker"处理。详见 `wg_crypto_impl.c` patch。

### 验证

```bash
$ ./build/crypto_vector_test
[PASS] blake2s("abc") vector
[PASS] chacha20-poly1305 RFC 8439 §2.8.2 KAT
[PASS] chacha20-poly1305 roundtrip + tamper
[PASS] xchacha20-poly1305 roundtrip + tamper
All crypto vector tests passed.

$ ./build/wg_core src/client.conf
[info] pkt sizes: initiation=148 response=92
[handshake] attempt 1
[handshake] success
[data] keepalive packet sent
```

Server 端 `wg show wg0`：
```
peer: TqbeoU9mcVHNariBBVoRvEySH0I0GWuUJ72Tj5qnam0=
  latest handshake: <just now>
  transfer: ... received, ... sent
```

### 教训

- **纯 roundtrip 测试 ≠ KAT**。自写 crypto 必须用 RFC 公开向量做 known-answer。后续加更多 KAT：Curve25519 RFC 7748 §6.1、Blake2s 长消息、ChaCha20 §2.4.2 等。
- **Poly1305 是多次 update 可重入的流式 API**。任何流式 hash / MAC 实现都必须显式区分"部分块缓冲"和"最终化"两个阶段。
- **WireGuard 握手 `encrypted_static` 正好 16 字节倍数 → 偶然躲过 bug**；但 `encrypted_timestamp` = 12 字节必踩雷。要不是真实 server 对拍，roundtrip 能永远绿灯下去。

---

## 7. 🔥 数据面静默丢包：r_idx 字段方向写反（Round 3）

修完 poly1305 + 接好 utun 数据面之后，握手仍然成功，但 ping 一个回包都收不到。Server 端 tcpdump 显示我们的 data 包全部送达了，但 server 既不回复也不在 dmesg 报错；`wg show wg0 transfer` 的 rx_bytes 增量恰好等于 148（一个 handshake initiation 大小），证实我们的 4 个 data 包**根本没走到 server 端的 decrypt-成功计数行**。

排查路径：
1. 加了 mbuf-vs-buffer 全长度 KAT（0/13/16/32/48/96/112/113）—— 全 PASS，crypto 完全无锅。
2. 加了 wg_encap 的 first-packet 完整 hex dump：

   ```
   [wire] first data packet: 48 bytes
     0000: 04 00 00 00 5c 93 44 53 00 00 00 00 00 00 00 00
     ...
   ```
3. 字段拆解后立刻意识到 `5c 93 44 53` 是 r_idx 字段。对照 FreeBSD `if_wg.c:1448`：
   ```c
   noise_consume_response(sc->sc_local, &remote, resp->s_idx, resp->r_idx, ...);
   ```
   而我自己的 `wait_for_response` 写的是：
   ```c
   noise_consume_response(local, &matched, s_idx /* 我们自己的 */, pkt.r_idx, ...);
   ```
   把第 3 参数写错了。

### Bug 的实际后果

`noise_consume_response` 的 `s_idx` 参数被存进 `r->r_index.i_remote_index`，这个值代表"对端的本地 index"，应该是 server 在 handshake response 里写在 `s_idx` 字段的值（来自 `pkt.s_idx`）。但我传的是**我们自己**的 sender index。

所以 `kp->kp_index.i_remote_index` 里存的是我们自己的 index。每次 `noise_keypair_encrypt` 输出 `*r_idx = kp->kp_index.i_remote_index`，就把"我们自己的 index"塞进了 data 包的 `r_idx` 字段。Server 在自己的索引哈希里查这个值 —— 当然查不到 —— 直接 `kfree_skb_reason(SKB_DROP_REASON_WIREGUARD_NO_KEYPAIR_FOUND)` 静默丢弃。

### 为什么握手没暴露这个 bug

`noise_consume_response` 内部用第 4 参数 `pkt.r_idx`（这个我传对了）查找 noise_remote。这一步根本不引用第 3 参数。所以握手认证全程通过，**只有数据包加密时引用 `kp_index.i_remote_index` 才会引爆 bug**。

握手 path 和数据 path 走的是完全不同的字段，互相不能背书对方的正确性。

### 修复

```c
- ret = noise_consume_response(local, &matched, s_idx, pkt.r_idx, ...);
+ if (pkt.r_idx != expected_local_idx)   /* sanity */
+     return -1;
+ ret = noise_consume_response(local, &matched, pkt.s_idx, pkt.r_idx, ...);
```

加了一行 sanity check 因为 `noise_consume_response(s_idx, r_idx)` 的两个参数语义不对称（一个属于 responder 一个属于 initiator），将来很容易再写错。

### 验证

```
$ ping -c 5 10.88.0.1
PING 10.88.0.1: 56 data bytes
64 bytes from 10.88.0.1: icmp_seq=0 time=1.890 ms
64 bytes from 10.88.0.1: icmp_seq=1 time=10.979 ms
64 bytes from 10.88.0.1: icmp_seq=2 time=11.568 ms

3 packets transmitted, 3 packets received, 0.0% packet loss

[tunnel] shutdown. final: tx=3 pkts/252 B  rx=3 pkts/252 B
```

**端到端通了。M1 数据面全部完成。**

### 教训

- **现代 Linux 的 silent drop 不再走 dmesg。** `SKB_DROP_REASON_*` 是新的 framework，dmesg 永远看不到，要靠 `bpftrace tracepoint:skb:kfree_skb`。下次 silent drop 第一反应是 bpftrace 而不是 dmesg。
- **计数器是真相，dmesg 是噪音。** 这次给出关键定位的不是 dmesg，是 `wg show transfer rx_bytes` 的精确增量（148 = exactly handshake init）。任何子系统调试都先问"它有没有计数器"。
- **wire dump 应该比 KAT 早做。** mbuf-vs-buffer KAT 写了 25 分钟，wire dump 写了 5 分钟，后者一秒命中 bug。**调 wire protocol 的第一动作是 hex dump 实际字节，再写抽象测试。**
- **握手通了 ≠ 数据面通了。** Round 2 + Round 3 两个不同的 bug 都是这个模式。一个 bug 在 `encrypted_timestamp` 那条 path 上、一个 bug 在 data path 上、握手都成功但数据都失败。**协议正确性必须 ping 通才算数。**
