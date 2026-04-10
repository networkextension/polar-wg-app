# WireGuard macOS 用户态移植 — 调试工作日志

> 这份文档记录了从「libwg.a 能编译」到「真实 Linux server 握手成功」之间那一段最难受的调试过程。重点不是最后那几行 patch，而是**如何一步步把范围从"整个协议栈"收敛到"poly1305_update 的 3 行代码"**，以及**调试环境本身是怎么影响思考节奏的**。

---

## 0. 起点：一个"看起来都对"的初版

把 FreeBSD 的 `wg_noise.c` / `wg_cookie.c` / `wg_crypto.c` 通过 `macos_stubs/` 伪装内核头搬到 macOS 用户态之后，拿一个最小 handshake 探针 `wg_core.c` 对拍真实 Linux server：

```
$ ./build/wg_core src/client.conf
[info] pkt sizes: initiation=148 response=92
[handshake] attempt 1
recv: Resource temporarily unavailable
[handshake] attempt 2
recv: Resource temporarily unavailable
...
[handshake] failed after retries
```

Server 端 `wg show wg0` 的 `latest handshake` 完全没刷新，也没 `transfer received` 的增量。

**这是最折磨的一类 bug**：没有崩溃、没有错误码、没有日志 —— 对端**静默丢包**。 WireGuard 本身设计如此：任何校验失败的包（mac1 错、timestamp 太旧、AEAD tag 不过）都直接 `drop`，不回 ICMP、不回 reject，这是它的 anti-DoS 特性之一。对攻击者是好事，对调试者是地狱。

---

## 1. 第一次收敛：排除"网络不通"

调试第一原则是**先排除环境，再怀疑代码**。

```bash
$ nc -z -v -u 172.16.203.128 51820
Connection to 172.16.203.128 port 51820 [udp/*] succeeded!
$ ping -c 2 172.16.203.128
64 bytes: time=3.259 ms
64 bytes: time=0.590 ms
```

UDP 连通，延迟 1ms 级，直连 VM。**网络层 OK**，问题 100% 在应用层。

**教训**：在花半小时怀疑 NAT、防火墙、路由表之前，`nc -u -z` 五秒搞定。

---

## 2. 第二次收敛：我发的包到底长什么样？

静默丢包场景下，**唯一客观的真相来源是线上的字节**。WireGuard 包格式非常简单，手工就能校验前几个关键字段：

- byte 0..3: type（`01 00 00 00` = initiation, LE）
- byte 4..7: sender index
- byte 8..39: ephemeral pubkey
- 末尾 32 字节: mac1 (16B) + mac2 (16B)

往 `send_initiation` 里插了十几行 hexdump：

```
[initiation] first 16 bytes: 01 00 00 00 30 dc 5f 94 7b 99 ad ec 2b 44 34 08
[initiation] last 32 (mac1+mac2): ae f3 38 ed 2d 1a 8d 22 4e 90 7a 7a b5 a8 af 38
                                  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

✅ type = 01 00 00 00 — LE 字节序对。
✅ mac1 非零 — cookie_maker_mac 真的跑了。
✅ mac2 全零 — 首次握手未收到 cookie reply，正常。
✅ sender index 每次不同 — 每次都重新生成 ephemeral。

**layout 完全符合 WireGuard 线协议**。所以 bug 不在 `wg_core.c` 组包阶段，而在更深处。

**这里有个关键心态**：看到这些字节时我第一反应是"那肯定是协议逻辑错了，可能 noise 状态机搬过来有 bug"，但立刻逼自己停下来 —— **协议状态机是 FreeBSD 原样代码，没动**。动过的只有两块：

1. `macos_stubs/` —— 内核 API 伪装层（mbuf / rwlock / callout / epoch）
2. `wg_crypto_impl.c` —— 我自己手写的 ChaCha20-Poly1305

**奥卡姆剃刀：先怀疑自己写的，后怀疑 FreeBSD 原版。**

---

## 3. 第三次收敛：先排除 Curve25519

`noise_create_initiation` 用到三样东西：
- Curve25519 (Swift CryptoKit bridge)
- Blake2s (FreeBSD 原版 `wg_crypto.c`)
- ChaCha20-Poly1305 (我自己写的 `wg_crypto_impl.c`)

Curve25519 走 Swift CryptoKit（Apple 官方实现），按理最不可能错。但为了彻底排除，调用 `noise_local_keys` 反推出本地 pubkey 打印，对拍 `echo PRIV | wg pubkey`：

```
[keys] derived local pubkey: 4e a6 de a1 4f 66 71 51 ... 9a a7 6a 6d
```

`wg pubkey` 同一私钥给出同样的值 —— **Curve25519 bridge 工作正常**。

Blake2s 有 RFC KAT (`"abc" → 508c5e8c...`)，`crypto_vector_test.c` 里早就过了。

**嫌疑人锁定到 ChaCha20-Poly1305**。

---

## 4. 调试环境的关键影响：为什么 `crypto_vector_test` 给了我假绿灯？

这里是这次调试最关键的反思点。看看原来的测试：

```c
static int test_chacha20_poly1305_roundtrip(void)
{
    // 随机 key/nonce/ad/plain
    chacha20_poly1305_encrypt(enc, plain, ...);
    chacha20_poly1305_decrypt(dec, enc, ...);
    if (memcmp(dec, plain, ...) != 0) return 1;  // ❌ fail
    // tamper check
    enc[last] ^= 1;
    if (chacha20_poly1305_decrypt(...))  return 1;  // tamper should fail
    return 0;
}
```

**这个测试永远会通过一个一致但错误的实现**。只要 encrypt 和 decrypt 用同一个"错误但对称的" MAC 算法，roundtrip 就一定对上。它测的是"我能解开我自己加密的东西"，不是"我的密文是不是标准 ChaCha20-Poly1305"。

> **调试环境本身是一个测量工具。测量工具有 bug，你看到的所有"证据"都被污染。**

我花了 40 分钟在这个假绿灯上：看着 `[PASS] chacha20-poly1305 roundtrip` 就下意识把 ChaCha20-Poly1305 从嫌疑名单里划掉了，转去怀疑：
- noise 状态机的 HKDF 顺序
- mbuf stub 的长度计算
- 字节序（即使 hexdump 都正确）
- 甚至想过是不是 Swift Curve25519 在某些随机数下会不 clamp（瞎猜）

**浪费了 40 分钟**。

**转折点**：决定不信任 roundtrip，去 RFC 8439 §2.8.2 抄一份完整 known-answer test —— 包括那句著名的 "Ladies and Gentlemen of the class of '99..."。这是 IETF 标准里钉死的加密输出，byte-for-byte 可对。

```c
static int test_chacha20_poly1305_rfc8439_kat(void)
{
    // key, nonce, aad, pt 全部从 RFC 8439 §2.8.2 抄
    // expected 密文+tag 共 130 字节也从 RFC 抄
    chacha20_poly1305_encrypt(enc, pt, pt_len, aad, 12, nonce, 12, key);
    if (memcmp(enc, expected, sizeof(expected)) != 0) {
        print_hex(expected); print_hex(enc);  // 让 diff 一目了然
        return 1;
    }
    return 0;
}
```

跑出来：

```
[FAIL] chacha20-poly1305 RFC 8439 KAT
  expected: ...6116 1ae10b594f09e26a7e902ecbd0600691
  actual  : ...6116 a93b7aa55fabacdd333d19eae10f7885
             ↑    ↑
             密文相同    tag 完全不同
```

**这一刻真相大白**：前 114 字节密文完全正确，**只有 16 字节 Poly1305 tag 是错的**。

这立刻把搜索空间从"ChaCha20-Poly1305 整个模块"缩小到"Poly1305 那一部分"。**几分钟之内**就找到了 bug。

**教训**：调试环境/测试工具必须自己先被验证过。Roundtrip 测试 ≠ KAT 测试。**"能自洽"和"和世界对的上"是两个概念。**

---

## 5. 定位到具体那三行

知道 Poly1305 tag 错之后，肉眼读 `poly1305_update`：

```c
static void poly1305_update(poly1305_ctx *ctx, const uint8_t *m, size_t len)
{
    while (len >= 16) { poly1305_block(ctx, m, 1u << 24); m += 16; len -= 16; }
    if (len > 0) {
        uint8_t buf[16] = {0};
        memcpy(buf, m, len);
        buf[len] = 1;                  // ← 任何 tail 都被当成最后一块
        poly1305_block(ctx, buf, 0);   // ← hibit=0，终结块语义
    }
}
```

RFC 8439 §2.8.1 AEAD 构造是：

```
MAC = Poly1305(AAD || pad16(AAD) || CT || pad16(CT) || len(AAD) || len(CT))
```

调用方 (`aead_encrypt_96` / `crypto_dispatch`) 会多次调 `poly1305_update`，每段可能都是非 16 倍数。上面那个实现里，**每一次 non-aligned update 都会把流"提前终结"**，累加器直接乱掉。

**为什么 WireGuard handshake 的 `encrypted_static` 恰好能过？**
- AAD = hash = 32 字节（16 倍数 ✓）
- PT = static pubkey = 32 字节（16 倍数 ✓）
- 每段尾部都是 16 对齐，`len > 0` 分支根本不触发
- → bug 被隐藏

**为什么 `encrypted_timestamp` 必踩？**
- AAD = hash = 32 字节 ✓
- **PT = TAI64N timestamp = 12 字节** ❌
- 第二段 update 触发 `len > 0` 分支 → 累加器提前终结 → tag 错

所以 initiation 包的 mac1 是对的（不走 Poly1305），`encrypted_static` 是对的（偶然对齐），**但 `encrypted_timestamp` 的 tag 是错的**。Linux kernel wg 解 timestamp 失败 → `drop`，不告诉任何人。

**这个 bug 的隐蔽性正好是"对齐偶然帮了 bug"的典型案例**。如果当初 `encrypted_static` 换成一个 13 字节 payload，crypto_vector_test 的 roundtrip 都能挂，第一分钟就发现了。

---

## 6. 修复

给 `poly1305_ctx` 加一个 16 字节部分块缓冲，把"部分块处理"从 `update` 彻底搬到 `finish`：

```c
typedef struct {
    uint32_t r[5], s[4], h[5];
    uint8_t  buf[16];      /* +++ */
    size_t   buflen;        /* +++ */
} poly1305_ctx;

static void poly1305_update(poly1305_ctx *ctx, const uint8_t *m, size_t len)
{
    // 1. 先把 ctx->buf 里的 tail 凑够 16 再消化
    if (ctx->buflen > 0) {
        size_t want = 16 - ctx->buflen;
        if (len < want) { memcpy(ctx->buf + ctx->buflen, m, len); ctx->buflen += len; return; }
        memcpy(ctx->buf + ctx->buflen, m, want);
        poly1305_block(ctx, ctx->buf, 1u << 24);  // 完整块：hibit=1
        m += want; len -= want; ctx->buflen = 0;
    }
    // 2. 跑满 16 字节块
    while (len >= 16) { poly1305_block(ctx, m, 1u << 24); m += 16; len -= 16; }
    // 3. 剩下 tail 存回缓冲，等下次 update 或 finish
    if (len > 0) { memcpy(ctx->buf, m, len); ctx->buflen = len; }
}

static void poly1305_finish(poly1305_ctx *ctx, uint8_t tag[16])
{
    // 只有 finish 才允许写 0x01 marker 并用 hibit=0 终结
    if (ctx->buflen > 0) {
        uint8_t last[16] = {0};
        memcpy(last, ctx->buf, ctx->buflen);
        last[ctx->buflen] = 1;
        poly1305_block(ctx, last, 0);
        ctx->buflen = 0;
    }
    // ...原有的 carry / modular reduction / add s...
}
```

核心心智模型：**"部分块"和"最终块"是两个概念**，不能混淆。任何流式 MAC/hash 实现都必须显式区分这两个阶段 —— `update` 只存 partial，只有 `finish` 才能 finalize。

---

## 7. 验证

```
$ ./build/crypto_vector_test
[PASS] blake2s("abc") vector
[PASS] chacha20-poly1305 RFC 8439 §2.8.2 KAT
[PASS] chacha20-poly1305 roundtrip + tamper
[PASS] xchacha20-poly1305 roundtrip + tamper

$ ./build/wg_core src/client.conf
[info] pkt sizes: initiation=148 response=92
[handshake] attempt 1
[handshake] success
[data] keepalive packet sent
```

Server 端 tcpdump：
```
devserver@latch:~$ sudo tcpdump -ni any udp port 51820
IP 172.16.203.1.63377 > 172.16.203.128.51820: UDP, length 148    ← initiation
IP 172.16.203.128.51820 > 172.16.203.1.63377: UDP, length 92     ← response
IP 172.16.203.1.63377 > 172.16.203.128.51820: UDP, length 32     ← keepalive data
```

`wg show wg0` 的 `latest handshake` 刷新到"just now"，`transfer` 开始有字节计数增长。

---

## 8. 调试环境对整个工作节奏的影响总结

这一次调试暴露的几件事：

### A. 静默丢包是最贵的 bug 类型
任何"对端不报错"的场景都意味着你失去了最重要的调试信号源。WireGuard 的 anti-DoS 设计让它天然如此。**反制手段**：在 server 端提前准备好 tcpdump，并且 dump 要跑在**握手发送之前**，否则 retry 的噪声会淹没第一次失败。

Linux 端如果有 root，可以 `sudo dmesg -w` 看 kernel wg 的 debug（需要 `modprobe wireguard` + `echo 'module wireguard +p' > /sys/kernel/debug/dynamic_debug/control`）。这是真正能看到"为什么 drop"的方式。

### B. 测试工具本身要被验证
`crypto_vector_test` 给出 `[PASS]` 让我浪费了 40 分钟 —— 因为我**没意识到 roundtrip 和 KAT 是两个完全不同的保证**：
- Roundtrip：我能解开我自己加密的 → "自洽性"
- KAT：我的密文和 RFC 钉死的值一致 → "正确性"

自洽 ≠ 正确。**自写 crypto 必须第一行代码就配 RFC KAT**，不是补测试。测试工具给出假阳性是一种"污染测量"，污染的测量会让你在错误方向上高效奔跑。

### C. 偶然对齐会隐藏 bug
Poly1305 bug 在 `encrypted_static` 路径上被 16 倍数对齐偶然掩盖。这种"特定 payload 长度才触发"的 bug，roundtrip 测试用了 128 字节 plaintext、`test_xchacha` 用了 111 字节 —— 111 不是 16 倍数，按理应该挂！

为什么还是没挂？因为 `roundtrip` 里 encrypt 和 decrypt **用的是同一个 buggy update**，`decrypt` 内部也会犯对称的错，两个错凑出一致的结果。所以 roundtrip 对 poly1305 实现 bug 是**结构性不敏感**的。

**启示**：写测试时要问"这个测试真的能 fail 吗？如果我把实现改成 `return 0`，它能发现吗？"

### D. 奥卡姆剃刀：怀疑自己写的，不怀疑原版
FreeBSD `wg_noise.c` 是跑在几十万台机器上的代码，我用 stub 只是改了头文件路径和少数宏。**先怀疑新代码，再怀疑老代码**。这次省了不少时间在"noise 状态机到底 HKDF 顺序对不对"这种死胡同上。

### E. 最小探针的价值
`wg_core.c` 是 600 行的最小 handshake 探针 —— 不碰 utun、不碰 allowedips、不碰定时器 —— 这个设计在调试时帮了大忙。如果当时已经在 `PacketTunnelProvider` 里跑完整数据面，这个 poly1305 bug 会被淹没在 TUN/UDP/NE framework 的噪声里。**能用纯 C 进程复现的问题就绝对不要放进 NE 沙盒**。

---

## 9. 按时间线看这次调试花了多少时间

| 阶段 | 耗时 | 价值 |
|---|---|---|
| 确认网络连通（nc/ping） | 1 min | 排除 80% 下水道 |
| hexdump initiation 包 | 10 min | 确认字节序/layout 正确 |
| 打印 noise_local_keys 核对 pubkey | 5 min | 排除 Curve25519 |
| **盯着 roundtrip `[PASS]` 怀疑 noise 状态机** | **40 min** | **0，假绿灯误导** |
| 写 RFC 8439 §2.8.2 KAT | 10 min | 立刻定位 |
| 读 poly1305_update 看出 bug | 3 min | — |
| 写缓冲逻辑 + finish 改造 | 10 min | — |
| 真机对拍 server 成功 | 2 min | — |

**70% 的时间浪费在假绿灯上**。如果开局第一步就写 KAT 而不是 roundtrip，这次调试会在 20 分钟内结束。

这是下一次开新 crypto 项目时要内化的事情：**KAT first, roundtrip never alone**。

---

---

## 10. Round 3 — 数据面静默丢包：另一个隐蔽 bug

修完 poly1305 + utun 数据面后，在真机跑 ping。情况：

- 路由 ✓ `route get 10.88.0.1 → utun7`
- TX ✓ utun_read 给到正确的 84 字节 ICMP echo，wg_encap 顺利发出 128 字节 UDP
- RX ❌ 一个回包都没有

跟上一轮的"静默丢包"完全一样的姿态，但这次问题是另一面。

### 第一阶段：排除 Mac 侧

第一直觉：connected UDP socket 静默过滤了 server 的回包（4-tuple 不匹配）。改成 unconnected + recvfrom 暴露 source addr。重跑 —— 还是 0 rx。Mac 这边的 socket 上**确实没有任何 UDP 包到达**。

### 第二阶段：让 server 告诉我们

在 server 上 tcpdump 51820，结果像下面这样：

```
In  IP 172.16.203.1.61186 > .128.51820: UDP, length 148   ← handshake init
Out IP 172.16.203.128.51820 > .1.61186: UDP, length 92    ← handshake response
In  IP 172.16.203.1.61186 > .128.51820: UDP, length 48    ← keepalive
In  IP 172.16.203.1.61186 > .128.51820: UDP, length 128   ← ping #1
In  IP 172.16.203.1.61186 > .128.51820: UDP, length 128   ← ping #2
In  IP 172.16.203.1.61186 > .128.51820: UDP, length 128   ← ping #3
```

清楚得不能再清楚了：**我们的所有包都送到了 server，但 server 除了握手 response 之外什么都没回**。问题完全在 server 侧（或 server 解读我们的包失败）。

### 第三阶段：Linux server 是怎么 drop 的

让 user 在 server 上跑：
- `ip addr show wg0` —— 确认 wg0 有 10.88.0.1/24 ✓
- `wg show wg0 transfer` 前后对比 —— rx_bytes 在每次测试只涨 **148 字节**，恰好是一个 handshake initiation 的大小。**我们的 4 个 data 包（48 + 3×128 = 432 字节）一字节都没被计数。**
- `dmesg | grep wireguard`（开了 dyndbg）—— 只有握手事件，零个 data 包相关消息

`wg` 的 `rx_bytes` 是在成功解密后才更新的。计数器停在 148 = 数据包**根本没走到解密成功的那行代码**。但 dmesg 里也没有解密失败的报错。这意味着包在 wg 模块的更早阶段就被 drop 了。

Linux kernel wg 在那一段代码路径里如果 `noise_keypair_lookup(r_idx)` 找不到 keypair，会用 `kfree_skb_reason(skb, SKB_DROP_REASON_WIREGUARD_NO_KEYPAIR_FOUND)` 静默丢弃。**这个 drop reason 默认不打 dmesg。** 现代 Linux 的 drop 信息要靠 `bpftrace tracepoint:skb:kfree_skb` 或 `drop_monitor` 才能看到。

### 第四阶段：先排除 crypto

在跑 server 端调查的同时，并行加了一个 mbuf-vs-buffer KAT 测试 —— 把同一份 plaintext / key / nonce 同时跑过 `chacha20poly1305_encrypt`（buffer API，已对 RFC 8439 KAT）和 `chacha20poly1305_encrypt_mbuf`（mbuf API，走 `crypto_dispatch`），要求 byte-identical。扫了 0 / 13 / 16 / 32 / 48 / 96 / 112 / 113 这些长度（覆盖 keepalive 16 + ping 96 + 各种边界）—— **全部 PASS**。

也就是说我们生成的 data 包密文和 tag 都是 RFC 8439 标准输出，server 应该能解。但 server 显然找不到对应的 keypair。

### 第五阶段：dump 实际线缆字节，去 FreeBSD 参考代码对拍

加了一行 wg_encap 的"第一个 data 包完整 hexdump"，重跑：

```
[wire] first data packet: 48 bytes
  0000: 04 00 00 00 5c 93 44 53 00 00 00 00 00 00 00 00
  0010: 17 7e ec cd db ee f2 66 ea ea ab 30 53 05 37 d5
  0020: 14 61 b4 28 31 46 43 62 43 34 91 14 f8 ae 18 66
```

字段拆解：
- `04 00 00 00` = WG_PKT_DATA ✓
- `5c 93 44 53` = **r_idx —— 这个值就是 server 找不到的 key**
- `00 00 00 00 00 00 00 00` = nonce 0 ✓
- 16 字节密文 + 16 字节 tag ✓

按协议，data 包的 `r_idx` 应该是**接收方（server）的 local index**，server 用它在自己的索引哈希表里查 keypair。这个值是 server 在握手 response 里以 `s_idx` 字段送给我们的，我们应该原样存下来供数据包使用。

去 FreeBSD `if_wg.c` 找参考实现，第 1448 行：

```c
if (noise_consume_response(sc->sc_local, &remote,
    resp->s_idx, resp->r_idx, resp->ue, resp->en) != 0) {
```

参数 3 是 `resp->s_idx`（response 包里 server 写入的 s_idx —— server 的 local index）。

回头看我自己的 `wait_for_response`：

```c
ret = noise_consume_response(local, &matched,
                             s_idx,        // ❌ 我们自己 initiation 的 s_idx
                             pkt.r_idx, pkt.ue, pkt.en);
```

参数 3 错了。我传的是**我们自己**的 sender index 而不是 server 的。

### bug 的实际后果

`noise_consume_response` 把第 3 参数当作"对端的 sender index"存进 `r->r_index.i_remote_index`。然后 `noise_begin_session` 拿这个值复制进 `kp->kp_index.i_remote_index`。然后每次 encrypt data 时：

```c
*r_idx = kp->kp_index.i_remote_index;   // 输出我们自己的 index
```

我们就把"我们自己的 sender index"塞进 data 包的 r_idx 字段。server 在自己的索引哈希里查我们的 index —— 当然查不到 —— 直接 drop with `NO_KEYPAIR_FOUND`。

### 为什么握手没暴露这个 bug

`noise_consume_response` 内部用第 4 参数 `pkt.r_idx`（这个是对的，是 server 回给我们的"我们自己的 index"）来查找 noise_remote。这一步不需要第 3 参数，所以握手认证全程通过。**只有数据包加密时引用 `kp_index.i_remote_index` 才会引爆这个 bug**。这是经典的"路径覆盖陷阱"——握手路径和数据路径走的是不同字段，bug 藏在两者交界处。

### 修复

```c
- ret = noise_consume_response(local, &matched, s_idx, pkt.r_idx, ...);
+ if (pkt.r_idx != expected_local_idx)   /* sanity: server echoed our index */
+     return -1;
+ ret = noise_consume_response(local, &matched, pkt.s_idx, pkt.r_idx, ...);
```

加了一行 sanity check，因为 `noise_consume_response` 的两个 `*_idx` 参数语义不对称（一个是远端的，一个是本端的，但名字都叫 `_idx`），将来很容易再写错。

### 验证

```
$ sudo WG_TRACE=40 ./build/wg_core --tunnel src/client.conf
...
[handshake] success
[tunnel] entering event loop
[tx#1] utun_read 84 B, inner IP ver=4
[rx#1] recvfrom 172.16.203.128:51820 len=128
[rx#1] decap OK: 84 inner bytes, ver=4
[tx#2] ...
[rx#2] decap OK ...
[tx#3] ...
[rx#3] decap OK ...

$ ping -c 5 10.88.0.1
PING 10.88.0.1 (10.88.0.1): 56 data bytes
64 bytes from 10.88.0.1: icmp_seq=0 ttl=64 time=1.890 ms
64 bytes from 10.88.0.1: icmp_seq=1 ttl=64 time=10.979 ms
64 bytes from 10.88.0.1: icmp_seq=2 ttl=64 time=11.568 ms

3 packets transmitted, 3 packets received, 0.0% packet loss
```

**端到端通了。** 1.9 ms RTT，0% 丢包。`tx=3 pkts/252 B  rx=3 pkts/252 B` 完全对账。

### Round 3 教训

**1. 现代 Linux 的 silent drop 不再走 dmesg。** SKB_DROP_REASON_* 是全新的 framework，dmesg 永远看不到，要靠 `bpftrace tracepoint:skb:kfree_skb` 或 `drop_monitor` 或 `perf trace`。下次 Linux server 静默丢包，第一反应应该是 `sudo bpftrace -e 'tracepoint:skb:kfree_skb { printf("%s\n", kstack) }'`，而不是 `dmesg | grep`。

**2. 计数器是真相，dmesg 是噪音。** 这次给关键定位的不是 dmesg，是 `wg show transfer` 的 `rx_bytes` 增量。**148 = exactly handshake init size** 这个观察直接告诉我"包到了 wg 模块但没走到 decrypt 成功那一行"，缩小范围比 dmesg 一万行 grep 都快。任何子系统在调试时第一件事是问"它有没有计数器？计数器涨了多少？"

**3. 握手通了 ≠ 数据面通。** Round 2 那个 poly1305 bug 也是握手部分通过（encrypted_static 正好 16 字节对齐躲过 bug），让我以为 crypto 全 OK。这次的 r_idx bug 也是握手通过、数据面挂。**握手 path 和 data path 用的是不同的字段、不同的代码路径，互相不能背书对方的正确性。** 任何对协议的"握手成功就是好的"判断都是错的——必须 ping 通才算数。

**4. 参数语义不对称的 API 是雷。** `noise_consume_response(local, rp, s_idx, r_idx, ue, en)` 的 `s_idx` 和 `r_idx` 看起来对称，实际上一个是 responder 的，一个是 initiator 的。这种对称外表下的语义不对称是经典的 footgun，作者写的时候觉得"r/s = remote/sender = 对端/本端"，但读的人很容易当成"我的 s_idx + 对方的 r_idx"。**写代码 review 这种 API 的时候，第一件事是看 callee 内部怎么用这两个参数，不能信参数名。**

**5. wire dump 应该比 KAT 早做。** 我花了 30 分钟写 mbuf-vs-buffer KAT 来排除 crypto，这是对的（结构性回归保护，留下来很值），但**应该更早 hex-dump 第一个 data 包**。如果先 dump 了，立刻看到 r_idx 字段，对照 FreeBSD 参考一秒钟就发现 bug。"先看实际的字节、再写抽象的测试"是这次的反思。

### Round 3 时间表

| 阶段 | 耗时 | 价值 |
|---|---|---|
| 第一直觉：connected UDP filtering | 5 min + 写 unconnected 改造 ~15 min | 0（包根本就到 socket 之前丢的） |
| Server tcpdump 确认 In/Out 不平衡 | 2 min | 100%，确定问题在 server 侧 |
| 让 user 跑 wg show / dmesg / sysctl | 5 min | 50%（rx_bytes = 148 是关键，dmesg 没用） |
| 写 mbuf-vs-buffer KAT 8 个长度 | 25 min | 30%（排除了一大类 bug，但当时我已经知道这个方向不对） |
| 加 wire dump + 对照 FreeBSD 参考 | 5 min | **100% bug 命中** |
| 修复 + 重测 | 3 min | — |

**约 65 分钟。** 一旦让出手让 wire bytes 说话，后面就是一秒钟的事。下次类似情况：tcpdump 出来比 KAT 出来更先去看。

---

## 11. 当前状态（M3 完成）

| 层 | 状态 |
|---|---|
| Crypto KAT (blake2s + curve25519 + chacha20-poly1305 buffer + mbuf) | ✅ |
| Handshake (initiator role) | ✅ |
| Data plane encap (wg_encap) | ✅ |
| Data plane decap (wg_decap) | ✅ |
| utun integration + routing | ✅ |
| ping 端到端 (短) | ✅ **3/3 0% loss** |
| Handshake retransmit timer | ✅ M3.1 |
| Rekey timer (REKEY_AFTER_TIME = 120s) | ✅ M3.2 |
| Persistent-keepalive | ✅ M3.3 |
| ping 端到端 (跨 rekey) | ✅ **200/200 0% loss over 200s** |
| Roaming endpoint update | ✅ |
| Allowedips (multi-peer) | ❌ |
| UAPI (`wg show` / `setconf`) | ❌ |

**会话现在可以无限期跑下去**。M3 的三个 timer 一上线，跨过 120s rekey 边界、跨过 180s reject_after 边界都能保持 0% 丢包。

### M3 验收数据

```
$ ping -c 200 -i 1 10.88.0.1
... 200 packets ...
200 packets transmitted, 200 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 0.635/2.800/7.387/1.210 ms
```

200 秒持续 ping 跨过：
- 第 25s 之后任何 idle 缺口会触发 persistent-keepalive（client.conf 配 25s）
- 第 120s 触发 proactive rekey（in-band，使用 select 循环里的 WG_PKT_RESPONSE 处理）
- 第 180s 是旧 keypair 的 REJECT_AFTER_TIME；如果 rekey 没成，从这一刻起所有 ping 都会超时

实际：**0% loss across the entire 200 seconds**，证明 rekey 在第 120s 完整 handover 成功。RTT min/avg/max = 0.635 / 2.800 / 7.387ms，跨 rekey 没有任何 spike，新 keypair 接管对 latency 是透明的。

---

## 12. 下一步

---

## 12. 下一步

- [x] Curve25519 RFC 7748 §6.1 KAT
- [x] mbuf-vs-buffer 全长度 KAT
- [x] L2 utun 挂接 + 数据面端到端
- [x] M3.1 Handshake retransmit timer (REKEY_TIMEOUT = 5s)
- [x] M3.2 Rekey timer (REKEY_AFTER_TIME = 120s) ← 验证 200s ping 0% loss
- [x] M3.3 Persistent-keepalive
- [ ] Blake2s 长消息 KAT
- [ ] M2 Allowedips trie（多 peer 支持）
- [ ] UAPI (`wg show` / `wg setconf`)
- [ ] Responder role（让别人能连进来，不只是出去）
- [ ] IPv6 inner（utun 的 IPv6 + 解析 inner ipv6 头）

三轮调试的累计教训：

1. **静默丢包是这个项目的常态。** WireGuard 的 anti-DoS 设计 + Linux 的 SKB_DROP_REASON framework 一起，让 silent drop 成了所有 bug 的默认表现。每次"没有错误也没有结果"的时候，第一反应必须是"找到一个能告诉我对错的真相源" —— RFC KAT、`wg show transfer` 计数器、tcpdump、bpftrace —— 而不是猜代码。

2. **测试基础设施先于实现。** Round 2 的假绿灯 roundtrip 浪费 40 分钟。Round 3 的 mbuf KAT 本来该是 Round 2 一起做的，因为它能立刻把 crypto 排除。每次写新代码之前先问"这段代码出错时谁能告诉我？"

3. **握手通了 ≠ 数据面通了。** Round 2 和 Round 3 都是 "握手成功 → 数据包失败" 的两个不同 bug。这两条 path 是分离的，互不背书。**任何对协议正确性的判断必须 ping 通才算数。**

4. **看实际的字节，比写抽象的测试快。** Round 3 那个 `wire dump` 一加上去，对照 FreeBSD 参考代码 30 秒就找到 bug。**以后调试 wire protocol 的第一动作是 hex dump，而不是写测试。**

5. **API 参数语义不对称要警惕。** `noise_consume_response(s_idx, r_idx)` 看起来对称但不是 —— 一个属于 responder，一个属于 initiator。这种 footgun 必须在调用点加 sanity check（我留了一行 `if pkt.r_idx != expected_local_idx`）才安全。
