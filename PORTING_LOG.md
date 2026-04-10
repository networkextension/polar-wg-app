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

## 10. 下一步

- [ ] 把 Curve25519 RFC 7748 §6.1 向量加进 `crypto_vector_test.c`
- [ ] 把 Blake2s 多消息长度 KAT 加进去
- [ ] 把 `wg_core` 的调试 hexdump 改成 `-v` flag 控制，默认静默
- [ ] L2 utun 挂接 + allowedips trie 移植 —— 真正进入数据面
- [ ] 定时器：`callout` → `dispatch_after` + generation counter 取消机制

这次调试最大的产出不是那 3 行 poly1305 修复，而是**把 KAT 基础设施建立起来**。后面再写任何 crypto 相关代码，第一步就是往 `crypto_vector_test.c` 加向量 —— 这条规矩现在已经刻进墙上了。
