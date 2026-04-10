# 下一步工作计划

**总目标**：从「握手成功」跨到「能 ping 通」—— 真正的数据面。

**验收标准**：
```bash
$ sudo ./build/wg_core src/client.conf
$ ping -c 10 10.88.0.1          # Linux server 的 tunnel IP
10 packets transmitted, 10 received, 0% loss
```

---

## 里程碑

### M4 — 测试基础设施先行（最优先）

上一轮调试的最大教训：**静默丢包场景下，测试基础设施先于实现**。在 M1 动任何数据面代码之前先把 KAT 补齐。

- **M4.1** Curve25519 RFC 7748 §6.1 KAT（排除 Swift CryptoKit bridge 的信任假设）
- **M4.2** Blake2s 长消息 KAT（不只 `"abc"`）
- **M4.3** `crypto_vector_test` 纳入 Makefile，`make test` 目标
- **M4.4** encap → decap loopback 单元测试（纯进程内，不走网络）

### M1 — utun 数据面贯通

这一步是整个工作量的 70%。把 `wg_core.c` 从一次性握手探针升级为常驻 VPN 进程。

- **M1.1** 抽出 `wg_encap()` 辅助函数（从现有 `send_keepalive_data` 拆）
- **M1.2** 新写 `wg_decap()` —— 整个移植树目前**没有任何接收 data 包并解密的代码**
- **M1.3** 打开 utun：`socket(PF_SYSTEM) → connect(utun_control) → getsockopt(UTUN_OPT_IFNAME)`
- **M1.4** 事件循环：`select()` 监听 `utun_fd` + `udp_fd`，双向转发
- **M1.5** shell helper：`ifconfig utunN inet 10.88.0.2/24` + `route add`
- **M1.6** 对真实 Linux server 跑 `ping` 验收

### M3 — 最小定时器集

utun 通了之后立刻做，否则 2 分钟后密钥失效。

- **M3.1** Handshake 重传定时器（`REKEY_TIMEOUT = 5s`）
- **M3.2** Rekey 定时器（`REKEY_AFTER_TIME = 120s`）
- **M3.3** Persistent-keepalive（配置时启用）

### M2 — Allowedips trie

单 peer 可以跳过。多 peer 场景才做。

- **M2.1** 移植或自写 IPv4/IPv6 最长前缀匹配 trie
- **M2.2** 出站选 peer + 入站 inner-IP 反 spoofing 校验

---

## 依赖关系

```
M4 ─► M1 ─┬─► M3
          │
          └─► M2 (可选，多 peer)
```

---

## 已知技术债 / 风险

1. `wg_crypto_impl.c::crypto_dispatch` 硬编码 AAD=0（仅 transport 用，不是通用）
2. `macos_stubs/sys/mbuf.h` 单段平坦 buffer，无 chain / `m_pullup`；不能直接搬 `if_wg.c` 的 mbuf 链式操作
3. macOS 无 `callout`，定时器要用 `dispatch_after` + generation counter 从头写
4. utun 需要 root 权限
5. `libswift_crypto.a` 构建在 macOS 26.0 但链接到 11.0 目标，warning（不影响运行）

---

## 当前开工顺序

1. **M4.1 Curve25519 KAT**（10 min，立刻消除一个信任假设）
2. **M1.2 `wg_decap()`**（新代码，阻塞 ping 的唯一必要模块）
3. **M1.3/1.4 utun + 事件循环**（把 wg_core 改成常驻进程）
4. **M1.6 ping 验收**（跑真机对拍）
5. **M3.1 handshake 重传**（避免启动窗口丢包）

M2、M4.2/4.3/4.4 留在 ping 通后补。
