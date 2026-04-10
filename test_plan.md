你说得对，我搞错了架构。macOS 上走用户态 + `utun` 字符设备（类似 wireguard-go 的方式），不是 kext。重新写。

# WireGuard macOS 用户态移植测试计划（utun 版）

## 一、架构确认

移植后的形态：用户态进程，通过 `/dev/utunN`（或 `connect(PF_SYSTEM, com.apple.net.utun_control)`）收发 L3 包，UDP socket 收发加密包，中间是从 FreeBSD 移植过来的 noise/cookie/crypto/allowedips 等 C 代码。

数据面两条路径：
- **出站**：`utun read` → allowedips 查 peer → noise 加密 → `sendto` UDP
- **入站**：`recvfrom` UDP → noise 解密 → allowedips 反查校验 → `utun write`

测试要围绕这个用户态进程展开，不涉及任何内核加载。

---

## 二、测试分层

### Layer 0：进程启停与 utun 创建
- 进程以 root 启动，成功 open utun，`ifconfig utun_N` 可见
- `SIGTERM` 后 utun 接口消失，无残留 fd
- 重复启停 100 次无句柄泄漏（`lsof -p`）
- 同时跑两个实例使用不同 utun 单元号

### Layer 1：纯 C 单元测试
把移植的 .c 文件链接成用户态测试可执行文件（不需要任何特权），用 RFC 向量验证：

| 文件 | 测试点 | 向量来源 |
|---|---|---|
| `crypto.c` | ChaCha20-Poly1305 / Curve25519 / BLAKE2s / HKDF | RFC 7539、RFC 7748、Linux kernel `selftest/` |
| `noise.c` | Noise_IK 状态机、密钥派生、rekey 计时器 | WireGuard 白皮书附录 + 抓包对拍 |
| `cookie.c` | MAC1/MAC2、cookie reply 加解密 | 自构造 + Linux 对拍 |
| `allowedips.c` | trie 插入/查找/删除、v4/v6、最长前缀 | 边界 + 随机 fuzz |
| `ratelimiter.c` | 令牌桶（注入假时钟） | 单元 mock |
| `timers.c` | 各计时器触发顺序 | 假时钟 |

关键：`noise.c` 和 `crypto.c` 必须能在不依赖 utun 的情况下独立编译运行，方便 CI 快速回归。

### Layer 2：本地回环数据面
不出物理网卡，验证收发路径打通：

- 单进程内 loopback：mock 一个 UDP socket pair，自己加密自己解密，`utun write` 后从同一 utun `read` 出明文
- 双进程同机：两个实例分别用 utun10/utun11，UDP 走 127.0.0.1 不同端口，互相 ping 对端 utun IP
- 校验包计数、字节数、握手计数与 `wg show` 等价输出一致

### Layer 3：与参考实现互通（最重要）
黄金参考是 **Linux 内核 wireguard** 和 **wireguard-go**。

拓扑：
```
[macOS 移植版]  <--UDP-->  [Linux wg (VM/远端)]
[macOS 移植版]  <--UDP-->  [wireguard-go on macOS]
[macOS 移植版]  <--UDP-->  [macOS 移植版]
```

每对组合跑：
1. 握手建立（`latest handshake` 时间戳更新）
2. ICMP v4/v6 ping
3. iperf3 TCP 60s
4. iperf3 UDP -b 1G，丢包率
5. MTU 扫描：1280 / 1380 / 1420 / 1500
6. 强制 rekey（>2 分钟空闲后再发包；或调试接口手动触发）
7. Roaming：客户端 NAT 后切换源端口，对端应自动更新 endpoint
8. persistent-keepalive 行为

### Layer 4：UAPI 兼容
WireGuard 的 cross-platform UAPI 是 unix socket（`/var/run/wireguard/<ifname>.sock`），文本协议。必须做到：

- `wg show` / `wg showconf` / `wg setconf` 全部能用
- `wg-quick up/down` 全流程（含路由、DNS、PostUp/PostDown）
- get/set 往返一致：`set` 一份配置后 `get` 出来字段完全一致
- 1 / 10 / 100 / 1000 个 peer 压力
- 非法输入（错长度 key、重复 allowed-ip、非法端口）被拒绝且不崩

### Layer 5：故障注入与协议鲁棒性
用 `dnctl` + `pfctl` 做 pipe：

- 丢包 1% / 5% / 20%
- 延迟 50ms / 200ms / 1s
- 乱序、重复
- MTU 黑洞（中间链路 1300）
- 损坏密文一个字节 → Poly1305 必须拒绝
- 重放历史包 → 滑动窗口必须拒绝
- 错误静态密钥握手 → 静默丢弃，不放大
- 畸形 handshake initiation（截断、超长、错 type）→ 不崩
- UDP flood 到监听端口 → ratelimiter 生效，CPU 不跑满

### Layer 6：稳定性 soak
- 24h iperf3 持续打流（TCP + UDP 并行）
- 每 10 秒 add/remove 一个 peer
- 每 30 秒切换 endpoint
- 监控：`footprint -p`、`leaks -atExit`、`sample`、fd 数、CPU%
- 通过线：内存增长 <5%、无 fd 泄漏、无崩溃

### Layer 7：性能基线
对比对象：同机 wireguard-go。

- 单流 TCP 吞吐
- 单流 UDP PPS
- 8 流并发吞吐
- CPU per Gbps
- 握手延迟（首包到能转发）

目标：达到 wireguard-go 的 80% 以上；crypto 单测速度持平或更快（因为是 C）。

---

## 三、自动化框架

### 目录
```
wg-macos-test/
├── unit/                 # Layer 1，纯用户态，无需 root
│   ├── test_crypto.c
│   ├── test_noise.c
│   ├── test_allowedips.c
│   ├── test_cookie.c
│   └── Makefile
├── loopback/             # Layer 2
│   └── test_selfloop.sh
├── interop/              # Layer 3
│   ├── peer_linux.sh     # 在 Linux 端配置
│   ├── peer_go.sh        # 启动 wireguard-go
│   ├── test_handshake.sh
│   ├── test_iperf.sh
│   ├── test_mtu.sh
│   ├── test_rekey.sh
│   └── test_roaming.sh
├── uapi/                 # Layer 4
│   ├── test_setconf_roundtrip.sh
│   ├── test_wgquick.sh
│   └── test_many_peers.sh
├── fault/                # Layer 5
│   ├── pf_pipe.sh
│   ├── replay.py
│   ├── corrupt.py
│   └── fuzz_handshake.py
├── soak/                 # Layer 6
│   └── soak_24h.sh
├── perf/                 # Layer 7
│   └── bench.sh
├── vectors/              # RFC + 抓包
├── ci/
│   ├── run_fast.sh       # L0-L2 + L4，PR 触发，<10 分钟
│   ├── run_full.sh       # 全量，nightly
│   └── to_junit.py
└── README.md
```

### 总入口示意
```bash
#!/usr/bin/env bash
set -euo pipefail
RESULTS=results/$(date +%Y%m%d-%H%M%S)
mkdir -p "$RESULTS"

./build.sh                       # 编译移植版 wg + 单测 harness

run() { name=$1; shift; echo "== $name =="; \
        if "$@" > "$RESULTS/$name.log" 2>&1; \
          then echo "PASS $name" >> "$RESULTS/summary"; \
          else echo "FAIL $name" >> "$RESULTS/summary"; fi; }

# L1 不需要 root
run unit_crypto      ./unit/test_crypto
run unit_noise       ./unit/test_noise
run unit_allowedips  ./unit/test_allowedips
run unit_cookie      ./unit/test_cookie

# L0/L2+ 需要 sudo
sudo -E ./loopback/test_selfloop.sh
sudo -E ./interop/test_handshake.sh
sudo -E ./interop/test_iperf.sh
sudo -E ./interop/test_mtu.sh
sudo -E ./interop/test_rekey.sh
sudo -E ./interop/test_roaming.sh
sudo -E ./uapi/test_setconf_roundtrip.sh
sudo -E ./uapi/test_wgquick.sh
sudo -E ./fault/pf_pipe.sh
sudo -E python3 ./fault/replay.py
sudo -E python3 ./fault/corrupt.py
sudo -E python3 ./fault/fuzz_handshake.py

./ci/to_junit.py "$RESULTS" > "$RESULTS/junit.xml"
```

### 互通对端怎么搞
最省事的方式：UTM 跑一个 Debian VM，host-only 网络直连，VM 里用官方 wg。脚本通过 ssh 控制 VM 端 `wg set` 和 `ip` 命令，整个测试在 macOS 一侧 `make test` 一键跑完。

---

## 四、通过标准

| 层 | 标准 |
|---|---|
| L0 | 100 次启停无泄漏、无残留 utun |
| L1 | 全部 RFC 向量通过；fuzz 1 小时无崩溃 |
| L2 | 自环 ping/iperf 通；包计数一致 |
| L3 | 与 Linux/wg-go 三向互通全绿 |
| L4 | UAPI 与官方 `wg(8)` 完全兼容；1000 peer OK |
| L5 | 所有恶意/异常输入被正确处理 |
| L6 | 24h soak 内存增长 <5%，无崩溃，无 fd 泄漏 |
| L7 | 吞吐 ≥ wireguard-go 80% |

---

## 五、两周排期

- **D1**：Layer 0 + 构建脚本 + utun 启停冒烟
- **D2–3**：Layer 1 单元测试（crypto/noise/allowedips/cookie）
- **D4**：Layer 2 自环
- **D5–6**：Layer 3 与 Linux 互通（握手、ping、iperf、MTU）
- **D7**：Layer 3 rekey + roaming
- **D8**：Layer 4 UAPI 与 wg-quick
- **D9–10**：Layer 5 故障注入与 fuzz
- **D11**：Layer 7 perf 基线
- **D12**：启动 Layer 6 24h soak
- **D13**：CI 脚本化、JUnit 输出、README
- **D14**：回归 + 缺陷修复

---

要我先帮你写哪一块的实际代码？建议从这三个里挑一个起步：

1. `unit/test_crypto.c` —— 最快建立信心，纯 C 不依赖 utun
2. `loopback/test_selfloop.sh` + 一个最小 utun 收发 demo —— 验证你的 utun 集成
3. `interop/test_handshake.sh` —— 直接对 Linux 拉互通，最能暴露移植问题
