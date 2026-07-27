# wg-agent：Swift-only 多平台重构设计

状态：设计稿 / 待评审
日期：2026-07-26
取代：`scripts/wgctl-agent.sh`(darwin)、`skills/wg-mac-install/scripts/wg-agent.sh`(linux/bsd)、`scripts/join-linux.sh` 内嵌的 `wgctl-hb-linux` / `wgctl-refresh-linux`

---

## 1. 目标与约束

**目标**：设备侧 reconciler 只用 Swift 实现，一套代码覆盖 macOS / iOS / Linux / FreeBSD，消除对 `sh` + `python3` 的运行时依赖。

**硬约束**：

- 语言只用 Swift。系统库（libcurl）可以通过 C interop 绑定，但不允许 shell / python / go。
- 目标机上不能要求装 python3。当前三个 shell agent 每次心跳都要 fork 一次 python3 来拼 JSON —— 这是最大的部署包袱（jailbroken iOS、musl 小机器上 python3 都是负担）。
- 必须保留现网行为，见 §6。fleet 是活的，不能靠"重写一遍差不多"过渡。

**明确的非目标**：把 `wg_core`/`wgctl`（C 数据面）也改写成 Swift。

> **2026-07-27 更新**：Windows 原本列在非目标里，现已**改为目标**（语言选型已定为
> Swift，与 POSIX 侧统一）。数据面不自己做——复用官方 wireguard-windows。详见
> `polar-wg/doc/wg-mac-windows-client-design.md`，本文 §3 的平台矩阵已同步。

---

## 2. 现状核对（先纠正一个流传的说法）

**"Swift agent 在 dpaa2 上崩了所以被 revert 了" —— 源码层面不成立。**

`git log --all` 里没有任何 revert 提交，`wg-agent.swift` 从未被删除，它现在就在 `origin/main` 上，540 行，功能完整。真实情况是：**它从来没有被任何 installer 装过**。`scripts/install.sh` 装 `wgctl-agent.sh`，`join.sh` 装 `wg-agent.sh`，没有一个脚本、plist、systemd unit 引用过 Swift 二进制。所谓"退回"是运维层面的（机器上跑的是 sh），不是代码层面的。

它已经踩平的三个坑，是这次重构最有价值的资产，全部必须继承：

| 提交 | 症状 | 结论 |
|---|---|---|
| `3205310` | CP 不可达 → 每次 cron tick 的 agent 都卡死不退出 → dpaa2 上 98 个僵尸进程、load 114 | `URLSession.shared` 在 corelibs 上会让进程**无法正常退出**，main 返回不够，必须显式 `exit()`。而教科书写法（ephemeral session + `invalidateAndCancel`）在 FreeBSD 上直接 SIGABRT in `_MultiHandle` |
| `0b0d66f` | 同样场景下 URLSession 事件循环 **busy-spin 到 ~200% CPU**，把 dpaa2 的 sshd 饿死 | FoundationNetworking 对超时敏感的客户端不可用。**并且：watchdog 线程在 CPU 打满时自己也会错过 deadline** |
| `3a94ddd` | 换成 curl 子进程后还剩 ~100% spin | 真凶是 `Foundation.Process` 的 `Pipe`/dispatch I/O 在 FreeBSD 上 busy-poll。改 `posix_spawn`+`waitpid` 后 0% CPU。附带修好了 `wg-quick` 的管道悬挂（读到 EOF 会等 wg-quick 后台的 route-monitor 子进程，`waitpid` 只等直接子进程）。另：`posix_spawn_file_actions_t` 在 Linux↔FreeBSD 类型不同，所以用 dup2 父进程 fd 的土办法 |

**沉淀成一条平台黑名单**：非 Darwin 上禁用 `URLSession`/FoundationNetworking、`Foundation.Process`+`Pipe`、`posix_spawn_file_actions_t`、`ProcessInfo.executableURL`（FreeBSD 返回 nil）。可用的只有裸 POSIX + `Codable`/`JSONSerialization` + `FileManager`。

---

## 3. 平台矩阵与裁决

工具链现状（2026-07 核实，Swift 6.3.3 为当前发布版）：

| 平台 | 工具链 | 裁决 | 说明 |
|---|---|---|---|
| macOS arm64 + x86_64 | 官方 Tier 1 | **做** | universal Mach-O，Swift runtime 随 OS |
| iOS arm64（越狱/内部机，root LaunchDaemon） | 官方（deployment-only） | **做** | 见 §7 的两个坑：SwiftPM 不能 target iOS；root 进程 `DYLD_*` 被剥离，必须链系统 runtime |
| Linux glibc amd64/arm64 | 官方 Tier 1 | **做** | 但不单独出包，直接发 musl 静态件 |
| Linux musl 静态 amd64/arm64 | 官方 Static Linux SDK | **做** | 单文件零依赖，SDK 自带 curl/boringssl |
| FreeBSD amd64 | 官方**预览**（nightly tarball，非发布通道） | **做，但 tier-2** | `--static-swift-stdlib` 在预览版里无效 |
| FreeBSD arm64 | **无官方工具链**，唯一实现是 `networkextension/swift-freebsd`（本项目自有） | **做，但 tier-2 且限期观察** | 见下 |
| Android arm64 | Swift 6.3 起官方 | 暂缓 | 语言侧没问题，卡在 SELinux/init 集成，与本设计无关 |
| Windows amd64 | 官方（dev + deploy，2026-01 成立 Windows Workgroup） | **做** ← 2026-07-27 改判 | 数据面复用官方 wireguard-windows，我们只写 agent。见下 |

### Windows 的改判（2026-07-27）

原判"不做"，理由写的是"整个 daemon 模型（wg-quick、unix signal、posix spawn）不存在"。
这条理由**看错了对象**：那些是 POSIX *数据面 + 生命周期* 的设施，而 Windows 上这两层
本来就该复用官方 wireguard-windows（WireGuardNT 内核驱动 + 每隧道一个 Windows 服务 +
托盘 UI），不该由我们提供。我们要写的只有 agent —— 而 agent 需要的东西 Windows 全都有。

另一条曾用来反对 Swift 的论据是"Windows 目标无法从 macOS 交叉编译"。**该论据已撤回**：
构建主机是可获取的资源，不是架构约束。

改判后的关键事实：**标准 `wg(8)` 工具在 Windows 上可用**，所以 Windows 与 Linux 走
同一条控制路径（`wg show <iface> dump` 读状态、`wg set … endpoint` 换端点），只有
"路由变了要重启"从 `wg-quick down/up` 换成 `sc stop/start WireGuardTunnel$<name>`。

移植面因此很小：`WGAgentCore` 零平台 API，原样编译；`WGPlatform` 六个文件里四个需要
Windows 实现（`Resolver` 几乎白送——`getaddrinfo` 同名存在于 ws2_32；`ProcessRunner`
换 `CreateProcessW`；`HostFacts` 换 `GetAdaptersAddresses`；`Runtime` 的看门狗要重想，
因为 Windows 没有 SIGALRM，而 §4.5 选 `alarm(2)` 正是因为睡眠线程在 CPU 打满时会
错过自己的 deadline）。

**唯一未确定的是 HTTP 栈**：FoundationNetworking/URLSession 在 Windows 上的当前状态
查不到权威结论，不猜测；备选是 libcurl via vcpkg（与 musl 分支共用 `CCurl` target）
或 WinHTTP。有构建主机后一小时内可证伪。完整设计见
`polar-wg/doc/wg-mac-windows-client-design.md`。

### FreeBSD 这个决定值得单独说

调研的默认结论是"FreeBSD arm64 上 Swift-only 不现实，应该继续用 shell 或改写成 C"，理由是没有官方工具链、你得自己维护编译器。**但这个理由对本项目不成立，因为编译器本来就是你维护的**——`networkextension/swift-freebsd` 就是这个仓库的组织。

更关键的一条：2026 年 6 月在该工具链里定位并修复了一个 **`Synchronization.Mutex` 运行时死锁**（"线程 park 之后永远醒不过来，整个 runtime 挂住"）。这**极可能就是当初 dpaa2 上 Swift agent 崩溃的真正原因**，而它已经修了。也就是说"Swift 在 FreeBSD 上不稳"这个判断的证据基础已经变了。

所以裁决是**做，但降级为 tier-2**，并且明确代价：

- FreeBSD 目标的稳定性等于自有工具链的稳定性，出了 runtime 级别的 hang，责任在自己这边，没有上游可依赖。
- 因此 FreeBSD 上 **shell agent 保留为 fallback，不删**，直到 Swift 版在 dpaa2 上连续无事故运行满一个观察期（建议 30 天）。
- 这条也是为什么 §4 的架构要把并发压到最浅：runtime 级 bug 的爆炸半径要小。

---

## 4. 架构

分三层，核心层不碰任何 I/O，因此在所有平台上都能跑同一份测试。

```
Sources/
  WGAgentCore/          纯逻辑，零 I/O，零平台分支 —— 可在 macOS 上完整单测
    Model/              Codable：DeviceState / PeersResponse / HeartbeatBody / Policy
    ConfRender.swift    wg conf 渲染 + 语义比较
    LongPoll.swift      probe→trial→longpoll 状态机（注入 Clock + Transport）
    Reconcile.swift     决策：不动 / syncconf / 全量 reload / self-evict
    Facts.swift         把平台采集到的原始事实组装成 heartbeat body
  WGPlatform/           协议 + 纯 POSIX 实现（全平台共用）
    ProcessRunner.swift posix_spawn + waitpid
    HTTPTransport.swift libcurl 绑定
    NetFacts.swift      getifaddrs / uname / uptime
    FileLock.swift      flock 单实例
    Watchdog.swift      硬看门狗
  WGPlatformDarwin/     launchctl、PF_ROUTE 路由收敛、wg_core unix socket
  WGPlatformLinux/      wg-quick / wg syncconf、iptables、/proc
  WGPlatformFreeBSD/    pf.conf、sysrc
  CCurl/                systemLibrary target
  wg-agent/             main：组装 + 逐 iface 驱动
```

### 4.1 PlatformShim：四个协议

```swift
protocol ProcessRunner  { func run(_ path: String, _ args: [String]) throws -> (code: Int32, out: String) }
protocol HTTPTransport  { func request(_ req: HTTPRequest) throws -> HTTPResponse }
protocol HostFacts      { func interfaces() -> [LanAddr]; func uptimeSec() -> Int?; func osArch() -> (String, String) }
protocol TunnelControl  { func reload(iface: String, routesChanged: Bool) throws; func teardown(iface: String) throws }
```

只有 `TunnelControl` 和 `HostFacts` 有平台分支；`ProcessRunner`/`HTTPTransport` 各只有两个实现（Darwin / 其它）。

### 4.2 HTTP：Darwin 用 URLSession，其余绑定 libcurl（不是 spawn curl）

```
Darwin (macOS + iOS)  → URLSession        （Apple 自家实现，与 corelibs 是两套代码，可靠）
其它全部              → libcurl via C interop（curl_easy_*）
```

这是对 `0b0d66f` 的**改进而非推翻**：当时的结论"别用 URLSession，用 curl"是对的，但用的是 spawn `curl(1)` 二进制。现在改成进程内绑定 libcurl，三个好处：热路径上少一次 fork/exec、"不依赖 shell 工具"这句话变成真的、超时/CA 由 `CURLOPT_*` 显式控制而不是靠命令行参数。musl Static SDK 自带 curl，静态链接不额外付出。

**明令禁止**：任何平台上 `import FoundationNetworking`。musl 静态下 URLSession 是彻底坏的（corelibs-foundation #5092 仍 open，#5157 无 CA bundle）。

**各 SDK 的 libcurl 实际情况（2026-07-26 逐个核过，不是推测）**：

| 目标 | curl 头文件 | libcurl | systemLibrary 可行？ |
|---|---|---|---|
| musl 静态 aarch64/x86_64 | ✅ 12 个头，在 sysroot 内 | ✅ `libcurl.a` 9.0MB，8.15.0-DEV | ✅ `<curl/curl.h>` 直接可解析，无需额外 `-I` |
| macOS | ✅ 11 个头 | `libcurl.4.tbd`（动态） | ✅ 但按计划走 URLSession |
| iOS | ❌ 无 | ❌ 无 | ❌ 不可能——URLSession 是唯一选择 |
| **Android** | ❌ **整个 artifactbundle 里一个 curl 头都没有** | ✅ `libcurl.a` 11.3MB，8.7.0-DEV | ❌ **as-shipped 不可行** |
| FreeBSD | 本机无从核实 | — | 待自有工具链上验证 |

**Android 这条会骗人**：`libcurl.a` 在，`find` 一搜像是没问题，但那份 libcurl 只是 `libFoundationNetworking.a` 的链接期依赖，没有任何公开头文件。要做就得自己 vendor 一套 8.7.x 的头（不能拿 musl SDK 的 8.15 头去凑，版本对不上）。Android 本来就是"暂缓"，这条记下来避免将来踩。

另外两个实现约束：静态 SDK 的 `toolset.json` 强制 `-static-executable -static-stdlib`，所以链的必须是静态归档（`libcurl.a` 正好）；`.pc` 文件里的 `prefix` 是构建农场的绝对路径（`/home/build-user/...`），**`pkgConfig:` 完全不可用**，必须靠 sysroot 解析，并手写 `-DCURL_STATICLIB` 和 `-lcurl -lssl -lcrypto -lz`。

### 4.3 子进程：保留 posix_spawn shim

`swift-subprocess` 仍是 0.4.0 pre-1.0，且 Static Linux SDK 只是 "build only — not tested"。当前仓库里那份 `posix_spawn` + 阻塞 `waitpid` + dup2 捕获输出的实现已经在 dpaa2 上验证过 0% CPU，直接搬过来，别换。等 subprocess 1.0 且静态 SDK 有 CI 覆盖再评估。

### 4.4 并发：刻意保持极浅

- 单 task、顺序 `await`，**不用 TaskGroup、不用自定义 executor、不用 Dispatch**。
- 定时用 stdlib `ContinuousClock` / `Task.sleep`，不用 `DispatchSourceTimer`（libdispatch 恰好是 FreeBSD 上最弱的一层）。
- 阻塞调用（`waitpid`、`curl_easy_perform`）绝不放在协作线程池上。对一个 60 秒 reconciler 来说，本来就该是单线程顺序执行的。

理由已在 §3 说过：FreeBSD 的并发正确性靠自有补丁，把并发面积压到最小，就是把风险压到最小。

### 4.5 保留硬看门狗

flock 单实例 + 独立线程 50 秒强制 `exit(2)`，**所有平台都要**（macOS 也要，虽然 launchd 不会重叠——便宜的保险）。但要记住 `0b0d66f` 的教训：**CPU 打满时 watchdog 自己也可能错过 deadline**，所以它是最后一道防线，不是第一道。第一道是 §4.2/§4.3 里那些不会 spin 的选型。

---

## 5. 用 syscall 替掉 shell-out

现在每次心跳要 fork 出 `ifconfig`/`ip`/`route`/`uname`/`sysctl` 再加一个 python3。Swift 里绝大部分可以直接系统调用：

| 事实 | 现在 | 改成 |
|---|---|---|
| `lan_addrs` | `ifconfig` / `ip -o -4 addr` + 正则（含十六进制掩码转前缀位数） | `getifaddrs(3)` |
| `os` / `arch` | `uname -s` / `uname -m` + 映射 | `uname(2)` |
| `uptime_sec` | `/proc/uptime` 或 `sysctl -n kern.boottime` + sed | 直接读文件 / `sysctlbyname` |
| 默认路由出口网卡 | `ip route get 1.1.1.1` + sed | `PF_ROUTE` socket（Darwin/BSD）/ 读 `/proc/net/route`（Linux） |
| JSON 拼装 | fork python3 | `Codable` |
| 公网出口 IP | curl 外部 echo 服务 | 同左（本质需要外部观测，保留，见 §6.3） |

**必须保留的 shell-out**（这些是 wg 工具链本身，不是脚本）：`wg show <iface> dump`、`wg-quick up/down`、`wg syncconf`、`iptables`、`pfctl`/`sysrc`、`launchctl`。它们通过 `ProcessRunner` 走，仍然是 posix_spawn 直接 exec 二进制，不经 shell。

macOS 上的 peer 状态有更好的路子：`wgctl show` 只是把 `/var/run/wireguard/<iface>.sock` 的内容原样打出来（见 `src/wgctl.c` `dump_one()`），Swift 可以直接 connect 这个 unix socket。建议顺手给 `wg_core` 加一个 JSON dump 模式，彻底摆脱文本解析。

---

## 6. 功能范围

### 6.1 必须等价迁移（现网行为，不可回退）

1. **每次调用跑一轮就退出**的模型（launchd `StartInterval=60` / systemd timer / cron），保持 `LP_BUDGET(55) < 调度间隔(60)`。
2. **长轮询状态机** `probe → trial → longpoll`，含全部五条降级保证：无 `rev` 的老服务端 → 每轮单次拉取；服务端忽略 `?wait` → trial 阶段用 `PR_ELAPSED < 5` 检出并记一次日志后转单次；`not_modified` → 确认长轮询；异常瞬回 → `LP_FLOOR` 10 秒兜底防热循环；任何 error → 立刻 break 等下一 tick。
3. **多 iface**：glob `/etc/wgctl/*.json`，**仅当只有一个 iface 时才长轮询**（否则一个 iface 的 45 秒 hold 会饿死另一个的心跳）。
4. `config.json` → `<iface>.json` 的**遗留迁移**。
5. **心跳 401 + body 匹配才自我驱逐**，且只拆自己这个 iface（各平台删除清单见 `wgctl-agent.sh` 的 `evict()`）。注意 `/v1/peers` 的 401 **不驱逐**。
6. **fail-soft**：peers 请求任何非 200 → 保留现有 conf 不动。
7. **hub 的 egress NAT 收敛**：Linux iptables MASQUERADE（check-before-act 幂等）+ FreeBSD pf（`pfctl -e` 仅在 `Status: Disabled` 时执行，**永远不用 `-E`**，会 ref-count 泄漏）。
8. **macOS 路由收敛**：对每个 `/etc/wireguard/*.conf` 跑 postup 钩子，**无条件执行，包括没有任何 state 文件时**（手工搭的 hub 也要覆盖）。永不自动添加 `0.0.0.0/0` / `::/0`。

### 6.2 顺带修掉的现存缺陷（调研中发现，均已定位到行）

| 缺陷 | 影响 |
|---|---|
| macOS 的 `stats` **恒为 0** | `wgctl-agent.sh` 匹配 `peer:\s+(\S+)`，但 `wg_core.c:1524` 打的是 `peer #%d: %s`。`cur` 永不置位 → 后续所有字段被跳过 → `peers:[]` 且 **`stats` 的 rx/tx/last_handshake_sec 全 0**，而 `iface_up:true`。roster 那半边无所谓（服务端本来就不收，见 §6.4），但 **`stats` 是被真正消费并入库的**，所以每台 macOS 设备在控制面里流量恒为 0、握手年龄恒为 0 |
| `agent_ver` 恒为 `unknown` | 读 `/usr/local/share/wg-mac/VERSION`，而 install.sh 写的是 `/usr/local/libexec/wg-mac/VERSION` |
| `join-linux.sh` 的 401 自我驱逐是死代码 | 用了 `curl -fsS`，401 时 curl 以 22 退出但仍打印 `%{http_code}`，`$CODE` 变成 `"401\n000"`，两个分支都不匹配 |
| `listen` vs `wg_listen` 键名分裂 | `join-linux.sh` 写 `listen`，`wg-agent.sh` 读 `wg_listen` → 端口恒为默认 1632。**新实现两个键都接受** |
| 两个 Linux agent 会打架 | `wgctl-refresh-linux` 和 `wg-agent` 渲染出的 conf 字节不同（头部注释、keepalive 规则、Address 重算），同时存在则互相判定"变了"→ 永久 flap。**新 installer 必须卸载另一个的 unit** |

### 6.3 需要拍板的协议缺口

以下都是协议文档里有、但所有 shell agent 都直接扔掉的，重写时必须显式决定做还是不做：

- **`POST /v1/token/refresh` 完全没实现**。`token_expires` 写进了 state 文件却从没被读过。一旦服务端启用 token 轮换，整个 fleet 会被驱逐。**建议：这次补上**。
- **`refresh_sec` 被忽略**，agent 硬编码 60 秒。服务端调这个值对现网无效。
- **DNS/proxy policy 在桌面端完全没实现**。`230737f` 只落在服务端 + iOS NE。要做的话得先定响应结构。
- **公网出口 IP**：`wgctl-agent.sh` 今天（2026-07-26）刚改成 curl 外部 echo 服务 + 15 分钟缓存 + 失败回退陈旧值；**Linux/FreeBSD/Swift 三个实现仍在上报默认路由网卡的本地地址**，NAT 后永远是 RFC1918。新实现统一走缓存 echo 方案。
- 自我驱逐目前**依赖服务端的散文**（`grep -qE 'invalid device token|token expired|token does not match'`），服务端改个措辞就全网静默失效。新实现应匹配结构化的 `{"error":"invalid_device_token"}`，并保留旧字符串作 fallback。

### 6.4 服务端实际消费的字段（决定 agent 该采集什么）

核对 `polar-wg` 服务端后的结论：**整个 `status` 块是白报的。**

```go
type wgHeartbeatRequest struct {
    LANAddrs   []WGLanAddr `json:"lan_addrs"`
    WGEndpoint string      `json:"wg_endpoint"`
    Stats      *struct{ RXBytes, TXBytes, LastHandshakeSec *int64 }  `json:"stats"`
}   // ← 没有 status 字段
```

`handleWGHeartbeat` 只把 `lan_addrs` / `wg_endpoint` / `stats` 三项落库（`wg_heartbeats` + `wg_devices`）。`status` 里的 `peers[]`、`peer_count`、`peers_online`、`os`、`arch`、`agent_ver`、`iface_up`、`uptime_sec` 在 JSON 解码时被整块丢弃 —— **spoke 和 hub 一视同仁，都白报**。

admin UI 上真正显示的 peer roster 来自**另一条完全独立的链路**：控制面进程在 hub 机器上**自己 shell out 跑 `wg`/`wgctl` 采样**（`hub_local_self_poll.go`，30 秒一次），生成 `wg_peer_status` 推到 `/internal/v1/wg-peer-status`，按 iface pubkey 缓存（`hubStatusCache`，带 TTL），由 `/admin/wg-hub-status` 输出。跟 agent 心跳没有任何关系。

`doc/hub-status.md` 自己在开头也写了："server-side storage + admin UI ... 是 Polar repo 的范围，**not part of this repo's scope**" —— 服务端那半边从来没实现过。

**对本设计的三条影响**：

1. **spoke 不序列化 `peers[]`**，hub 也不必（服务端不收）。省掉每次心跳的一大块拼装。若将来服务端要收，再按 hub-status.md 的理由只让 hub 报——hub 的内核握手表才是权威（睡眠/NAT 后的 spoke 会停止自报，hub 仍知道它的 last-handshake 年龄）。
2. **但 `wg show <iface> dump` 还是要跑**，因为 `stats` 是被消费的，而它是 peer 的聚合（sum rx、sum tx、min 握手年龄）。spoke 上就一个 peer（hub），成本是一行。
3. **`stats.last_handshake_sec` 是 spoke 最有价值且不冗余的信号**：心跳走公网 HTTPS 到 CP，wg 隧道是另一条路径，设备完全可能心跳正常而隧道已死（就是"handshake pending 到永远"那类故障）。这一个字段就覆盖了，别为了省事把它一起砍掉。

### 6.5 conf 渲染：改用语义比较

现在的变更检测是对整个文件 `cmp -s`，所以列对齐（`PrivateKey `、`Address    `、`PublicKey  `、`Endpoint   ` 的空格数）是**字节敏感**的——格式漂一个空格，就会每 60 秒 kickstart 一次隧道，永远不停。

新实现**不要去复刻空格**。渲染保持确定性（peer 按 pubkey 排序），比较改成**解析后比语义**（interface 三元组 + peer 集合）。这样从 shell 切到 Swift 时不会因为格式差异触发一次全网 flap，以后也不会。

另外必须保留 B 的空渲染保护：渲染结果为空时**绝不覆盖**现有 conf（A 目前会写入空 conf 然后 kickstart，是真实隐患）。

---

## 7. 构建与分发

| 目标 | 方式 | 产物 |
|---|---|---|
| macOS | `swift build -c release --arch arm64 --arch x86_64` | universal Mach-O |
| Linux（全部） | `swift build -c release --swift-sdk {x86_64,aarch64}-swift-linux-musl` | 静态 ELF，零依赖 |
| iOS arm64 | **不能用 SwiftPM**（`swift build --triple arm64-apple-ios` 不支持，swift-package-manager#8716）→ `swiftc -target arm64-apple-ios15.0 -sdk $(xcrun --sdk iphoneos --show-sdk-path)` + `codesign -f -s -` 带四个私有 entitlement | Mach-O |
| FreeBSD | 机器上原生编译（无 GitHub runner） | 原生二进制 |

**三个已知的构建陷阱**：

1. **musl SDK 版本必须和工具链对齐 —— 已实测复现并给出解法（2026-07-26）**。

   直接 `swift build --swift-sdk aarch64-swift-linux-musl` 会失败，因为默认 `swift` 是 **Xcode 的 6.4** 工具链，而装在本机的静态 SDK 是 **6.3.2**：

   ```
   error: module compiled with Swift 6.3.2 cannot be imported by the Swift 6.4 compiler:
          …/swift-6.3.2-RELEASE_static-linux-0.1.0.artifactbundle/…/Foundation.swiftmodule/
          aarch64-swift-linux-musl.swiftmodule
   ```

   这就是 `doc/worklog-2026-06-12-ios-kcp.md` 里那次"只能上 hub 原生编译"的真正原因，**不是 SDK 坏了，是拿错了编译器**。静态 SDK 本来也要求用 swift.org 的开源工具链，不能用 Xcode 自带的。

   解法：本机已装 `~/Library/Developer/Toolchains/swift-6.3.2-RELEASE.xctoolchain`（bundle id `org.swift.632202605101a`），版本正好对上。用它的 `swift` 显式交叉编译即可：

   ```bash
   SWIFT632=~/Library/Developer/Toolchains/swift-6.3.2-RELEASE.xctoolchain/usr/bin/swift
   $SWIFT632 build -c release --swift-sdk aarch64-swift-linux-musl   # ✅
   $SWIFT632 build -c release --swift-sdk x86_64-swift-linux-musl    # ✅
   $SWIFT632 build -c release --swift-sdk aarch64-unknown-linux-android28  # ✅（Android SDK 也已装）
   ```

   **macOS/iOS 目标继续用 Xcode 的工具链**，只有 Linux/Android 交叉走 6.3.2。升级工具链时两边必须同步升，否则同样的错误会再来一次。
2. **iOS root daemon 不能依赖 `@rpath`**：特权进程的 `DYLD_*` 被剥离、`@rpath` 解析受限。deployment target 设 ≥ 12.2，链系统的 `/usr/lib/swift/*` 绝对路径。
3. **glibc 下限**（如果哪天还是要出 glibc 包）：在 jammy(2.35) 上编，不要 noble(2.38)，否则 Ubuntu 22.04 的 hub 加载不了——`676586d` 已经踩过。

CI：现有 `.github/workflows/wg-agent-linux.yml` 扩成 musl 双架构 + macOS universal；iOS 和 FreeBSD 保持本地/机上构建。

---

## 8. 迁移路线

现网是活的，按阶段推进，每阶段可独立回滚：

**Phase 0（独立于重构，可立刻做）**：修 §6.2 那五个缺陷。都是几行的改动，且和语言无关——macOS 的 peer roster 现在是全空的，这个 bug 每多留一天，hub-status 的数据就多脏一天。

**Phase 1**：SwiftPM 化 + 把现有 `wg-agent.swift` 拆进 §4 的分层，补齐长轮询、rev 持久化、`config.json` 迁移、缓存 echo 公网 IP。产物先只发 Linux musl。

**Phase 2**：以 **report-only 模式**在若干台机器上与 shell agent 并行跑——只发心跳、不写 conf、不碰系统。对比两者算出的 heartbeat body，确认字段级一致。

**Phase 3**：按平台灰度切换，顺序建议 Linux → macOS → iOS → FreeBSD。每切一个平台，对应的 installer 同时负责卸载旧 unit（尤其 Linux 上两个 agent 打架那条）。

**Phase 4**：FreeBSD 观察期满 30 天无事故后，才删 shell agent。在此之前 `.sh` 保留在仓库里，且 installer 要能一键切回。

---

## 9. 风险登记

| 风险 | 等级 | 处置 |
|---|---|---|
| FreeBSD 自有工具链出 runtime 级 hang | 高 | 并发压到最浅（§4.4）；shell fallback 保留；观察期 30 天 |
| musl 静态 SDK 与工具链版本漂移导致构建断 | 中 | 双向 pin 6.3.3；CI 锁版本；已有前科 |
| 切换时 conf 格式差异引发全网 flap | 中 | 改语义比较，不复刻字节（§6.5） |
| libcurl 绑定在某平台行为不一致 | 中 | 显式设 `CURLOPT_CAINFO`/`CAPATH`（musl 静态和 Android 必须）；保留硬看门狗 |
| iOS root daemon 签名/entitlement 回归 | 低 | entitlement 从现有二进制 dump 后固化进构建脚本 |
| 心跳字段不等价导致 CP 侧数据静默变脏 | 中 | Phase 2 的 report-only 比对是专门为这个设的 |
```
