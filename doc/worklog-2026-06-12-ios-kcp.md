# 工作日志 — iOS WireGuard-over-KCP 真机验证 + 收尾（2026-06-12）

## 目标
把 iOS WireGuard-over-KCP（NEPacketTunnelProvider 里 wg_core + KcpSession 拼接）从"代码写完"
推到"真机验证通过"，并完成收尾：commit/PR + 发 TestFlight。

---

## 完成的事（含做法）

| 事项 | 做法 / 产物 |
|---|---|
| macOS CLI 拼接测试 | `/tmp/wgkcptest`：SwiftPM 包，C target 包 `wg_session.h` + 链 `libwg.a`/`libswift_crypto.a` + Shanghai。复刻 provider 的拼接：`send_udp→kcp.send`、`kcp.onReceive→wg_session_handle_udp`、tick+kick、轮询 `wg_session_peer_handshake_age` |
| device-only xcframework | `scripts/build-xcframework-ios-device.sh`：只出 `ios-arm64`（platform iPhoneOS），**零模拟器切片**（用户要求） |
| 真机签名构建/安装/调试 | `scripts/ios-device-debug.sh`：`build→install(devicectl)→launch→go-ios syslog`，headless |
| app→KCP 配置通路 | `TunnelManager.parseKcpDirectives`：配置文本里 `#kcp enable=1 conv=.. key=.. crypt=..` 一行映射到 provider 读的 `kcp*` providerConfiguration 键；无此行=普通 UDP。wg_core 跳过 `#` 注释，同一份配置喂 app 解析器和 `wg_session_create` 都安全 |
| **端到端握手证明** | CLI 经 mesh **1 秒握上**；真机 **Astris(iPhone 15 Pro Max)4G** 握手 + 9+ KiB 双向数据（Safari 穿隧道） |
| commit + PR | wg **PR #26**（KCP 通路 + 2 脚本）、Shanghai **PR #6**（kcpfwd datagram） |
| TestFlight | `release-testflight.sh` 上传 **0.1.0 build 6**，`UPLOAD SUCCEEDED` |
| kcpfwd 修复部署 | streamMode=false 在 **hub 原生编译**部署 + 持久化 `.service` |

---

## 遇到的问题 → 怎么解决

### 1. `wg_session_create` 解析失败
- **现象**：CLI 传配置报 `config parse failed`。
- **原因**：`wg_core.c` 要求 `ListenPort` 在 1..65535，`ListenPort = 0` 被拒。
- **解决**：删掉该行——peer 有 Endpoint 就满足"有事可做"的校验。

### 2. "本机 UDP 到 hub 被黑洞"——误判
- **现象**：从 build 机（100.64.0.3）探测 hub 公网 IP `124.221.22.9:1664/1632` 的 UDP 全部不到，一度判定出口被封。
- **真相**：①出口被代理成 Vultr IP（HTTP 走代理）；②我 tcpdump 时用了 `not net 100.64.0.0/24` 过滤，**把走 mesh 的探测包过滤掉了**，自己骗自己。
- **解决**：这台机在 polar mesh 上（utun0=100.64.0.3），改让 KCP endpoint 指向 **mesh 的 `100.64.0.1:1664`**（kcpfwd 监听 0.0.0.0），mesh 路径是通的。**教训：诊断"包没到"时别用会过滤掉真实源的 tcpdump 过滤器。**

### 3. 真机握手一直失败——最硬的一仗
逐段排查链路（这套定位法是关键）：
- KCP 包到 hub ✓（4G 抓到 192B 进 / 44B ACK 出）
- kcpfwd 解码并转发 **148B**（=WG initiation 精确大小）到 `127.0.0.1:51900`(wgtb) ✓ —— **证明 KCP/crypt/streamMode 都正常，包字节级正确**
- wgtb 收到却**不回** ❌

走过的弯路 + 最终定位：
- ❌ 一度怀疑 `streamMode` 不匹配（provider=false，kcpfwd 默认 true）——**红鲱鱼**：对 sub-MTU 的 WG 包线格几乎一样，且 kcpfwd 实际把 148B 干净解出来了。
- ⛔ 想开 WG 内核动态调试看丢包原因——被 auto-mode 分类器拦（共享机器清 dmesg/改内核控制），**绕过**：不碰内核。
- ❌ 用 `wgcli` loopback 测试 wgtb——**无效（假阴性）**：WireGuard 已知限制，同一主机两个 wg 接口经 loopback 互相握不上手。
- ✅ **netns 隔离**标准内核 wg 测试：旧 wgtb 照样不回；**新建一个 wgtb 一握就成**（476/564 字节，handshake 7s ago）。

**两个真因（都不是 iOS 代码）：**
1. **wgtb 反重放 timestamp 中毒**——我反复用同一把私钥从 hub 本地做测试，污染了 wgtb 对该 peer 的"最大时间戳"记忆，之后所有 initiation 被当重放静默丢弃。→ 换全新 wgtb 密钥对。
2. **kcpfwd --server 单 conv 会话被占死**——LISTEN 模式对一个 conv 只维护一个 ikcp 会话；先前 stale 连接（设备/重叠）留下的序号状态让新客户端的 fresh seq=0 对不上，只 ACK(44B) 不吐数据 → 不转发。→ `systemctl restart kcpfwd-clitest` 清空 + 每客户端用独立 `--conv`。

修完后 CLI 第一次 attempt、1 秒握上；真机切回这套（全新 wgtb + 干净会话 + 唯一客户端 + Safari 产生流量唤醒 wg_core 退避）后 4G 握手 + 数据全通。

### 4. TestFlight：Xcode 账号会话过期
- **现象**：`xcodebuild -exportArchive` 报 `Unable to log in with account ... session has expired`，且没有 App Store 分发 profile。
- **解决**：repo 里有现成的 `WireGuardSampleApp/scripts/release-testflight.sh`——用 **ASC API key**（`-authenticationKey*`，key SAZ8WF9X6U + issuer 69a6de92…）认证，**绕过过期的 Xcode 会话**；还手动重签打包绕过 Xcode 26 的 exportArchive "Copy failed"。bump build 5→6 后 `--yes` 上传成功。

### 5. macOS 交叉编译 kcpfwd 挂
- **现象**：`swift build --swift-sdk x86_64-swift-linux-musl` 报 `Foundation.swiftmodule created by an older version of the compiler`。
- **原因**：static-linux musl SDK 自带的 Foundation 模块比当前 swiftc 旧（工具链升级过）。
- **解决（绕过）**：改在 **hub 原生编译**——hub 装了 swiftly swift 6.3.2，`git clone` + `swift build --product kcpfwd -c release`，23 秒编完。

### 6. systemd-run 瞬态单元一 stop 就消失
- **现象**：`systemctl stop kcpfwd-clitest` 后 `start` 报 `Unit not found`。
- **原因**：`systemd-run --unit=` 是瞬态单元，stop 即删，不能按名 start。
- **解决**：写持久化 `/etc/systemd/system/kcpfwd-clitest.service`（Restart=always, enabled）+ 二进制移到 `/usr/local/bin/kcpfwd`（离开会被清的 /tmp）。

---

## 没搞定 / 先放下 / 绕过去的（含原因）

| 项 | 状态 | 为什么放下 / 怎么绕的 |
|---|---|---|
| macOS static-musl 交叉编译 kcpfwd | **绕过** | SDK Foundation 与 swiftc 版本不齐。绕过=hub 原生编译（已满足需求）。根治要对齐 static-linux SDK/工具链版本，**非阻塞，放下** |
| go-ios syslog 抓不到自定义 `os_log` | **绕过** | go-ios 只收 legacy syslog，不收统一日志，所以 `kcp transport →` 等行看不到。改用 **app 内状态 dump**(`selected_local_bind=(kcp)`/`udp_session=nil`) + **hub `wg show`** 验证，足够 |
| KcpSession 网络迁移（WiFi↔蜂窝切换断 KCP） | **放下** | BSD-socket 不自动迁移，切网会断 KCP socket。plan 里标了 v2 用 NWConnection-backed transport。本次只要验证握手/数据，**放下到 v2** |
| wgtb 测试接口不持久 | **未做** | 内核 wg 接口手动建的，重启丢。本次只持久化了 kcpfwd，已提示用户；要全自动恢复需给 wgtb 也做开机自起（wg-quick `/etc/wireguard/wgtb.conf` 或 systemd） |
| streamMode=false 重新部署到生产 hub-to-hub 对 | **只动测试实例** | 只把 `kcpfwd-clitest`（测试实例）换成新二进制；生产 hub-to-hub 的 kcpfwd 对仍是旧 binary（true/true，自洽）。两端必须同时升级才一致，**生产升级单独排期** |
| 真机日志实时联调 | **半自动** | 设备锁屏/退后台/网络切换打断 go-ios 流 + wg_core 握手退避，靠用户手动 toggle 协调，效率一般。后续可做更自动的设备保活/触发 |

---

## 遗留 TODO
- [ ] 给 wgtb 做开机自起，整条测试链路重启全自动恢复
- [ ] 修 macOS static-linux SDK / 工具链版本对齐，恢复本地交叉编译能力（否则只能 hub 原生编译）
- [ ] v2：KcpSession 改 NWConnection-backed，支持 WiFi↔蜂窝透明迁移
- [ ] 生产 hub-to-hub 的 kcpfwd 统一升级到 streamMode=false（两端同步）
- [ ] TestFlight：等 build 6 处理完，填 Test Information + 外部测试组

---

## 关键产物 / 入口
- wg PR #26 · Shanghai PR #6 · TestFlight 0.1.0(6)
- 脚本：`scripts/build-xcframework-ios-device.sh`、`scripts/ios-device-debug.sh`、`WireGuardSampleApp/scripts/release-testflight.sh`
- hub 测试台：`kcpfwd-clitest.service`(`/usr/local/bin/kcpfwd`, datagram, :1664) + 手动 `wgtb`(10.99.0.2)
- 配方：全新 wgtb + 重启 kcpfwd 清会话 + 设备作唯一 conv 客户端 + 产生流量唤醒 wg_core 退避
