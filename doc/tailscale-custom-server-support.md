# Tailscale 客户端的自定义 coordination server 支持

> 配合 `doc/wg-mac-tailscale-howto.md`。当 admin 发的 token 是 `tskey-…`
> 时，用户需要在 Tailscale 官方客户端里把 coordination server 切换成
> `https://wg.4950.store:2443`（Polar 内嵌的 Headscale）。每个平台的入口位置
> 不同，本文汇总。
>
> 官方参考：<https://tailscale.com/kb/1315/custom-coordination-server>

---

## 1. 平台支持矩阵

| 平台 | 入口 | 备注 |
|---|---|---|
| **macOS CLI** (`brew install tailscale`, 含 `tailscaled`) | `tailscale up --login-server=https://wg.4950.store:2443 --authkey=tskey-…` | 一等公民，最稳 |
| **macOS App Store 版** ("Tailscale" by Tailscale, Inc.) | 安装后先用 CLI 切：`/Applications/Tailscale.app/Contents/MacOS/Tailscale set --login-server=https://wg.4950.store:2443`，然后 GUI 重新登录 | GUI 本身没暴露切换菜单；CLI 命令藏在 App bundle 里 |
| **iOS App Store** | 首次启动登录页底部："Use alternate coordination server" → 填 URL → 用 authkey 登录 | 2024 年起所有版本都加了这个选项；登过 official Tailscale 的话先 Sign Out 再走 |
| **Android Play Store** | 登录页右上角菜单 → "Use an alternate server"；或 Settings → 长按 Tailscale logo 进 debug 菜单 | 行为同 iOS |
| **Android F-Droid** (开源 fork) | Settings → Server URL，直接编辑 | 自由切换，无需 sideload |
| **Linux CLI** | `tailscale up --login-server=https://wg.4950.store:2443 --authkey=tskey-…` | 同 macOS CLI |
| **Windows GUI / CLI** | CLI: `tailscale up --login-server=… --authkey=…`；GUI: 系统托盘 → Preferences → "Use a custom coordination server" | Windows 客户端 1.50+ 才在 GUI 暴露选项 |

---

## 2. 各平台详细步骤

### 2.1 macOS App Store 版（用户最容易踩坑的）

```bash
# 1. 装官方 App Store 版
open "https://apps.apple.com/app/tailscale/id1475387142"
# 2. 不要立刻登录；先切 coordination server
/Applications/Tailscale.app/Contents/MacOS/Tailscale set \
    --login-server=https://wg.4950.store:2443
# 3. GUI 里点 "Log in"，弹出我们 Headscale 的登录页
# 4. 用 authkey 登录（在浏览器粘贴 tskey-…，或在 GUI 提示框里贴）
```

如果用户在切之前已经登过官方 Tailscale，需要先：
```bash
/Applications/Tailscale.app/Contents/MacOS/Tailscale logout
```
然后再 `set --login-server=…`。

### 2.2 iOS App Store

1. 装官方 [Tailscale](https://apps.apple.com/app/tailscale/id1470499037) 应用
2. 打开 app，**不要**直接走 "Sign in"
3. 在登录页**底部**有一行小字 "Use alternate coordination server"，点它
4. 输入 `https://wg.4950.store:2443`，确认
5. 这时再走登录流程；提示让你贴 authkey 时贴 `tskey-…`

> 如果用户已经登过官方 Tailscale：Settings → Sign Out → 然后回到登录页才能看到 "Use alternate coordination server"。

### 2.3 Android Play Store

1. 装官方 [Tailscale](https://play.google.com/store/apps/details?id=com.tailscale.ipn) 应用
2. 启动后登录页右上角溢出菜单 → "Use an alternate server"
3. 填 `https://wg.4950.store:2443`
4. 用 authkey 登录

如果选项不显眼，**长按** Tailscale 主页的 logo 三秒会进 debug 菜单，里面也能改 server URL。

### 2.4 F-Droid Android 版（推荐给国内用户）

F-Droid 仓库的 Tailscale 是开源 fork，coordination server 在 Settings 里就是一个常规可编辑项：

```
Settings → Server URL → https://wg.4950.store:2443 → Save
```

无需 sideload、无需 ADB。

### 2.5 Windows

CLI（PowerShell 或 cmd）：
```powershell
tailscale up --login-server=https://wg.4950.store:2443 --authkey=tskey-…
```

GUI（Tailscale 1.50+）：
- 系统托盘图标右键 → Preferences → Account
- 勾 "Use a custom coordination server"
- 填 URL → 重新登录

---

## 3. 常见坑

| 现象 | 原因 | 处理 |
|---|---|---|
| Tailscale GUI 启动后直接弹 login.tailscale.com 登录页 | 没切 coordination server 就开始登录 | Sign Out → 切 server → 重登 |
| `tailscale set --login-server=…` 报 "tailscaled not running" | macOS App Store 版的 tailscaled 是后台进程，第一次启动后才在跑 | 先打开一次 GUI（不登录），让 tailscaled 起来，再跑 set |
| iOS 登录页找不到 "Use alternate coordination server" | App 版本 < 1.50，或之前已经登过官方账号 | 升级 app；或 Sign Out 后重启 app |
| Android 切了 server 但还是连官方 | app 缓存；切完 server 后强退 + 清后台 | 设置 → 应用 → Tailscale → 强行停止 |
| `authkey already used` | tskey 是单次的（reusable=false） | admin 重发；或 mint 时勾 reusable |
| 连上了但 `tailscale status` 看不到其他设备 | Headscale 端 ACL 默认全互通，但 namespace/user 没对齐 | Polar admin 检查 `headscale users list` + 确保 PreAuthKey 绑到正确 user |
| iOS / Android 没看到 wg-mac 设备 | wg-mac 客户端走的是 `/v1/*` 自有协议，Tailscale 客户端走 `/machine/*`，**当前 dual-rail 还没做 peer-list 互通**（设计 §C4 尚未上线） | 等 Polar 那边完成 C4 (设备视图统一)；目前两条 rail 设备列表各看各的 |

---

## 4. 跟 Polar admin 协作

如果用户报"按你写的填了 URL 但是没用"，让 admin 检查：

1. `https://wg.4950.store:2443/health` 返回 200 — Polar dock 正常
2. nginx vhost 是否代理了 `/machine/*` → 127.0.0.1:8081（Headscale 监听）：
   ```nginx
   location /machine/ { proxy_pass http://127.0.0.1:8081; }
   location /derp/    { proxy_pass http://127.0.0.1:8081; }
   ```
3. Polar dock 启动时 `WG_HEADSCALE_ENABLED=1` 已设；`/etc/headscale/config.yaml` 存在
4. `headscale users list` 能看到对应 user；`headscale preauthkeys list -u <user>` 能看到当前 tskey 行

如果以上都对但 client 还是连不上，多半是 nginx 没透传 Connection upgrade（DERP 走 ws）。Polar 仓库 [`reference_polar_repo`] 的 `scripts/nginx/` 有现成模板。

---

## 5. 相关参考

- `doc/wg-mac-tailscale-howto.md` — 两种 token 路径总览（操作员侧入口文档）
- `doc/JOIN_PROTOCOL.md` — wg-mac `/v1/*` 协议（不是 Tailscale 路径）
- `~/github/Polar-/doc/wg-mac-tailscale-compat-design.md` — Phase 11 dual-rail 整体设计
- `~/github/Polar-/doc/wg-mac-tailscale-spike-report.md` — 嵌入 Headscale 的 spike 结论
- [Tailscale KB 1315](https://tailscale.com/kb/1315/custom-coordination-server) — 官方各平台说明
- [Headscale README — Client compatibility](https://github.com/juanfont/headscale#supported-clients) — 哪些版本/平台兼容
