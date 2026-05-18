# wg-mac + Tailscale 客户端兼容 — operator howto

> Polar control plane (`https://zen.4950.store`) 同时接受两种客户端：
> 我们自己的 wg-mac (mac CLI / iOS app / Android app)，以及官方 Tailscale
> 客户端。两条路径连入同一个 mesh，两边设备互通。

---

## 1. 两种 token，两条路径

Admin 在 `/wg-tokens.html` 创建一个 token 时，server 会同时返回两个字符串：

| 前缀 | 用途 | 走哪个客户端 |
|---|---|---|
| `polar_wg_<32 hex>` | wg-mac 原生 `/v1/register` 流程 | wg-mac (本仓库) |
| `tskey-<...>` | Headscale PreAuthKey | 官方 Tailscale 客户端 |

两个 token 是同一个 mint 操作的两半，**绑定到同一个 hub / namespace**，
mesh CIDR 都是 `100.64.0.0/10`（CGNAT），任选其一即可。不要同时给同一
台设备两个，会产生两个独立的 mesh 身份。

---

## 2. 你拿到 `polar_wg_…` 时

走 wg-mac 路径。

### macOS CLI

```bash
curl -sSL https://zen.4950.store/v1/install | \
    sudo bash -s -- --token=polar_wg_<your-hex-token>
```

或本地脚本（开发/测试用）：

```bash
sudo bash scripts/join.sh \
    --server=https://zen.4950.store \
    --token=polar_wg_<your-hex-token>
```

完成后：

```bash
sudo wgctl show wgc0
```

### iOS / Android

1. 打开 wg-mac app
2. 切到 **Mesh Join** tab
3. Server URL 填 `https://zen.4950.store`，token 粘贴 `polar_wg_…`
4. 点 **Join Mesh**

设备会出现在 `/wg-tokens.html` 的 💻 Devices 列表里，source 列显示
`🍎 wg-mac`。

---

## 3. 你拿到 `tskey-…` 时

走官方 Tailscale 客户端。

### macOS

```bash
brew install --cask tailscale
sudo tailscale up \
    --login-server=https://zen.4950.store \
    --authkey=tskey-<your-key>
```

### iOS

1. App Store 装 [Tailscale](https://apps.apple.com/app/tailscale/id1470499037)
2. 启动后在登录页选 **Use a custom coordination server**
3. 服务器填 `https://zen.4950.store`
4. Auth key 粘贴 `tskey-…`

### Android

1. Play Store 装 [Tailscale](https://play.google.com/store/apps/details?id=com.tailscale.ipn)
2. 同上：custom coordination server + authkey

设备会出现在 `/wg-tokens.html` 的 💻 Devices 列表里，source 列显示
`🪶 tailscale`（embedded Headscale 接管）。

---

## 4. 同时拿到两个 token 怎么办

挑一个。两种客户端见到的 mesh 是同一个，IP 段重叠不冲突，但**身份是分开
的**：

- 用 `polar_wg_…` 注册一次后，再拿同 mint 的 `tskey-…` 跑 `tailscale up`
  会创建**第二个**设备条目（一个 🍎，一个 🪶），各自占用一个 mesh IP，
  心跳独立，admin 看到两条记录。
- 如果是给团队，统一让一类机器走一条路径，运维更简单：
  - **macOS + 自己的服务器/路由器** → 推荐 wg-mac，体积小、launchd 集成
  - **iPhone / Android / Windows** → 推荐 Tailscale 官方客户端，跨平台
    省事

---

## 5. Troubleshooting

| 症状 | 原因 | 处理 |
|---|---|---|
| `register failed: invalid_token` | 把 `tskey-…` 当作 wg-mac token 投进 `/v1/register` 了 | 走 Tailscale 路径，或问 admin 要 `polar_wg_…` |
| `tailscale up` 卡在 "waiting for login" | login-server URL 写错（trailing `/`、http vs https） | 严格用 `https://zen.4950.store`（无尾斜杠） |
| `token_already_bound` 409 | 同一个 wg-mac token 二次注册 | 让 admin 重新发一个 |
| `pubkey_already_registered` 409 | 同一台机器换 token 重新跑 join | 先 `sudo wgctl leave wgc0` 释放旧条目 |
| `/v1/install` 404 | server vhost 没代理 `/v1/*` 到 polar-dock | 联系 admin 检查 nginx |
| iOS app paste `tskey-…` 后按 Join Mesh 没反应 | 我们的 app 检测到 Tailscale token 会禁用 Join 按钮，引导你装 Tailscale | 按 app 提示走 Tailscale 路径 |

---

## 6. 相关参考

- [`doc/JOIN_PROTOCOL.md`](./JOIN_PROTOCOL.md) — wg-mac `/v1/register` 协议细节
- `~/github/Polar-/doc/wg-mac-tailscale-compat-design.md` — 整体架构设计（dual control plane）
- `~/github/Polar-/doc/wg-mac-tailscale-spike-report.md` — 嵌入 Headscale 的 spike 报告
- [Headscale](https://github.com/juanfont/headscale) — Polar 内嵌的 Tailscale 控制面
- [Tailscale custom coordination server](https://tailscale.com/kb/1315/custom-coordination-server) — 官方文档
