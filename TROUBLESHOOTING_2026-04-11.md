# 排查文档 - Tunnel 握手失败与路由异常（2026-04-11）

## 现象
- UI 显示 Connected，但 `wg` 层一直重传 initiation：
  - `[hs] retransmit: initiation sent (attempt N)`
  - `last_handshake_time_sec=0`
  - `tx_bytes=0 / rx_bytes=0`
- `ping 10.88.0.1` 超时。
- `tcpdump` 显示外层 UDP 源地址错误：
  - 实际发送：`192.168.112.201 -> 172.16.203.128:51820`
  - 期望发送：`172.16.203.1 -> 172.16.203.128:51820`

## 根因

### 根因 1：UDP Session 未正确建立
- 原逻辑只从 provider config 的 `endpoint` 字段取 peer。
- 实际入口是 `serverAddress` 或配置文本 `Endpoint=`。
- 导致 `firstPeerEndpoint` 为空，`udpSession` 为空，写包静默 no-op。

### 根因 2：路由策略导致潜在回环
- Full 模式若直接 `includedRoutes = default`，但不排除 outer endpoint，
  extension 发往 peer 的外层 UDP 可能被再次导入 utun。

### 根因 3：开发环境多网卡/桥接导致源地址选错
- VMware Fusion bridge 场景，系统默认外发路径选到 `en0` 地址。
- 服务器与本机 bridge 网段应走 `172.16.203.x`，否则对端回包路径不一致。

## 解决方案

### 1) Endpoint 获取与 UDP 建链
- 新增 endpoint 解析链路：
  1. session introspection API（`wg_session_peer_*`）
  2. 配置文本 `Endpoint=` 回退
- 成功拿到 endpoint 后创建 `udpSession`。

### 2) Full / Split 双模式路由
- Full Tunnel：
  - 默认路由接管（v4/v6 default）。
  - 对 peer endpoint 添加 `excludedRoutes`（防止回环）。
- Split Tunnel：
  - 不改系统 default route。
  - 仅写入 peer allowed IP 对应目标网段。

### 3) 同网段源地址绑定（开发增强）
- 若 peer endpoint 与某本地接口在同一子网：
  - 使用该接口地址作为 `createUDPSession(to:from:)` 的 `from`。
- 结果：抓包源地址从 `192.168.112.201` 修正到 `172.16.203.1`。

### 4) `handleAppMessage(get=1)` 诊断增强
新增字段：
- `route_mode`
- `tunnel_remote`
- `peer_host`
- `selected_endpoint`
- `selected_local_bind`
- `udp_session`
- `included_v4/v6`、`excluded_v4/v6` 及计数

## 验证流程（建议保留）

### 客户端
```bash
sudo tcpdump -ni any udp port 51820
```
确认发包源地址、目标地址与端口是否符合预期。

### 服务端
```bash
sudo wg show
sudo systemctl status wg-quick@wg0 --no-pager
```
确认 peer 公钥、allowed-ips、最新握手时间、transfer 是否增长。

### 路由
```bash
netstat -rn
```
确认 Full/Split 模式下路由表变化符合设计。

## 本次经验
- NE 的“Connected”只表示 control-plane 完成，不代表 data-plane 可用。
- `tx/rx=0 + handshake_time=0` 是快速判断“外层 UDP 未打通”的高价值信号。
- 开发环境（bridge、多网卡、VM）与生产环境差异大，建议保留“同网段源绑定”作为可控策略。
