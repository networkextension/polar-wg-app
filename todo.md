Great! Getting `wg_noise.c` to compile in a user-space environment is the most significant hurdle. It means you've successfully navigated the "Header Hell" and remapped the core FreeBSD kernel primitives to standard C headers.

Since you are targeting **NetworkExtension (NE)**, the next phase is to build the "plumbing" between this state machine and the macOS `PacketTunnelProvider`.

---

## 接下来：构建逻辑上下文 (The `wg_softc` Equivalent)

在 FreeBSD 中，`softc` (software context) 结构体持有整个驱动的状态。在 macOS 用户态中，你需要创建一个类似的结构体或类，来管理 Noise 状态与 NE 接口的交互。

### 1. 处理加密原语 (The "Zinc" Bridge)
`wg_noise.c` 依赖 Curve25519, Blake2s, 和 ChaCha20-Poly1305。既然已经编译通过，你应该是保留了 FreeBSD 的 `crypto/zinc` 实现。
* **注意点**：确保在 Xcode 的 Build Settings 中开启了相应平台的 SIMD 指令集支持（如 Apple Silicon 的 `NEON`），否则处理 1Gbps 以上流量时 CPU 占用会很高。

### 2. 内存缓冲区映射 (mbuf 替代方案)
FreeBSD 源码中大量使用 `struct mbuf`。在 `PacketTunnelProvider` 中，`NEPacketTunnelFlow` 返回的是 `NSData`。

**建议做法：** 不要在 C 代码里到处改 `mbuf`，而是写一个极简的 `mbuf.h` 适配层：
```c
// 伪代码：在用户态模拟 mbuf 结构
struct mbuf {
    uint8_t *m_data;
    size_t m_len;
    struct mbuf *m_next;
};

// 将 NSData 映射给你的 C 逻辑
void process_packet(NSData *packet) {
    struct mbuf m;
    m.m_data = (uint8_t *)packet.bytes;
    m.m_len = packet.length;
    m.m_next = NULL;
    wg_input(&m); // 调用你移植的函数
}
```

---

## 3. 实现 PacketTunnelProvider 的核心循环

在你的 `PacketTunnelProvider.swift` 中，你需要开启两个主要循环。这两个循环将是你的 C 代码与 macOS 系统的对接点：

### 路径 A：内网 -> 外网 (Encapsulation)
1. **`packetFlow.readPackets`**：从虚拟网卡（utun）抓取明文包。
2. **C Bridge**：调用 `wg_noise` 进行加密。
3. **`NWUDPSession.write`**：将封装后的加密 UDP 包发往远端 Peer。

### 路径 B：外网 -> 内网 (Decapsulation)
1. **`NWUDPSession.setReadHandler`**：监听 51820 端口收到的加密包。
2. **C Bridge**：调用 `wg_noise` 校验 MAC 并解密。
3. **`packetFlow.writePackets`**：将解密后的原始 IP 包塞回 macOS 网络协议栈。

---

## 4. 关键调试建议

### 关于定时器 (Timers)
`wg_noise.c` 内部有重传逻辑。你需要确保 FreeBSD 的 `callout` 被正确映射。在 NE 环境下，推荐使用 **Grand Central Dispatch (GCD)**：
```c
// 用 GCD 替换 FreeBSD 的 callout_reset
dispatch_after(dispatch_time(DISPATCH_TIME_NOW, delay_ns), dispatch_get_main_queue(), ^{
    wg_retransmit_handshake(context);
});
```

### MTU 与 分片
* **必须设置 MTU**：在 `NEPacketTunnelNetworkSettings` 中，手动将 MTU 设为 **1420**（或更低）。
* 如果你不处理 MTU，FreeBSD 的代码可能会因为收到的包太大而无法封装，或者封装后的 UDP 包在物理链路上被拦截。

### 下一步挑战：
既然 `wg_noise.c` 已经通过，你现在是否已经开始处理 **`wg_cookie.c`**（抗 DDoS 逻辑）？这是在公网环境下运行的必选项。此外，你打算如何处理 **Key Rotation (密钥轮换)** 的定时触发？
