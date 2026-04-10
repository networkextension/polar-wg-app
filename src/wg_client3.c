#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// --- 1. 结构体定义 (必须放在函数声明之前) ---

// 模拟 mbuf 结构，需匹配 libwg.a 的预期
struct mbuf {
    struct mbuf *m_next;
    void        *m_data;
    int          m_len;
    uint8_t      data_storage[2048]; 
};

struct noise_keypair; // 前向声明

// --- 2. 外部函数声明 (从 libwg.a 链接) ---

// 对应符号表中的 _noise_keypair_encrypt 
extern int noise_keypair_encrypt(struct noise_keypair *, uint32_t *r_idx, uint64_t nonce, struct mbuf *); 

// 对应符号表中的 _noise_keypair_decrypt 
extern int noise_keypair_decrypt(struct noise_keypair *, uint64_t nonce, struct mbuf *); 

// --- 3. 辅助函数 ---

struct mbuf* alloc_mbuf(void* data, size_t len) {
    struct mbuf* m = (struct mbuf*)calloc(1, sizeof(struct mbuf));
    if (!m) return NULL;
    m->m_data = m->data_storage;
    m->m_len = (int)len;
    memcpy(m->m_data, data, len);
    return m;
}

// --- 4. 主逻辑 ---

void handle_packets(int utun_fd, int udp_fd, struct noise_keypair *kp, struct sockaddr_in *peer_addr) {
    uint8_t raw_buf[1600];
    uint32_t receiver_index = 0; 
    uint64_t tx_nonce = 0;

    while (1) {
        // 从 utun 读取明文 (macOS utun 前4字节通常是 family 类型)
        ssize_t n = read(utun_fd, raw_buf, sizeof(raw_buf));
        if (n <= 0) continue;

        // 转换为 mbuf
        struct mbuf *m = alloc_mbuf(raw_buf, n);
        if (!m) continue;

        // 调用 libwg.a 加密
        // 这里的 receiver_index 会由函数内部填充 
        if (noise_keypair_encrypt(kp, &receiver_index, tx_nonce++, m) == 0) {
            // 加密成功，发送给 Linux 虚拟机
            sendto(udp_fd, m->m_data, m->m_len, 0, (struct sockaddr *)peer_addr, sizeof(*peer_addr));
            printf("[TX] Sent %d bytes (encrypted)\n", m->m_len);
        } else {
            fprintf(stderr, "[!] Encryption failed\n");
        }

        free(m);
    }
}

int main() {
    // 这里补全你的 utun 和 socket 初始化逻辑
    printf("WireGuard client demo starting...\n");
    return 0;
}
