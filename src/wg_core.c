#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "macos_stubs/sys/mbuf.h"
#include "macos_stubs/sys/param.h"
#include "macos_stubs/sys/rwlock.h"
#include <libkern/OSByteOrder.h>
#define htole32(x) OSSwapHostToLittleInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)
#define htole64(x) OSSwapHostToLittleInt64(x)

/* WireGuard wire format is little-endian. Match FreeBSD if_wg.c:73-76. */
#define WG_PKT_INITIATION htole32(1)
#define WG_PKT_RESPONSE   htole32(2)
#define WG_PKT_COOKIE     htole32(3)
#define WG_PKT_DATA       htole32(4)
#define WG_PKT_PADDING    16

#define WG_KEY_LEN 32
#define WG_AUTHTAG_LEN 16
#define WG_TIMESTAMP_LEN 12
#define WG_MAX_LINE 512
#define REKEY_TIMEOUT_SEC 5
#define COOKIE_MAC_SIZE 16
#define COOKIE_NONCE_SIZE 24
#define COOKIE_COOKIE_SIZE 16
#define COOKIE_ENCRYPTED_SIZE (COOKIE_COOKIE_SIZE + COOKIE_MAC_SIZE)

struct cookie_macs {
    uint8_t mac1[COOKIE_MAC_SIZE];
    uint8_t mac2[COOKIE_MAC_SIZE];
};

struct cookie_maker {
    uint8_t cm_mac1_key[32];
    uint8_t cm_cookie_key[32];
    struct rwlock cm_lock;
    bool cm_cookie_valid;
    uint8_t cm_cookie[COOKIE_COOKIE_SIZE];
    sbintime_t cm_cookie_birthdate;
    bool cm_mac1_sent;
    uint8_t cm_mac1_last[COOKIE_MAC_SIZE];
};

extern void cookie_maker_init(struct cookie_maker *, const uint8_t key[32]);
extern void cookie_maker_free(struct cookie_maker *);
extern void cookie_maker_mac(struct cookie_maker *, struct cookie_macs *, void *, size_t);
extern int cookie_maker_consume_payload(struct cookie_maker *,
                                        uint8_t nonce[COOKIE_NONCE_SIZE],
                                        uint8_t ecookie[COOKIE_ENCRYPTED_SIZE]);

struct noise_local;
struct noise_remote;
struct noise_keypair;

extern int crypto_init(void);
extern void crypto_deinit(void);

extern struct noise_local *noise_local_alloc(void *arg);
extern void noise_local_put(struct noise_local *);
extern void noise_local_private(struct noise_local *, const uint8_t private_key[WG_KEY_LEN]);

extern struct noise_remote *noise_remote_alloc(struct noise_local *, void *arg,
                                               const uint8_t public_key[WG_KEY_LEN]);
extern int noise_remote_enable(struct noise_remote *);
extern void noise_remote_put(struct noise_remote *);

extern int noise_create_initiation(struct noise_remote *,
                                   uint32_t *s_idx,
                                   uint8_t ue[WG_KEY_LEN],
                                   uint8_t es[WG_KEY_LEN + WG_AUTHTAG_LEN],
                                   uint8_t ets[WG_TIMESTAMP_LEN + WG_AUTHTAG_LEN]);
extern int noise_consume_response(struct noise_local *,
                                  struct noise_remote **,
                                  uint32_t s_idx,
                                  uint32_t r_idx,
                                  uint8_t ue[WG_KEY_LEN],
                                  uint8_t en[WG_AUTHTAG_LEN]);

extern struct noise_keypair *noise_keypair_current(struct noise_remote *);
extern int noise_keypair_nonce_next(struct noise_keypair *, uint64_t *);
extern int noise_keypair_encrypt(struct noise_keypair *, uint32_t *r_idx, uint64_t nonce, struct mbuf *);
extern void noise_keypair_put(struct noise_keypair *);

struct wg_pkt_initiation {
    uint32_t t;
    uint32_t s_idx;
    uint8_t ue[WG_KEY_LEN];
    uint8_t es[WG_KEY_LEN + WG_AUTHTAG_LEN];
    uint8_t ets[WG_TIMESTAMP_LEN + WG_AUTHTAG_LEN];
    struct cookie_macs m;
};

struct wg_pkt_response {
    uint32_t t;
    uint32_t s_idx;
    uint32_t r_idx;
    uint8_t ue[WG_KEY_LEN];
    uint8_t en[WG_AUTHTAG_LEN];
    struct cookie_macs m;
};

struct wg_pkt_cookie {
    uint32_t t;
    uint32_t r_idx;
    uint8_t nonce[COOKIE_NONCE_SIZE];
    uint8_t ec[COOKIE_ENCRYPTED_SIZE];
};

struct wg_pkt_data_hdr {
    uint32_t t;
    uint32_t r_idx;
    uint64_t nonce;
};

/* Wire-format size guarantees (match FreeBSD if_wg.c CTASSERTs). */
_Static_assert(sizeof(struct wg_pkt_initiation) == 148, "wg_pkt_initiation size");
_Static_assert(sizeof(struct wg_pkt_response)   == 92,  "wg_pkt_response size");
_Static_assert(sizeof(struct wg_pkt_cookie)     == 64,  "wg_pkt_cookie size");
_Static_assert(sizeof(struct wg_pkt_data_hdr)   == 16,  "wg_pkt_data_hdr size");

struct client_config {
    char endpoint_host[128];
    uint16_t endpoint_port;
    uint8_t private_key[WG_KEY_LEN];
    uint8_t peer_public_key[WG_KEY_LEN];
};

static int b64_value(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') return (int)(c - 'A');
    if (c >= 'a' && c <= 'z') return (int)(c - 'a') + 26;
    if (c >= '0' && c <= '9') return (int)(c - '0') + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int decode_base64_32(const char *in, uint8_t out[WG_KEY_LEN])
{
    size_t in_len = strlen(in);
    uint8_t tmp[64] = {0};
    int out_len = 0;
    int i;

    if (in_len != 44)
        return -1;

    for (i = 0; i < 44; i += 4) {
        int v0 = b64_value((unsigned char)in[i]);
        int v1 = b64_value((unsigned char)in[i + 1]);
        int v2;
        int v3;

        if (v0 < 0 || v1 < 0)
            return -1;

        tmp[out_len++] = (uint8_t)((v0 << 2) | (v1 >> 4));
        if (in[i + 2] == '=')
            break;

        v2 = b64_value((unsigned char)in[i + 2]);
        if (v2 < 0)
            return -1;
        tmp[out_len++] = (uint8_t)(((v1 & 0x0f) << 4) | (v2 >> 2));

        if (in[i + 3] == '=')
            break;

        v3 = b64_value((unsigned char)in[i + 3]);
        if (v3 < 0)
            return -1;
        tmp[out_len++] = (uint8_t)(((v2 & 0x03) << 6) | v3);
    }

    if (out_len != WG_KEY_LEN)
        return -1;

    memcpy(out, tmp, WG_KEY_LEN);
    return 0;
}

static char *trim(char *s)
{
    char *end;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
        s++;
    if (*s == '\0')
        return s;

    end = s + strlen(s) - 1;
    while (end > s && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) {
        *end = '\0';
        end--;
    }
    return s;
}

static int split_endpoint(const char *s, char host[128], uint16_t *port)
{
    const char *colon = strrchr(s, ':');
    long p;
    size_t host_len;

    if (!colon)
        return -1;

    host_len = (size_t)(colon - s);
    if (host_len == 0 || host_len >= 128)
        return -1;

    memcpy(host, s, host_len);
    host[host_len] = '\0';

    p = strtol(colon + 1, NULL, 10);
    if (p < 1 || p > 65535)
        return -1;

    *port = (uint16_t)p;
    return 0;
}

static int load_config(const char *path, struct client_config *cfg)
{
    FILE *f;
    char line[WG_MAX_LINE];
    int in_interface = 0;
    int in_peer = 0;
    int got_priv = 0;
    int got_pub = 0;
    int got_endpoint = 0;

    memset(cfg, 0, sizeof(*cfg));

    f = fopen(path, "r");
    if (!f) {
        perror("fopen config");
        return -1;
    }

    while (fgets(line, sizeof(line), f)) {
        char *p = trim(line);
        char *eq;

        if (*p == '\0' || *p == '#' || *p == ';')
            continue;

        if (*p == '[') {
            in_interface = (strncmp(p, "[Interface]", 11) == 0);
            in_peer = (strncmp(p, "[Peer]", 6) == 0);
            continue;
        }

        eq = strchr(p, '=');
        if (!eq)
            continue;
        *eq = '\0';
        eq++;

        p = trim(p);
        eq = trim(eq);

        if (in_interface && strcmp(p, "PrivateKey") == 0) {
            if (decode_base64_32(eq, cfg->private_key) != 0) {
                fprintf(stderr, "invalid PrivateKey in config\n");
                fclose(f);
                return -1;
            }
            got_priv = 1;
        } else if (in_peer && strcmp(p, "PublicKey") == 0) {
            if (decode_base64_32(eq, cfg->peer_public_key) != 0) {
                fprintf(stderr, "invalid Peer PublicKey in config\n");
                fclose(f);
                return -1;
            }
            got_pub = 1;
        } else if (in_peer && strcmp(p, "Endpoint") == 0) {
            if (split_endpoint(eq, cfg->endpoint_host, &cfg->endpoint_port) != 0) {
                fprintf(stderr, "invalid Endpoint format, expected host:port\n");
                fclose(f);
                return -1;
            }
            got_endpoint = 1;
        }
    }

    fclose(f);

    if (!got_priv || !got_pub || !got_endpoint) {
        fprintf(stderr, "config missing required fields: Interface.PrivateKey / Peer.PublicKey / Peer.Endpoint\n");
        return -1;
    }

    return 0;
}

static int udp_connect_endpoint(const char *host, uint16_t port)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *it;
    char port_str[8];
    int fd = -1;

    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        fprintf(stderr, "getaddrinfo failed for %s:%s\n", host, port_str);
        return -1;
    }

    for (it = res; it; it = it->ai_next) {
        int one = 1;

        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0)
            continue;

        (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));

        if (connect(fd, it->ai_addr, it->ai_addrlen) == 0)
            break;

        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

static int send_initiation(int udp_fd,
                           struct noise_remote *remote,
                           struct cookie_maker *cookie,
                           uint32_t *out_s_idx)
{
    struct wg_pkt_initiation pkt;
    int ret;

    memset(&pkt, 0, sizeof(pkt));
    pkt.t = WG_PKT_INITIATION;

    ret = noise_create_initiation(remote, &pkt.s_idx, pkt.ue, pkt.es, pkt.ets);
    if (ret != 0) {
        fprintf(stderr, "noise_create_initiation failed: %d\n", ret);
        return -1;
    }

    cookie_maker_mac(cookie, &pkt.m, &pkt, sizeof(pkt) - sizeof(pkt.m));

    if (send(udp_fd, &pkt, sizeof(pkt), 0) != (ssize_t)sizeof(pkt)) {
        perror("send initiation");
        return -1;
    }

    *out_s_idx = pkt.s_idx;
    return 0;
}

static int wait_for_response(int udp_fd,
                             struct noise_local *local,
                             struct noise_remote *remote,
                             struct cookie_maker *cookie,
                             uint32_t s_idx)
{
    uint8_t buf[2048];
    ssize_t n;

    n = recv(udp_fd, buf, sizeof(buf), 0);
    if (n < 0) {
        perror("recv");
        return -1;
    }

    if (n < 4) {
        fprintf(stderr, "short packet\n");
        return -1;
    }

    {
        uint32_t t;
        memcpy(&t, buf, sizeof(t));

        if (t == WG_PKT_COOKIE) {
            if (n < (ssize_t)sizeof(struct wg_pkt_cookie)) {
                fprintf(stderr, "short cookie packet\n");
                return -1;
            }
            {
                struct wg_pkt_cookie pkt;
                memcpy(&pkt, buf, sizeof(pkt));
                if (cookie_maker_consume_payload(cookie, pkt.nonce, pkt.ec) == 0)
                    fprintf(stderr, "received and consumed cookie reply\n");
                else
                    fprintf(stderr, "received cookie reply but consume failed\n");
            }
            return 1;
        }

        if (t != WG_PKT_RESPONSE || n < (ssize_t)sizeof(struct wg_pkt_response)) {
            fprintf(stderr, "unexpected packet type/size: type=%u len=%zd\n",
                    (unsigned)le32toh(t), n);
            return -1;
        }
    }

    {
        struct wg_pkt_response pkt;
        struct noise_remote *matched = NULL;
        int ret;

        memcpy(&pkt, buf, sizeof(pkt));
        ret = noise_consume_response(local, &matched, s_idx, pkt.r_idx, pkt.ue, pkt.en);
        if (ret != 0) {
            fprintf(stderr, "noise_consume_response failed: %d\n", ret);
            return -1;
        }

        if (matched != remote) {
            fprintf(stderr, "response matched unexpected peer\n");
            if (matched)
                noise_remote_put(matched);
            return -1;
        }

        if (matched)
            noise_remote_put(matched);
    }

    return 0;
}

static int send_keepalive_data(int udp_fd, struct noise_remote *remote)
{
    struct noise_keypair *kp;
    struct mbuf *m;
    uint64_t nonce;
    uint32_t r_idx;
    struct wg_pkt_data_hdr hdr;
    uint8_t out[256];
    size_t out_len;
    /* Keepalive: 0-byte plaintext padded to WG_PKT_PADDING (16) bytes of zeros.
     * See FreeBSD if_wg.c:calculate_padding — when plaintext len is 0, padlen
     * rounds up to 16. noise_keypair_encrypt will then append the 16-byte
     * Poly1305 tag, giving a 32-byte transport payload. */
    static const uint8_t zero_pad[WG_PKT_PADDING] = {0};

    kp = noise_keypair_current(remote);
    if (!kp) {
        fprintf(stderr, "no current keypair after handshake\n");
        return -1;
    }

    if (noise_keypair_nonce_next(kp, &nonce) != 0) {
        fprintf(stderr, "noise_keypair_nonce_next failed\n");
        noise_keypair_put(kp);
        return -1;
    }

    m = m_devget(zero_pad, WG_PKT_PADDING);
    if (!m) {
        fprintf(stderr, "m_devget failed\n");
        noise_keypair_put(kp);
        return -1;
    }

    if (noise_keypair_encrypt(kp, &r_idx, nonce, m) != 0) {
        fprintf(stderr, "noise_keypair_encrypt failed\n");
        m_freem(m);
        noise_keypair_put(kp);
        return -1;
    }

    hdr.t = WG_PKT_DATA;
    hdr.r_idx = r_idx;          /* opaque index, written on the wire verbatim (see if_wg.c:1599) */
    hdr.nonce = htole64(nonce);

    out_len = sizeof(hdr) + (size_t)m->m_len;
    if (out_len > sizeof(out)) {
        fprintf(stderr, "keepalive packet too large\n");
        m_freem(m);
        noise_keypair_put(kp);
        return -1;
    }

    memcpy(out, &hdr, sizeof(hdr));
    memcpy(out + sizeof(hdr), m->m_data, (size_t)m->m_len);

    if (send(udp_fd, out, out_len, 0) != (ssize_t)out_len) {
        perror("send keepalive");
        m_freem(m);
        noise_keypair_put(kp);
        return -1;
    }

    m_freem(m);
    noise_keypair_put(kp);
    return 0;
}

int main(int argc, char *argv[])
{
    const char *config_path = "test.ini";
    struct client_config cfg;
    struct noise_local *local = NULL;
    struct noise_remote *remote = NULL;
    struct cookie_maker cookie;
    int cookie_inited = 0;
    int udp_fd = -1;
    int ret = 1;
    int attempt;

    signal(SIGPIPE, SIG_IGN);

    if (argc > 1)
        config_path = argv[1];

    printf("[info] pkt sizes: initiation=%zu response=%zu\n",
           sizeof(struct wg_pkt_initiation), sizeof(struct wg_pkt_response));

    if (load_config(config_path, &cfg) != 0)
        return 1;

    if (crypto_init() != 0) {
        fprintf(stderr, "crypto_init failed\n");
        return 1;
    }

    local = noise_local_alloc(NULL);
    if (!local) {
        fprintf(stderr, "noise_local_alloc failed\n");
        goto out;
    }

    noise_local_private(local, cfg.private_key);

    remote = noise_remote_alloc(local, NULL, cfg.peer_public_key);
    if (!remote) {
        fprintf(stderr, "noise_remote_alloc failed\n");
        goto out;
    }

    if (noise_remote_enable(remote) != 0) {
        fprintf(stderr, "noise_remote_enable failed\n");
        goto out;
    }

    cookie_maker_init(&cookie, cfg.peer_public_key);
    cookie_inited = 1;

    udp_fd = udp_connect_endpoint(cfg.endpoint_host, cfg.endpoint_port);
    if (udp_fd < 0) {
        fprintf(stderr, "failed to connect udp endpoint %s:%u\n",
                cfg.endpoint_host, (unsigned)cfg.endpoint_port);
        goto out;
    }

    {
        struct timeval tv;
        tv.tv_sec = 3;
        tv.tv_usec = 0;
        if (setsockopt(udp_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0)
            perror("setsockopt SO_RCVTIMEO");
    }

    for (attempt = 1; attempt <= 5; ++attempt) {
        uint32_t s_idx = 0;
        int w;

        printf("[handshake] attempt %d\n", attempt);

        if (send_initiation(udp_fd, remote, &cookie, &s_idx) != 0) {
            sleep(REKEY_TIMEOUT_SEC);
            continue;
        }

        w = wait_for_response(udp_fd, local, remote, &cookie, s_idx);
        if (w == 0) {
            printf("[handshake] success\n");
            if (send_keepalive_data(udp_fd, remote) == 0)
                printf("[data] keepalive packet sent\n");
            ret = 0;
            break;
        }

        sleep(REKEY_TIMEOUT_SEC);
    }

    if (ret != 0)
        fprintf(stderr, "[handshake] failed after retries\n");

out:
    if (udp_fd >= 0)
        close(udp_fd);
    if (cookie_inited)
        cookie_maker_free(&cookie);
    if (remote)
        noise_remote_put(remote);
    if (local)
        noise_local_put(local);
    crypto_deinit();
    return ret;
}
