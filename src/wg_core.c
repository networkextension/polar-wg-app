#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sys_domain.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <unistd.h>

#include "macos_stubs/sys/mbuf.h"
#include "macos_stubs/sys/param.h"
#include "macos_stubs/sys/rwlock.h"
#include "macos_stubs/sys/mutex.h"
#include "allowedips.h"
#include "wg_cookie.h"
#include <libkern/OSByteOrder.h>
#ifndef htole32
#define htole32(x) OSSwapHostToLittleInt32(x)
#endif
#ifndef le32toh
#define le32toh(x) OSSwapLittleToHostInt32(x)
#endif
#ifndef htole64
#define htole64(x) OSSwapHostToLittleInt64(x)
#endif
#ifndef le64toh
#define le64toh(x) OSSwapLittleToHostInt64(x)
#endif

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

/* Protocol timers (RFC, also see wg_noise.h). All in seconds. */
#define REKEY_TIMEOUT_SEC      5    /* retransmit pending initiation */
#define REKEY_AFTER_TIME_SEC   120  /* trigger rekey */
#define REKEY_JITTER_MAX_SEC   30   /* random extra delay on rekey to
                                     * decorrelate two-sided initiators */
#define REJECT_AFTER_TIME_SEC  180  /* keypair becomes unusable */
#define KEEPALIVE_TIMEOUT_SEC  10
#define MAX_HANDSHAKE_ATTEMPTS 18   /* ~REJECT_AFTER_TIME / REKEY_TIMEOUT */

/* COOKIE_* sizes come from wg_cookie.h */

/* cookie_macs / cookie_maker / cookie_checker definitions and APIs come
 * from wg_cookie.h above. */

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
extern int noise_consume_initiation(struct noise_local *,
                                    struct noise_remote **,
                                    uint32_t s_idx,
                                    uint8_t ue[WG_KEY_LEN],
                                    uint8_t es[WG_KEY_LEN + WG_AUTHTAG_LEN],
                                    uint8_t ets[WG_TIMESTAMP_LEN + WG_AUTHTAG_LEN]);
extern int noise_create_response(struct noise_remote *,
                                 uint32_t *s_idx,
                                 uint32_t *r_idx,
                                 uint8_t ue[WG_KEY_LEN],
                                 uint8_t en[WG_AUTHTAG_LEN]);
extern int noise_consume_response(struct noise_local *,
                                  struct noise_remote **,
                                  uint32_t s_idx,
                                  uint32_t r_idx,
                                  uint8_t ue[WG_KEY_LEN],
                                  uint8_t en[WG_AUTHTAG_LEN]);
extern int noise_local_keys(struct noise_local *,
                            uint8_t public[WG_KEY_LEN],
                            uint8_t private[WG_KEY_LEN]);

#define NOISE_PUBLIC_KEY_LEN WG_KEY_LEN

extern struct noise_keypair *noise_keypair_current(struct noise_remote *);
extern struct noise_keypair *noise_keypair_lookup(struct noise_local *, uint32_t);
extern struct noise_remote  *noise_keypair_remote(struct noise_keypair *);
extern void                 *noise_remote_arg(struct noise_remote *);
extern int noise_keypair_nonce_next(struct noise_keypair *, uint64_t *);
extern int noise_keypair_encrypt(struct noise_keypair *, uint32_t *r_idx, uint64_t nonce, struct mbuf *);
extern int noise_keypair_decrypt(struct noise_keypair *, uint64_t nonce, struct mbuf *);
extern int noise_keypair_received_with(struct noise_keypair *);
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

#define WG_MAX_ALLOWED_CIDRS 16
#define WG_MAX_IFACE_ADDRS    4
#define WG_MAX_PEERS          64    /* mesh size cap. Each peer_state is
                                     * ~600 B, so 64 ≈ 40 KiB — fine. */

struct allowed_cidr {
    int     family;     /* AF_INET or AF_INET6 */
    uint8_t addr[16];   /* network order; only first 4 bytes used for AF_INET */
    int     prefix_len;
};

/* Parsed [Interface] Address. wg-quick supports comma-separated lists
 * with mixed v4/v6 (e.g. "10.88.0.2/24, fd00::2/64"). */
struct iface_addr {
    int  family;            /* AF_INET or AF_INET6 */
    char addr_str[64];      /* "10.88.0.2" or "fd00::2" — for ifconfig */
    int  prefix_len;
};

/* All per-peer state in one place. The noise_remote stores a pointer to
 * its peer_state via noise_remote_arg, so handlers like wg_decap can
 * recover it from a noise_keypair without walking the peer list. */
struct peer_state {
    /* Identity */
    uint8_t pubkey[WG_KEY_LEN];

    /* Endpoint (mutable; updated on roaming) */
    bool                     has_endpoint;
    char                     endpoint_host[128];   /* original spec, for display */
    uint16_t                 endpoint_port;
    struct sockaddr_storage  endpoint;
    socklen_t                endpoint_len;

    /* Allowed-IPs CIDRs */
    struct allowed_cidr  allowed[WG_MAX_ALLOWED_CIDRS];
    int                  n_allowed;

    /* Persistent keepalive (seconds; 0 = disabled) */
    int                  pk_sec;

    /* Noise / cookie state */
    struct noise_remote *remote;
    struct cookie_maker  cookie;
    bool                 cookie_inited;

    /* Handshake state machine (initiator side) */
    bool      hs_pending;
    time_t    hs_sent_at;
    uint32_t  hs_local_idx;
    int       hs_attempts;

    /* Keypair lifetime */
    time_t    keypair_birth;
    time_t    last_authd_tx;
    /* Random jitter added to REKEY_AFTER_TIME for THIS keypair, rerolled
     * on every keypair install. Keeps both peers in a two-initiator setup
     * from firing rekey at the exact same instant — the simultaneous-init
     * collision is "harmless but wasteful" (see tunnel_consume_initiation
     * comment), so we just lower its probability. */
    int       rekey_jitter_sec;

    /* Stats */
    uint64_t  tx_pkts, tx_bytes, rx_pkts, rx_bytes;
    uint64_t  rx_dropped_aips;
};

struct client_config {
    /* [Interface] */
    uint8_t  private_key[WG_KEY_LEN];
    uint16_t listen_port;           /* 0 = ephemeral */
    struct iface_addr if_addrs[WG_MAX_IFACE_ADDRS];
    int      n_if_addrs;

    /* [Peer] sections — at least one required */
    struct peer_state peers[WG_MAX_PEERS];
    int      n_peers;
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

/* Parse a single CIDR like "10.88.0.0/24" or "fd00::/64" or "10.88.0.2"
 * (bare addr defaults to /32 for v4, /128 for v6). Fills *out and returns
 * 0 on success, -1 on bad input. */
static int parse_cidr(const char *s, struct allowed_cidr *out)
{
    char tmp[64];
    char *slash;
    int prefix;

    if (strlen(s) >= sizeof(tmp)) return -1;
    strcpy(tmp, s);
    slash = strchr(tmp, '/');
    if (slash) {
        *slash = '\0';
        prefix = atoi(slash + 1);
    } else {
        prefix = -1;
    }

    memset(out->addr, 0, sizeof(out->addr));
    if (inet_pton(AF_INET, tmp, out->addr) == 1) {
        out->family = AF_INET;
        out->prefix_len = (prefix < 0) ? 32 : prefix;
        if (out->prefix_len < 0 || out->prefix_len > 32) return -1;
        return 0;
    }
    if (inet_pton(AF_INET6, tmp, out->addr) == 1) {
        out->family = AF_INET6;
        out->prefix_len = (prefix < 0) ? 128 : prefix;
        if (out->prefix_len < 0 || out->prefix_len > 128) return -1;
        return 0;
    }
    return -1;
}

/* Parse a single Interface Address entry like "10.88.0.2/24" or
 * "fd00::2/64". Stores into out as an iface_addr (string + prefix_len),
 * because the production user is /sbin/ifconfig and that wants the
 * canonical text form. Returns 0 on success, -1 on bad input. */
static int parse_iface_addr(const char *s, struct iface_addr *out)
{
    char tmp[64];
    char *slash;
    int prefix;
    uint8_t bin[16];

    if (strlen(s) >= sizeof(tmp)) return -1;
    strcpy(tmp, s);
    slash = strchr(tmp, '/');
    if (slash) {
        *slash = '\0';
        prefix = atoi(slash + 1);
    } else {
        prefix = -1;
    }
    if (inet_pton(AF_INET, tmp, bin) == 1) {
        out->family = AF_INET;
        out->prefix_len = (prefix < 0) ? 32 : prefix;
        if (out->prefix_len < 0 || out->prefix_len > 32) return -1;
    } else if (inet_pton(AF_INET6, tmp, bin) == 1) {
        out->family = AF_INET6;
        out->prefix_len = (prefix < 0) ? 128 : prefix;
        if (out->prefix_len < 0 || out->prefix_len > 128) return -1;
    } else {
        return -1;
    }
    strncpy(out->addr_str, tmp, sizeof(out->addr_str) - 1);
    out->addr_str[sizeof(out->addr_str) - 1] = '\0';
    return 0;
}

/* Parse a comma-separated list of Interface Address entries. */
static int parse_iface_addrs(const char *s, struct client_config *cfg)
{
    char buf[256];
    char *p, *save;

    if (strlen(s) >= sizeof(buf)) return -1;
    strcpy(buf, s);

    for (p = strtok_r(buf, ",", &save); p; p = strtok_r(NULL, ",", &save)) {
        while (*p == ' ' || *p == '\t') p++;
        char *end = p + strlen(p) - 1;
        while (end > p && (*end == ' ' || *end == '\t')) { *end = '\0'; end--; }
        if (!*p) continue;
        if (cfg->n_if_addrs >= WG_MAX_IFACE_ADDRS) {
            fprintf(stderr, "too many Interface Address entries (max %d)\n",
                    WG_MAX_IFACE_ADDRS);
            return -1;
        }
        if (parse_iface_addr(p, &cfg->if_addrs[cfg->n_if_addrs]) != 0) {
            fprintf(stderr, "invalid Address in [Interface]: %s\n", p);
            return -1;
        }
        cfg->n_if_addrs++;
    }
    return 0;
}

/* Parse a comma-separated list of CIDRs like "10.88.0.0/24, 10.99.0.0/16"
 * into peer->allowed[]. Returns the number of CIDRs added, or -1 on error. */
static int parse_allowed_ips(const char *s, struct peer_state *peer)
{
    char buf[512];
    char *p, *save;
    int added = 0;

    if (strlen(s) >= sizeof(buf)) return -1;
    strcpy(buf, s);

    for (p = strtok_r(buf, ",", &save); p; p = strtok_r(NULL, ",", &save)) {
        while (*p == ' ' || *p == '\t') p++;
        char *end = p + strlen(p) - 1;
        while (end > p && (*end == ' ' || *end == '\t')) { *end = '\0'; end--; }
        if (!*p) continue;
        if (peer->n_allowed >= WG_MAX_ALLOWED_CIDRS) {
            fprintf(stderr, "too many AllowedIPs entries (max %d)\n",
                    WG_MAX_ALLOWED_CIDRS);
            return -1;
        }
        if (parse_cidr(p, &peer->allowed[peer->n_allowed]) != 0) {
            fprintf(stderr, "invalid CIDR in AllowedIPs: %s\n", p);
            return -1;
        }
        peer->n_allowed++;
        added++;
    }
    return added;
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
    int cur_peer = -1;          /* index into cfg->peers[] for the
                                 * currently active [Peer] section */

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
            if (in_peer) {
                if (cfg->n_peers >= WG_MAX_PEERS) {
                    fprintf(stderr, "too many [Peer] sections (max %d)\n",
                            WG_MAX_PEERS);
                    fclose(f);
                    return -1;
                }
                cur_peer = cfg->n_peers++;
            }
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
        } else if (in_interface && strcmp(p, "ListenPort") == 0) {
            int lp = atoi(eq);
            if (lp < 1 || lp > 65535) {
                fprintf(stderr, "invalid ListenPort: %s\n", eq);
                fclose(f);
                return -1;
            }
            cfg->listen_port = (uint16_t)lp;
        } else if (in_interface && strcmp(p, "Address") == 0) {
            if (parse_iface_addrs(eq, cfg) != 0) {
                fclose(f);
                return -1;
            }
        } else if (in_peer && cur_peer >= 0) {
            struct peer_state *peer = &cfg->peers[cur_peer];
            if (strcmp(p, "PublicKey") == 0) {
                if (decode_base64_32(eq, peer->pubkey) != 0) {
                    fprintf(stderr, "invalid Peer PublicKey in config\n");
                    fclose(f);
                    return -1;
                }
            } else if (strcmp(p, "Endpoint") == 0) {
                if (split_endpoint(eq, peer->endpoint_host,
                                   &peer->endpoint_port) != 0) {
                    fprintf(stderr, "invalid Endpoint format, expected host:port\n");
                    fclose(f);
                    return -1;
                }
                peer->has_endpoint = true;
            } else if (strcmp(p, "PersistentKeepalive") == 0) {
                peer->pk_sec = atoi(eq);
            } else if (strcmp(p, "AllowedIPs") == 0) {
                if (parse_allowed_ips(eq, peer) < 0) {
                    fclose(f);
                    return -1;
                }
            }
        }
    }

    fclose(f);

    if (!got_priv) {
        fprintf(stderr, "config missing Interface.PrivateKey\n");
        return -1;
    }
    if (cfg->n_peers == 0) {
        fprintf(stderr, "config has no [Peer] section\n");
        return -1;
    }

    /* Validate each peer; reject the file as a whole if anything is
     * structurally broken. */
    int any_endpoint = 0;
    for (int i = 0; i < cfg->n_peers; i++) {
        struct peer_state *peer = &cfg->peers[i];
        int has_pub = 0;
        for (size_t j = 0; j < sizeof(peer->pubkey); j++) {
            if (peer->pubkey[j]) { has_pub = 1; break; }
        }
        if (!has_pub) {
            fprintf(stderr, "peer #%d missing PublicKey\n", i);
            return -1;
        }
        if (peer->has_endpoint) any_endpoint = 1;
    }
    if (!any_endpoint && cfg->listen_port == 0) {
        fprintf(stderr, "no peer has an Endpoint and no Interface.ListenPort — "
                        "nothing to do\n");
        return -1;
    }

    return 0;
}

/* Resolve host:port into a sockaddr we can sendto() repeatedly. Fills
 * *out_ss and returns 0 on success, -1 on failure. */
static int
resolve_endpoint(const char *host, uint16_t port,
                 struct sockaddr_storage *out_ss, socklen_t *out_len)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    char port_str[8];

    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(host, port_str, &hints, &res) != 0 || res == NULL) {
        fprintf(stderr, "getaddrinfo failed for %s:%s\n", host, port_str);
        return -1;
    }
    memcpy(out_ss, res->ai_addr, res->ai_addrlen);
    *out_len = res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}

/* Open an unconnected UDP socket bound to INADDR_ANY:listen_port.
 * Pass listen_port = 0 for an ephemeral port (initiator-only mode).
 * We deliberately do NOT connect(): using sendto/recvfrom lets us see
 * the actual source address of every inbound packet and supports
 * peer roaming + responder mode (multiple peers initiating to us).
 * Returns fd, or -1 on failure. */
static int
udp_open_unconnected(int family, uint16_t listen_port)
{
    int fd = socket(family, SOCK_DGRAM, 0);
    int one = 1;
    if (fd < 0) { perror("socket(udp)"); return -1; }
    (void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    if (family == AF_INET) {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family      = AF_INET;
        sin.sin_addr.s_addr = htonl(INADDR_ANY);
        sin.sin_port        = htons(listen_port);
        if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
            perror("bind(udp4)");
            close(fd); return -1;
        }
    } else {
        struct sockaddr_in6 sin6;
        memset(&sin6, 0, sizeof(sin6));
        sin6.sin6_family = AF_INET6;
        sin6.sin6_addr   = in6addr_any;
        sin6.sin6_port   = htons(listen_port);
        if (bind(fd, (struct sockaddr *)&sin6, sizeof(sin6)) < 0) {
            perror("bind(udp6)");
            close(fd); return -1;
        }
    }

    /* Dump the bound address for tcpdump correlation. */
    {
        struct sockaddr_storage ss;
        socklen_t sl = sizeof(ss);
        if (getsockname(fd, (struct sockaddr *)&ss, &sl) == 0) {
            char abuf[64]; uint16_t p = 0;
            if (ss.ss_family == AF_INET) {
                struct sockaddr_in *s = (struct sockaddr_in *)&ss;
                inet_ntop(AF_INET, &s->sin_addr, abuf, sizeof(abuf));
                p = ntohs(s->sin_port);
            } else {
                struct sockaddr_in6 *s = (struct sockaddr_in6 *)&ss;
                inet_ntop(AF_INET6, &s->sin6_addr, abuf, sizeof(abuf));
                p = ntohs(s->sin6_port);
            }
            fprintf(stderr, "[udp] bound local %s:%u (fd=%d)\n", abuf, p, fd);
        }
    }
    return fd;
}

static void
fmt_sockaddr(const struct sockaddr *sa, char *out, size_t out_len)
{
    char abuf[64] = {0};
    uint16_t port = 0;
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *s = (const struct sockaddr_in *)sa;
        inet_ntop(AF_INET, &s->sin_addr, abuf, sizeof(abuf));
        port = ntohs(s->sin_port);
    } else if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)sa;
        inet_ntop(AF_INET6, &s->sin6_addr, abuf, sizeof(abuf));
        port = ntohs(s->sin6_port);
    } else {
        snprintf(out, out_len, "<af=%d>", sa->sa_family);
        return;
    }
    snprintf(out, out_len, "%s:%u", abuf, port);
}

static int send_initiation(int udp_fd, struct peer_state *peer,
                           uint32_t *out_s_idx)
{
    struct wg_pkt_initiation pkt;
    int ret;

    if (peer->endpoint_len == 0) {
        fprintf(stderr, "send_initiation: peer has no endpoint\n");
        return -1;
    }

    memset(&pkt, 0, sizeof(pkt));
    pkt.t = WG_PKT_INITIATION;

    ret = noise_create_initiation(peer->remote, &pkt.s_idx, pkt.ue, pkt.es, pkt.ets);
    if (ret != 0) {
        fprintf(stderr, "noise_create_initiation failed: %d\n", ret);
        return -1;
    }

    cookie_maker_mac(&peer->cookie, &pkt.m, &pkt, sizeof(pkt) - sizeof(pkt.m));

    if (sendto(udp_fd, &pkt, sizeof(pkt), 0,
               (struct sockaddr *)&peer->endpoint, peer->endpoint_len)
        != (ssize_t)sizeof(pkt)) {
        perror("sendto initiation");
        return -1;
    }

    *out_s_idx = pkt.s_idx;
    return 0;
}

static int wait_for_response(int udp_fd,
                             struct noise_local *local,
                             struct peer_state *peer,
                             uint32_t expected_local_idx)
{
    uint8_t buf[2048];
    struct sockaddr_storage from_ss;
    socklen_t from_sl = sizeof(from_ss);
    ssize_t n;

    n = recvfrom(udp_fd, buf, sizeof(buf), 0,
                 (struct sockaddr *)&from_ss, &from_sl);
    if (n < 0) {
        perror("recvfrom");
        return -1;
    }
    {
        char addr_s[80];
        fmt_sockaddr((struct sockaddr *)&from_ss, addr_s, sizeof(addr_s));
        fprintf(stderr, "[handshake] recvfrom %s len=%zd\n", addr_s, n);
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
                if (cookie_maker_consume_payload(&peer->cookie, pkt.nonce, pkt.ec) == 0)
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

        /* Sanity: the response's r_idx must equal OUR initiation's s_idx. */
        if (pkt.r_idx != expected_local_idx) {
            fprintf(stderr,
                    "response r_idx 0x%08x != our initiation s_idx 0x%08x\n",
                    (unsigned)pkt.r_idx, (unsigned)expected_local_idx);
            return -1;
        }

        ret = noise_consume_response(local, &matched,
                                     pkt.s_idx, pkt.r_idx,
                                     pkt.ue, pkt.en);
        if (ret != 0) {
            fprintf(stderr, "noise_consume_response failed: %d\n", ret);
            return -1;
        }

        if (matched != peer->remote) {
            fprintf(stderr, "response matched unexpected peer\n");
            if (matched)
                noise_remote_put(matched);
            return -1;
        }

        noise_remote_put(matched);
    }

    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────
 * wg_encap / wg_decap: the core transport-packet helpers.
 *
 * wg_encap: take a plaintext inner IP packet (len bytes), pad to
 *   WG_PKT_PADDING, authenticate+encrypt with the current keypair, prepend
 *   a wg_pkt_data_hdr, and UDP-send. len = 0 gives a keepalive.
 *
 * wg_decap: take a raw UDP datagram that must start with WG_PKT_DATA,
 *   look up the keypair by r_idx, decrypt in-place, strip trailing zero
 *   padding down to the inner IP packet's real length, and hand back a
 *   pointer into the caller's buffer.
 * ───────────────────────────────────────────────────────────────────────── */

static int
wg_encap(int udp_fd, struct peer_state *peer,
         const uint8_t *plain, size_t plain_len)
{
    struct noise_keypair *kp = NULL;
    struct mbuf *m = NULL;
    uint64_t nonce;
    uint32_t r_idx;
    struct wg_pkt_data_hdr hdr;
    uint8_t out[2048];
    size_t padded_len;
    size_t out_len;
    uint8_t scratch[2048];
    int rc = -1;

    if (!peer || peer->endpoint_len == 0) {
        /* No known endpoint yet (responder mode awaiting first
         * initiation, or peer never roamed). Drop. */
        return -1;
    }

    /* Pad the plaintext up to WG_PKT_PADDING alignment. Keepalive (0-byte)
     * rounds up to exactly 16 zero bytes. See if_wg.c:calculate_padding. */
    padded_len = (plain_len + (WG_PKT_PADDING - 1)) & ~(size_t)(WG_PKT_PADDING - 1);
    if (padded_len == 0)
        padded_len = WG_PKT_PADDING;
    if (padded_len > sizeof(scratch)) {
        fprintf(stderr, "wg_encap: plaintext too large (%zu)\n", plain_len);
        return -1;
    }
    memset(scratch, 0, padded_len);
    if (plain_len)
        memcpy(scratch, plain, plain_len);

    kp = noise_keypair_current(peer->remote);
    if (!kp) {
        fprintf(stderr, "wg_encap: no current keypair for peer\n");
        return -1;
    }
    if (noise_keypair_nonce_next(kp, &nonce) != 0) {
        fprintf(stderr, "wg_encap: nonce_next failed\n");
        goto out;
    }

    m = m_devget(scratch, (int)padded_len);
    if (!m) {
        fprintf(stderr, "wg_encap: m_devget failed\n");
        goto out;
    }
    if (noise_keypair_encrypt(kp, &r_idx, nonce, m) != 0) {
        fprintf(stderr, "wg_encap: keypair_encrypt failed\n");
        goto out;
    }

    hdr.t = WG_PKT_DATA;
    hdr.r_idx = r_idx;          /* opaque wire index */
    hdr.nonce = htole64(nonce);

    out_len = sizeof(hdr) + (size_t)m->m_len;
    if (out_len > sizeof(out)) {
        fprintf(stderr, "wg_encap: frame too large (%zu)\n", out_len);
        goto out;
    }
    memcpy(out, &hdr, sizeof(hdr));
    memcpy(out + sizeof(hdr), m->m_data, (size_t)m->m_len);

    if (sendto(udp_fd, out, out_len, 0,
               (struct sockaddr *)&peer->endpoint, peer->endpoint_len)
        != (ssize_t)out_len) {
        perror("wg_encap: sendto");
        goto out;
    }
    rc = 0;
out:
    if (m)  m_freem(m);
    if (kp) noise_keypair_put(kp);
    return rc;
}

/* Inspect an IPv4/IPv6 header and return the *real* packet length, so we
 * can trim trailing WireGuard zero padding. Returns -1 if the packet is
 * malformed or too short to parse. */
static int inner_ip_len(const uint8_t *pkt, size_t cap)
{
    if (cap < 1) return -1;
    uint8_t version = pkt[0] >> 4;
    if (version == 4) {
        if (cap < 20) return -1;
        uint16_t total = ((uint16_t)pkt[2] << 8) | pkt[3]; /* IPv4 total length, network order */
        if (total < 20 || total > cap) return -1;
        return (int)total;
    } else if (version == 6) {
        if (cap < 40) return -1;
        uint16_t payload = ((uint16_t)pkt[4] << 8) | pkt[5];
        size_t total = (size_t)payload + 40;
        if (total > cap) return -1;
        return (int)total;
    }
    return -1;
}

/* Parse a received wg_pkt_data: decrypt in-place, figure out inner IP
 * length, and write the inner packet to the caller's out_pkt buffer.
 * On success, *out_peer is set to the peer_state that owns the keypair
 * used (recovered via noise_keypair_remote → noise_remote_arg).
 *
 * Returns the number of inner plaintext bytes written (>= 0 for data,
 * 0 for keepalive with no inner packet), or -1 on drop. */
static int
wg_decap(struct noise_local *local,
         const uint8_t *udp_pkt, size_t udp_len,
         uint8_t *out_pkt, size_t out_cap,
         struct peer_state **out_peer)
{
    struct wg_pkt_data_hdr hdr;
    struct noise_keypair *kp = NULL;
    struct mbuf *m = NULL;
    uint64_t nonce;
    int inner_len;
    int rc = -1;

    if (udp_len < sizeof(hdr) + WG_AUTHTAG_LEN) {
        fprintf(stderr, "wg_decap: short data packet (%zu)\n", udp_len);
        return -1;
    }
    memcpy(&hdr, udp_pkt, sizeof(hdr));
    if (hdr.t != WG_PKT_DATA) {
        fprintf(stderr, "wg_decap: wrong type 0x%08x\n", (unsigned)le32toh(hdr.t));
        return -1;
    }

    kp = noise_keypair_lookup(local, hdr.r_idx);
    if (!kp) {
        fprintf(stderr, "wg_decap: no keypair for r_idx=0x%08x\n",
                (unsigned)hdr.r_idx);
        return -1;
    }
    nonce = le64toh(hdr.nonce);

    m = m_devget(udp_pkt + sizeof(hdr), (int)(udp_len - sizeof(hdr)));
    if (!m) {
        fprintf(stderr, "wg_decap: m_devget failed\n");
        goto out;
    }
    if (noise_keypair_decrypt(kp, nonce, m) != 0) {
        fprintf(stderr, "wg_decap: decrypt failed (nonce=%llu)\n",
                (unsigned long long)nonce);
        goto out;
    }
    /* Promote the keypair to current on first successful recv, per
     * FreeBSD if_wg.c handling of noise_keypair_received_with. */
    (void)noise_keypair_received_with(kp);

    /* Recover the peer that owns this keypair so the caller can do
     * anti-spoofing and update its per-peer stats. */
    if (out_peer) {
        struct noise_remote *r = noise_keypair_remote(kp);
        *out_peer = r ? (struct peer_state *)noise_remote_arg(r) : NULL;
        if (r) noise_remote_put(r);
    }

    /* Decrypted plaintext sits in m->m_data, length m->m_len. This
     * includes zero padding up to WG_PKT_PADDING. m->m_len == 0 means
     * a valid authenticated keepalive (no inner packet). */
    if (m->m_len == 0) {
        rc = 0;
        goto out;
    }

    inner_len = inner_ip_len(m->m_data, (size_t)m->m_len);
    if (inner_len < 0) {
        fprintf(stderr, "wg_decap: cannot parse inner IP header (len=%d)\n",
                m->m_len);
        goto out;
    }
    if ((size_t)inner_len > out_cap) {
        fprintf(stderr, "wg_decap: inner packet too big for out buffer (%d)\n",
                inner_len);
        goto out;
    }
    memcpy(out_pkt, m->m_data, (size_t)inner_len);
    rc = inner_len;
out:
    if (m)  m_freem(m);
    if (kp) noise_keypair_put(kp);
    return rc;
}

/* ─────────────────────────────────────────────────────────────────────────
 * utun setup. On macOS a tunnel interface is a kernel control socket on
 * PF_SYSTEM with sc_id from com.apple.net.utun_control. Packets carry a
 * 4-byte "protocol family" header (AF_INET / AF_INET6) before the IP
 * payload — we strip it on read and prepend it on write.
 * ───────────────────────────────────────────────────────────────────────── */

static int
utun_open(char ifname[IFNAMSIZ])
{
    struct ctl_info ci;
    struct sockaddr_ctl sc;
    int fd;
    socklen_t name_len = IFNAMSIZ;

    fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) {
        perror("socket(PF_SYSTEM)");
        return -1;
    }
    memset(&ci, 0, sizeof(ci));
    strncpy(ci.ctl_name, UTUN_CONTROL_NAME, sizeof(ci.ctl_name));
    if (ioctl(fd, CTLIOCGINFO, &ci) < 0) {
        perror("ioctl CTLIOCGINFO");
        close(fd);
        return -1;
    }

    memset(&sc, 0, sizeof(sc));
    sc.sc_len      = sizeof(sc);
    sc.sc_family   = AF_SYSTEM;
    sc.ss_sysaddr  = AF_SYS_CONTROL;
    sc.sc_id       = ci.ctl_id;
    sc.sc_unit     = 0;  /* 0 = kernel picks next free utunN */

    if (connect(fd, (struct sockaddr *)&sc, sizeof(sc)) < 0) {
        perror("connect(utun)");
        close(fd);
        return -1;
    }

    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &name_len) < 0) {
        perror("getsockopt UTUN_OPT_IFNAME");
        close(fd);
        return -1;
    }

    return fd;
}

/* Read a plaintext IP packet from utun. Strips the leading 4-byte
 * AF_INET/AF_INET6 header. Returns IP-packet length, or -1 on error. */
static int
utun_read(int fd, uint8_t *out, size_t out_cap)
{
    uint8_t buf[4 + 2048];
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n < 4) {
        if (n < 0) perror("utun read");
        return -1;
    }
    size_t ip_len = (size_t)(n - 4);
    if (ip_len > out_cap) return -1;
    memcpy(out, buf + 4, ip_len);
    return (int)ip_len;
}

/* Write a plaintext IP packet to utun, prepending the 4-byte protocol
 * family header (big-endian AF_INET or AF_INET6). */
static int
utun_write(int fd, const uint8_t *pkt, size_t len)
{
    uint8_t hdr[4] = {0};
    struct iovec iov[2];
    uint32_t family;

    if (len < 1) return -1;
    family = ((pkt[0] >> 4) == 6) ? AF_INET6 : AF_INET;
    /* utun wants family in host byte order of a 32-bit int written in
     * network byte order. Apple's convention is: four bytes, big-endian
     * representation of the AF_* constant. */
    hdr[0] = (uint8_t)((family >> 24) & 0xff);
    hdr[1] = (uint8_t)((family >> 16) & 0xff);
    hdr[2] = (uint8_t)((family >>  8) & 0xff);
    hdr[3] = (uint8_t)( family        & 0xff);

    iov[0].iov_base = hdr;
    iov[0].iov_len  = 4;
    iov[1].iov_base = (void *)(uintptr_t)pkt;
    iov[1].iov_len  = len;

    ssize_t n = writev(fd, iov, 2);
    if (n < 0) { perror("utun writev"); return -1; }
    return 0;
}

/* Apply a single IPv4 Address entry to the utun. Idempotent: clears
 * any pre-existing route for the same /N before adding ours, so a
 * second wg_core (same Address, different iface unit after kickstart)
 * doesn't silently leave the kernel pointing at a dead utun. */
static int
utun_apply_inet4(const char *ifname, const struct iface_addr *a)
{
    char cmd[256];

    snprintf(cmd, sizeof(cmd),
             "/sbin/ifconfig %s inet %s %s mtu 1420 up",
             ifname, a->addr_str, a->addr_str);
    if (system(cmd) != 0) {
        fprintf(stderr, "utun_configure: '%s' failed\n", cmd);
        return -1;
    }
    if (a->prefix_len < 32) {
        uint32_t mask = a->prefix_len == 0 ? 0
                                            : (0xFFFFFFFFu << (32 - a->prefix_len));
        struct in_addr addr;
        if (inet_pton(AF_INET, a->addr_str, &addr) != 1)
            return -1;
        addr.s_addr &= htonl(mask);
        char net[64];
        inet_ntop(AF_INET, &addr, net, sizeof(net));
        /* Delete first (silent if nothing was there), then add. macOS
         * `route add` returns failure with "File exists" when a route
         * for that prefix is already installed against a dead utun —
         * which is exactly what we see across launchctl kickstart -k
         * cycles. */
        snprintf(cmd, sizeof(cmd),
                 "/sbin/route -q -n delete -net %s/%d >/dev/null 2>&1",
                 net, a->prefix_len);
        (void)system(cmd);
        snprintf(cmd, sizeof(cmd),
                 "/sbin/route -q -n add -net %s/%d -interface %s",
                 net, a->prefix_len, ifname);
        if (system(cmd) != 0)
            fprintf(stderr, "utun_configure: v4 route add failed (continuing)\n");
    }
    return 0;
}

/* Apply a single IPv6 Address entry to the utun. macOS utun supports
 * inet6 aliasing — the link-local fe80:: addr is added by the kernel
 * automatically when the interface comes up; we add the configured
 * global address on top. */
static int
utun_apply_inet6(const char *ifname, const struct iface_addr *a)
{
    char cmd[256];

    snprintf(cmd, sizeof(cmd),
             "/sbin/ifconfig %s inet6 %s prefixlen %d alias",
             ifname, a->addr_str, a->prefix_len);
    if (system(cmd) != 0) {
        fprintf(stderr, "utun_configure: '%s' failed\n", cmd);
        return -1;
    }
    /* On macOS, adding the inet6 alias also installs the prefix route
     * automatically (unlike v4 where we have to add it ourselves), so
     * no separate `route add -inet6` is needed for the common case. */
    return 0;
}

/* Install a route for every peer's AllowedIPs so matching packets enter the
 * tunnel — the wg-quick "Table=auto" behaviour. Routing follows AllowedIPs,
 * NOT the interface Address prefix, so a /32 [Interface] Address no longer
 * isolates the host: the hub peer's 10.88.0.0/24 (and per-peer /32 host
 * routes) still get installed. Default routes (0.0.0.0/0, ::/0) are skipped —
 * full-tunnel needs endpoint-preserving route surgery we don't implement, and
 * the mesh use case never advertises them. Best-effort: a failed route add is
 * logged and skipped (delete-first makes it idempotent across kickstarts). */
static void
utun_apply_peer_routes(const char *ifname, const struct client_config *cfg)
{
    char cmd[256], net[INET6_ADDRSTRLEN];
    for (int i = 0; i < cfg->n_peers; i++) {
        const struct peer_state *peer = &cfg->peers[i];
        for (int j = 0; j < peer->n_allowed; j++) {
            const struct allowed_cidr *c = &peer->allowed[j];
            if (c->prefix_len == 0)
                continue;                   /* skip 0.0.0.0/0 and ::/0 */
            if (c->family == AF_INET) {
                struct in_addr a;
                memcpy(&a, c->addr, 4);
                uint32_t mask = c->prefix_len >= 32 ? 0xFFFFFFFFu
                              : htonl(0xFFFFFFFFu << (32 - c->prefix_len));
                a.s_addr &= mask;           /* parse_cidr stores raw addr */
                if (!inet_ntop(AF_INET, &a, net, sizeof(net))) continue;
                snprintf(cmd, sizeof(cmd),
                         "/sbin/route -q -n delete -net %s/%d >/dev/null 2>&1",
                         net, c->prefix_len);
                (void)system(cmd);
                snprintf(cmd, sizeof(cmd),
                         "/sbin/route -q -n add -net %s/%d -interface %s",
                         net, c->prefix_len, ifname);
                if (system(cmd) != 0)
                    fprintf(stderr,
                            "utun_configure: route add %s/%d failed (continuing)\n",
                            net, c->prefix_len);
            } else if (c->family == AF_INET6) {
                if (!inet_ntop(AF_INET6, c->addr, net, sizeof(net))) continue;
                snprintf(cmd, sizeof(cmd),
                         "/sbin/route -q -n delete -inet6 %s/%d >/dev/null 2>&1",
                         net, c->prefix_len);
                (void)system(cmd);
                snprintf(cmd, sizeof(cmd),
                         "/sbin/route -q -n add -inet6 %s/%d -interface %s",
                         net, c->prefix_len, ifname);
                if (system(cmd) != 0)
                    fprintf(stderr,
                            "utun_configure: route6 add %s/%d failed (continuing)\n",
                            net, c->prefix_len);
            }
        }
    }
}

/* Run /etc/wireguard/<logical>.postup if executable, passing the logical
 * iface name, conf path, and the live utun unit. This is the wg-quick
 * `PostUp = …` hook — script-level safety net for the route-loss case
 * (macOS occasionally flushes utun routes on sleep/wake or primary
 * interface flip; the default postup re-installs the AllowedIPs routes
 * idempotently). No-op if the file doesn't exist or isn't executable.
 *
 * Forked, not exec'd: wg_core stays in the foreground for launchd's
 * KeepAlive. Briefly waits on the child so logs are sequenced — 5 s
 * cap, then continues (no postup script should take longer). */
static void
run_postup_hook(const char *logical, const char *conf_path, const char *utun_name)
{
    char hook[256];
    if (!logical || !*logical) return;
    snprintf(hook, sizeof(hook), "/etc/wireguard/%s.postup", logical);
    if (access(hook, X_OK) != 0)
        return;                              /* hook not installed → no-op */

    pid_t pid = fork();
    if (pid == 0) {
        /* child: replace into the hook. Args: <iface> <conf> <utun> */
        execl(hook, hook, logical,
              conf_path ? conf_path : "",
              utun_name ? utun_name : "",
              (char *)NULL);
        fprintf(stderr, "[postup] execl %s: %s\n", hook, strerror(errno));
        _exit(127);
    } else if (pid < 0) {
        fprintf(stderr, "[postup] fork: %s\n", strerror(errno));
        return;
    }
    /* parent: wait up to ~5 s, then move on. */
    for (int i = 0; i < 50; i++) {
        int status = 0;
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) {
            if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
                fprintf(stderr, "[postup] %s exited %d\n",
                        hook, WEXITSTATUS(status));
            return;
        }
        if (r < 0 && errno != EINTR) {
            fprintf(stderr, "[postup] waitpid: %s\n", strerror(errno));
            return;
        }
        struct timespec ts = {0, 100000000L};   /* 100 ms */
        nanosleep(&ts, NULL);
    }
    fprintf(stderr, "[postup] %s still running after 5s; detaching\n", hook);
}

/* Bring the utun up and apply all parsed Address entries. */
static int
utun_configure(const char *ifname, const struct client_config *cfg)
{
    if (cfg->n_if_addrs == 0) {
        fprintf(stderr, "utun_configure: no Address in [Interface]\n");
        return -1;
    }
    int v4_done = 0;
    for (int i = 0; i < cfg->n_if_addrs; i++) {
        const struct iface_addr *a = &cfg->if_addrs[i];
        if (a->family == AF_INET) {
            if (utun_apply_inet4(ifname, a) != 0) return -1;
            v4_done = 1;
        } else if (a->family == AF_INET6) {
            if (utun_apply_inet6(ifname, a) != 0) return -1;
        }
    }
    /* If only v6 was configured, the interface still needs `up`. */
    if (!v4_done) {
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "/sbin/ifconfig %s mtu 1420 up", ifname);
        (void)system(cmd);
    }
    /* Routes follow AllowedIPs (wg-quick Table=auto), independent of the
     * interface Address prefix — so the mesh stays reachable even on /32. */
    utun_apply_peer_routes(ifname, cfg);
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────
 * run_tunnel: after a successful handshake, enter the select() event
 * loop and forward packets between utun_fd and udp_fd in both directions.
 *
 * Terminates on SIGINT/SIGTERM (sig_quit is set from a handler).
 * ───────────────────────────────────────────────────────────────────────── */

static volatile sig_atomic_t sig_quit = 0;
static void on_quit(int s) { (void)s; sig_quit = 1; }

/* Set by SIGINFO (Ctrl-T on macOS / BSD). The select loop checks this
 * flag every iteration and prints a wg-show-style snapshot when set. */
static volatile sig_atomic_t sig_info = 0;
static void on_info(int s) { (void)s; sig_info = 1; }

/* Trace first N packets in each direction. Set WG_TRACE=N in the env to
 * raise the cap; 0 disables, default is 12 which is enough to see the
 * first ping echo round-trip without swamping the terminal. */
static int g_trace_cap = 12;
static int g_trace_tx  = 0;
static int g_trace_rx  = 0;

static void trace_hex(const char *tag, const uint8_t *b, size_t n)
{
    fprintf(stderr, "  %s:", tag);
    size_t max = n < 32 ? n : 32;
    for (size_t i = 0; i < max; i++) fprintf(stderr, " %02x", b[i]);
    if (n > max) fprintf(stderr, " ... (%zu bytes)", n);
    fprintf(stderr, "\n");
}

/* Bundle of two tries (v4 + v6) so we can pass a single pointer around. */
struct aips_set {
    struct aips_trie v4;
    struct aips_trie v6;
};

/* (build_aips_set was removed; main builds the shared multi-peer trie
 * inline now that each peer carries its own CIDR list.) */

/* Look up the inner src IP of a freshly decrypted packet against the
 * peer's allowed-ips. Returns the matched peer pointer, or NULL if the
 * inner src is not allowed. Used as the receive-side anti-spoofing
 * check (RFC: "the receiver verifies that the source address of the
 * inner packet matches one of the AllowedIPs of the peer that sent
 * it"). */
static void *
aips_lookup_inner_src(const struct aips_set *set,
                      const uint8_t *inner, size_t len)
{
    if (len < 1) return NULL;
    int ver = inner[0] >> 4;
    if (ver == 4) {
        if (len < 20) return NULL;
        return aips_lookup(&set->v4, inner + 12);   /* IPv4 src offset 12 */
    }
    if (ver == 6) {
        if (len < 40) return NULL;
        return aips_lookup(&set->v6, inner + 8);    /* IPv6 src offset 8  */
    }
    return NULL;
}

/* ─────────────────────────────────────────────────────────────────────────
 * Tunnel state machine
 *
 * The tunnel loop is driven by select() with a 1 s tick, and a tunnel_ctx
 * struct that owns the long-running noise/timer state. Each tick we:
 *
 *   1. retransmit a pending handshake initiation if it has been
 *      REKEY_TIMEOUT_SEC seconds since the last attempt;
 *   2. start a fresh handshake if the current keypair is REKEY_AFTER_TIME
 *      old and we are not already trying;
 *   3. send a persistent-keepalive if pk_sec > 0 and we have not sent
 *      anything to the peer for that long.
 *
 * On UDP recv, the handler dispatches by message type: DATA goes through
 * wg_decap; RESPONSE consumes the handshake and clears hs_pending; COOKIE
 * is fed to the cookie maker; anything else is logged and dropped.
 * ───────────────────────────────────────────────────────────────────────── */
typedef struct {
    /* I/O */
    int udp_fd;
    int utun_fd;
    char if_name[IFNAMSIZ];

    /* Logical name (e.g. "wg0") for /var/run/wireguard/<name>.{pid,name,sock}.
     * Empty string means: no PID/socket files written, no IPC server. */
    char logical_name[32];

    /* Status-query UNIX socket (SOCK_STREAM, listening). -1 if disabled. */
    int status_listen_fd;

    /* Shared (per-local) state */
    struct noise_local    *local;
    struct cookie_checker *cookie_checker;

    /* Allowed-IPs trie spanning ALL peers. Each CIDR maps to its own
     * peer_state*. Encap looks up dst → peer; decap verifies inner
     * src belongs to the peer that just authenticated the packet. */
    const struct aips_set *aips;

    /* Peer list (owned by client_config; we only borrow). */
    struct peer_state *peers;
    int                n_peers;
} tunnel_ctx;

/* Encode 32 bytes into the standard 44-character WireGuard base64 form.
 * out must have room for at least 45 chars including NUL. */
static void
b64_encode_32(char out[45], const uint8_t in[32])
{
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int oi = 0;
    /* 32 bytes / 3 = 10 full triplets + 2 leftover bytes */
    for (int i = 0; i < 30; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8) | in[i+2];
        out[oi++] = tbl[(v >> 18) & 0x3f];
        out[oi++] = tbl[(v >> 12) & 0x3f];
        out[oi++] = tbl[(v >>  6) & 0x3f];
        out[oi++] = tbl[ v        & 0x3f];
    }
    /* Last 2 bytes: 16 bits → 3 base64 chars + '=' pad */
    uint32_t v = ((uint32_t)in[30] << 16) | ((uint32_t)in[31] << 8);
    out[oi++] = tbl[(v >> 18) & 0x3f];
    out[oi++] = tbl[(v >> 12) & 0x3f];
    out[oi++] = tbl[(v >>  6) & 0x3f];
    out[oi++] = '=';
    out[oi]   = '\0';
}

/* Format a single CIDR like "10.88.0.0/24" into a caller-supplied buffer. */
static void
fmt_cidr(const struct allowed_cidr *c, char *out, size_t out_len)
{
    char addr_buf[INET6_ADDRSTRLEN];
    const char *p = inet_ntop(c->family, c->addr, addr_buf, sizeof(addr_buf));
    if (!p) p = "?";
    snprintf(out, out_len, "%s/%d", p, c->prefix_len);
}

/* Print a wg-show-style status snapshot of a single peer's tunnel state.
 * Output is meant to look familiar to anyone who has used the wg(8) tool:
 *
 *   interface: utun7
 *     peer pubkey: XXFzbjDln02y/aWfo2RFVZ/foiMC/NEo9QKXDdk9SXk=
 *     endpoint: 172.16.203.128:51820
 *     allowed ips: 0.0.0.0/0
 *     latest handshake: 14 seconds ago
 *     transfer: 1.4 KiB received, 1.2 KiB sent
 *     persistent keepalive: every 25 seconds
 *     anti-spoofing drops: 0
 *     handshake state: idle (kp_age=14s)
 */
static void
fmt_human_bytes(uint64_t b, char *out, size_t out_len)
{
    if (b < 1024)              snprintf(out, out_len, "%llu B",   (unsigned long long)b);
    else if (b < 1024ull*1024) snprintf(out, out_len, "%.2f KiB", (double)b / 1024.0);
    else if (b < 1024ull*1024*1024) snprintf(out, out_len, "%.2f MiB", (double)b / (1024.0*1024.0));
    else                       snprintf(out, out_len, "%.2f GiB", (double)b / (1024.0*1024.0*1024.0));
}

static void
fmt_human_age(time_t age_sec, char *out, size_t out_len)
{
    if (age_sec < 0)              snprintf(out, out_len, "never");
    else if (age_sec < 60)        snprintf(out, out_len, "%lld seconds ago", (long long)age_sec);
    else if (age_sec < 3600)      snprintf(out, out_len, "%lld minutes, %lld seconds ago",
                                           (long long)(age_sec / 60), (long long)(age_sec % 60));
    else                          snprintf(out, out_len, "%lld hours, %lld minutes ago",
                                           (long long)(age_sec / 3600),
                                           (long long)((age_sec % 3600) / 60));
}

static void
dump_status_snapshot(const tunnel_ctx *ctx, FILE *out)
{
    time_t now = time(NULL);

    fprintf(out, "interface: %s\n", ctx->if_name[0] ? ctx->if_name : "(unknown)");
    if (ctx->logical_name[0])
        fprintf(out, "  logical: %s\n", ctx->logical_name);
    fprintf(out, "  peers: %d\n", ctx->n_peers);
    fprintf(out, "\n");

    for (int i = 0; i < ctx->n_peers; i++) {
        const struct peer_state *peer = &ctx->peers[i];
        char pub_b64[45]  = "?";
        char endpoint[80] = "(none)";
        char rx_h[32], tx_h[32];
        char hs_age[64];

        b64_encode_32(pub_b64, peer->pubkey);
        if (peer->endpoint_len)
            fmt_sockaddr((const struct sockaddr *)&peer->endpoint,
                         endpoint, sizeof(endpoint));
        fmt_human_bytes(peer->rx_bytes, rx_h, sizeof(rx_h));
        fmt_human_bytes(peer->tx_bytes, tx_h, sizeof(tx_h));
        fmt_human_age(peer->keypair_birth ? (now - peer->keypair_birth) : -1,
                      hs_age, sizeof(hs_age));

        fprintf(out, "peer #%d: %s\n", i, pub_b64);
        fprintf(out, "  endpoint: %s\n", endpoint);
        if (peer->n_allowed > 0) {
            fprintf(out, "  allowed ips: ");
            for (int j = 0; j < peer->n_allowed; j++) {
                char buf[64];
                fmt_cidr(&peer->allowed[j], buf, sizeof(buf));
                fprintf(out, "%s%s", buf,
                        (j + 1 < peer->n_allowed) ? ", " : "\n");
            }
        } else {
            fprintf(out, "  allowed ips: (none)\n");
        }
        fprintf(out, "  latest handshake: %s\n", hs_age);
        fprintf(out, "  transfer: %s received, %s sent\n", rx_h, tx_h);
        fprintf(out, "  packets: rx=%llu tx=%llu  rx_dropped_aips=%llu\n",
                (unsigned long long)peer->rx_pkts,
                (unsigned long long)peer->tx_pkts,
                (unsigned long long)peer->rx_dropped_aips);
        if (peer->pk_sec > 0)
            fprintf(out, "  persistent keepalive: every %d seconds\n",
                    peer->pk_sec);
        fprintf(out, "  handshake state: %s",
                peer->hs_pending ? "pending" : "idle");
        if (peer->hs_pending)
            fprintf(out, " (attempt %d, sent %lds ago)",
                    peer->hs_attempts, (long)(now - peer->hs_sent_at));
        fprintf(out, "\n\n");
    }
}

static void
print_status_snapshot(const tunnel_ctx *ctx)
{
    fprintf(stderr, "\n");
    dump_status_snapshot(ctx, stderr);
}

/* Send a fresh handshake initiation for a specific peer. Used for both
 * the startup initiation and for retransmits / rekey from tunnel_tick. */
static int
tunnel_send_initiation(tunnel_ctx *ctx, struct peer_state *peer,
                       time_t now, const char *why)
{
    uint32_t s_idx = 0;
    if (send_initiation(ctx->udp_fd, peer, &s_idx) != 0) {
        fprintf(stderr, "[hs] %s: send_initiation failed\n", why);
        return -1;
    }
    peer->hs_pending   = true;
    peer->hs_sent_at   = now;
    peer->hs_local_idx = s_idx;
    peer->hs_attempts++;
    peer->last_authd_tx = now;
    fprintf(stderr, "[hs] %s: initiation sent (attempt %d, s_idx=0x%08x)\n",
            why, peer->hs_attempts, (unsigned)s_idx);
    return 0;
}

/* Stamp keypair_birth + last_authd_tx + a fresh jitter, in one place so
 * the three call sites (responder install, initiator install, probe-mode
 * install) can't drift apart. */
static void
peer_stamp_keypair(struct peer_state *peer, time_t now)
{
    peer->keypair_birth     = now;
    peer->last_authd_tx     = now;
    peer->rekey_jitter_sec  = (int)arc4random_uniform(REKEY_JITTER_MAX_SEC);
}

/* Per-tick housekeeping for ONE peer. */
static void
tunnel_tick_peer(tunnel_ctx *ctx, struct peer_state *peer, time_t now)
{
    /* 1. Pending handshake retransmit. Back off BEFORE trying, so even
     * if noise_create_initiation fails, we wait a full REKEY_TIMEOUT
     * before the next attempt instead of hammering every tick. */
    if (peer->hs_pending && (now - peer->hs_sent_at) >= REKEY_TIMEOUT_SEC) {
        peer->hs_sent_at = now;
        if (peer->hs_attempts >= MAX_HANDSHAKE_ATTEMPTS) {
            fprintf(stderr, "[hs] giving up after %d attempts\n", peer->hs_attempts);
            peer->hs_pending  = false;
            peer->hs_attempts = 0;
        } else {
            (void)tunnel_send_initiation(ctx, peer, now, "retransmit");
        }
    }

    /* 2. Initial / rekey handshake.
     *    has_endpoint == false → pure responder, never initiate.
     *    keypair_birth == 0    → never handshaked yet, send initial NOW.
     *    keypair_birth > 0     → send rekey at REKEY_AFTER_TIME + jitter.
     *
     *    Using has_endpoint (configured) instead of endpoint_len > 0
     *    (runtime) keeps a pure-responder peer that has learned an
     *    endpoint from inbound traffic from also initiating, which would
     *    produce simultaneous-init races at every REKEY_AFTER_TIME
     *    boundary. The jitter further decorrelates two-initiator setups. */
    if (!peer->hs_pending && peer->has_endpoint) {
        bool needs_initial = (peer->keypair_birth == 0);
        bool needs_rekey   = (peer->keypair_birth > 0 &&
                              (now - peer->keypair_birth) >=
                                  (REKEY_AFTER_TIME_SEC + peer->rekey_jitter_sec));
        if (needs_initial || needs_rekey) {
            peer->hs_attempts = 0;
            (void)tunnel_send_initiation(ctx, peer, now,
                                          needs_initial ? "initial" : "rekey");
        }
    }

    /* 3. Persistent keepalive. */
    if (peer->pk_sec > 0 && peer->last_authd_tx > 0 &&
        (now - peer->last_authd_tx) >= peer->pk_sec) {
        if (wg_encap(ctx->udp_fd, peer, NULL, 0) == 0) {
            peer->last_authd_tx = now;
            fprintf(stderr, "[pk] sent persistent keepalive\n");
        }
    }
}

static void
tunnel_tick(tunnel_ctx *ctx, time_t now)
{
    for (int i = 0; i < ctx->n_peers; i++)
        tunnel_tick_peer(ctx, &ctx->peers[i], now);
}

/* Consume a WG_PKT_INITIATION received during the tunnel loop (the
 * responder path). Validates mac1 via cookie_checker, runs the noise
 * handshake to install a new keypair, sends back a WG_PKT_RESPONSE
 * MAC'd with our cookie_maker, and stamps a fresh keypair_birth so
 * the timer logic treats this as a brand-new session. Returns 0 on
 * success, -1 on drop. */
static int
tunnel_consume_initiation(tunnel_ctx *ctx,
                          uint8_t *buf, size_t len,
                          const struct sockaddr *from, socklen_t from_len)
{
    struct wg_pkt_initiation pkt;
    struct noise_remote *matched = NULL;
    struct peer_state   *peer    = NULL;
    int ret;

    if (len < sizeof(pkt)) return -1;
    memcpy(&pkt, buf, sizeof(pkt));

    if (!ctx->cookie_checker) {
        fprintf(stderr, "[hs] inbound initiation but no cookie_checker; dropping\n");
        return -1;
    }

    ret = cookie_checker_validate_macs(ctx->cookie_checker, &pkt.m,
                                       buf, sizeof(pkt) - sizeof(pkt.m),
                                       false /* under_load */,
                                       (struct sockaddr *)from, NULL);
    if (ret != 0) {
        fprintf(stderr, "[hs] initiation mac1 validation failed: %d\n", ret);
        return -1;
    }

    if (noise_consume_initiation(ctx->local, &matched,
                                 pkt.s_idx, pkt.ue, pkt.es, pkt.ets) != 0) {
        fprintf(stderr, "[hs] noise_consume_initiation failed\n");
        return -1;
    }
    /* Recover the peer_state pointer from the matched noise_remote. */
    peer = (struct peer_state *)noise_remote_arg(matched);
    if (!peer) {
        fprintf(stderr, "[hs] matched remote has no peer_state arg\n");
        noise_remote_put(matched);
        return -1;
    }

    /* Send back the response. */
    {
        struct wg_pkt_response resp;
        memset(&resp, 0, sizeof(resp));
        if (noise_create_response(matched, &resp.s_idx, &resp.r_idx,
                                  resp.ue, resp.en) != 0) {
            fprintf(stderr, "[hs] noise_create_response failed\n");
            noise_remote_put(matched);
            return -1;
        }
        resp.t = WG_PKT_RESPONSE;
        cookie_maker_mac(&peer->cookie, &resp.m, &resp,
                         sizeof(resp) - sizeof(resp.m));
        if (sendto(ctx->udp_fd, &resp, sizeof(resp), 0, from, from_len)
            != (ssize_t)sizeof(resp)) {
            perror("[hs] sendto response");
            noise_remote_put(matched);
            return -1;
        }
    }
    noise_remote_put(matched);

    /* Update peer addr (roaming on initiation) and stamp new keypair.
     * NOTE: do NOT clear peer->hs_pending here. In a two-initiator setup,
     * if our own initiation crosses the wire with peer's initiation, the
     * peer's response to OUR initiation is still in flight. Clearing
     * hs_pending makes find_peer_pending_response() reject that response
     * with "no matching pending peer", causing 5-second handshake stalls
     * on every collision. Leaving hs_pending=true means our own retransmit
     * timer keeps ticking until either (a) peer's response lands and we
     * clear it via tunnel_consume_response, or (b) we time out and
     * retransmit — both are harmless because peer already installed a
     * keypair from this initiation we just processed. */
    memcpy(&peer->endpoint, from, from_len);
    peer->endpoint_len = from_len;
    peer_stamp_keypair(peer, time(NULL));
    fprintf(stderr, "[hs] responded to incoming initiation, keypair installed\n");
    return 0;
}

/* Find the peer_state in our list whose hs_local_idx matches the given
 * value. Used to attribute an incoming WG_PKT_RESPONSE to the right peer.
 * Returns NULL if no peer is currently waiting on that index. */
static struct peer_state *
find_peer_pending_response(tunnel_ctx *ctx, uint32_t r_idx)
{
    for (int i = 0; i < ctx->n_peers; i++) {
        struct peer_state *p = &ctx->peers[i];
        if (p->hs_pending && p->hs_local_idx == r_idx)
            return p;
    }
    return NULL;
}

/* Consume a WG_PKT_RESPONSE received during the tunnel loop. */
static int
tunnel_consume_response(tunnel_ctx *ctx, const uint8_t *buf, size_t len)
{
    struct wg_pkt_response pkt;
    struct noise_remote *matched = NULL;
    struct peer_state *peer;
    int ret;

    if (len < sizeof(pkt)) return -1;
    memcpy(&pkt, buf, sizeof(pkt));

    peer = find_peer_pending_response(ctx, pkt.r_idx);
    if (!peer) {
        fprintf(stderr,
                "[hs] response r_idx 0x%08x has no matching pending peer\n",
                (unsigned)pkt.r_idx);
        return -1;
    }
    ret = noise_consume_response(ctx->local, &matched,
                                 pkt.s_idx, pkt.r_idx, pkt.ue, pkt.en);
    if (ret != 0) {
        fprintf(stderr, "[hs] noise_consume_response failed: %d\n", ret);
        return -1;
    }
    if (matched != peer->remote) {
        fprintf(stderr, "[hs] response matched unexpected peer\n");
        if (matched) noise_remote_put(matched);
        return -1;
    }
    noise_remote_put(matched);

    peer->hs_pending  = false;
    peer->hs_attempts = 0;
    peer_stamp_keypair(peer, time(NULL));
    fprintf(stderr, "[hs] rekey complete, new keypair active\n");
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────
 * Runtime dir + status socket
 *
 * When wg_core is started with --logical-name <name>, we write three files
 * under /var/run/wireguard/:
 *
 *   <name>.pid    — pid of this process, for `wgctl down` to signal
 *   <name>.name   — kernel-assigned utun device (e.g. "utun5"); lets
 *                   wgctl show / scripts find the real interface
 *   <name>.sock   — SOCK_STREAM UNIX socket; any connect+read writes one
 *                   wg-show-style text dump and closes
 *
 * Files are unlinked on graceful exit. The directory must already exist
 * (install.sh creates it, mode 0755 owned by root).
 * ───────────────────────────────────────────────────────────────────────── */
#define WG_RUNTIME_DIR "/var/run/wireguard"

/* Set by main() so the cleanup path can unlink without re-deriving paths. */
static char g_pid_path[256];
static char g_name_path[256];
static char g_sock_path[256];

static void
runtime_paths(const char *logical, char pid_p[256], char name_p[256], char sock_p[256])
{
    snprintf(pid_p,  256, "%s/%s.pid",  WG_RUNTIME_DIR, logical);
    snprintf(name_p, 256, "%s/%s.name", WG_RUNTIME_DIR, logical);
    snprintf(sock_p, 256, "%s/%s.sock", WG_RUNTIME_DIR, logical);
}

static int
ensure_runtime_dir(void)
{
    /* mkdir is idempotent; ignore EEXIST. */
    if (mkdir(WG_RUNTIME_DIR, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "mkdir %s: %s\n", WG_RUNTIME_DIR, strerror(errno));
        return -1;
    }
    return 0;
}

static int
write_text_file(const char *path, const char *content, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) {
        fprintf(stderr, "open %s: %s\n", path, strerror(errno));
        return -1;
    }
    size_t len = strlen(content);
    ssize_t n  = write(fd, content, len);
    close(fd);
    if (n != (ssize_t)len) {
        fprintf(stderr, "write %s: short write\n", path);
        return -1;
    }
    return 0;
}

/* Bind /var/run/wireguard/<logical>.sock for status dumps. Returns the
 * listening fd, or -1 on failure. */
static int
status_socket_open(const char *sock_path)
{
    int fd;
    struct sockaddr_un un;

    if (strlen(sock_path) >= sizeof(un.sun_path)) {
        fprintf(stderr, "status socket path too long: %s\n", sock_path);
        return -1;
    }

    (void)unlink(sock_path);  /* clean up stale from a crashed previous run */

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket(AF_UNIX)"); return -1; }

    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    strncpy(un.sun_path, sock_path, sizeof(un.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&un, sizeof(un)) < 0) {
        perror("bind(status sock)");
        close(fd);
        return -1;
    }
    /* Root-only: don't leak peer pubkeys to other users. */
    (void)chmod(sock_path, 0600);

    if (listen(fd, 4) < 0) {
        perror("listen(status sock)");
        close(fd);
        (void)unlink(sock_path);
        return -1;
    }
    return fd;
}

/* Accept one client on the status socket, dump status, close. The protocol
 * is "one connect = one dump"; clients don't need to send anything. */
static void
status_socket_accept(tunnel_ctx *ctx)
{
    int cfd = accept(ctx->status_listen_fd, NULL, NULL);
    if (cfd < 0) {
        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
            perror("accept(status sock)");
        return;
    }
    /* fdopen lets us reuse the FILE*-based dump helper. */
    FILE *out = fdopen(cfd, "w");
    if (!out) {
        close(cfd);
        return;
    }
    dump_status_snapshot(ctx, out);
    fclose(out);  /* also closes cfd */
}

static void
runtime_cleanup(void)
{
    if (g_pid_path[0])  (void)unlink(g_pid_path);
    if (g_sock_path[0]) (void)unlink(g_sock_path);
    if (g_name_path[0]) (void)unlink(g_name_path);
}

static int
run_tunnel(int udp_fd, int utun_fd, const char *utun_name,
           const char *logical_name,
           struct noise_local *local, struct cookie_checker *checker,
           const struct aips_set *aips,
           struct peer_state *peers, int n_peers)
{
    tunnel_ctx ctx;
    uint8_t udp_buf[2048];
    uint8_t inner_buf[2048];
    time_t last_stats;

    memset(&ctx, 0, sizeof(ctx));
    ctx.udp_fd          = udp_fd;
    ctx.utun_fd         = utun_fd;
    ctx.local           = local;
    ctx.cookie_checker  = checker;
    ctx.aips            = aips;
    ctx.peers           = peers;
    ctx.n_peers         = n_peers;
    ctx.status_listen_fd = -1;
    if (utun_name) {
        strncpy(ctx.if_name, utun_name, sizeof(ctx.if_name) - 1);
        ctx.if_name[sizeof(ctx.if_name) - 1] = '\0';
    }
    if (logical_name && *logical_name) {
        strncpy(ctx.logical_name, logical_name, sizeof(ctx.logical_name) - 1);
        ctx.logical_name[sizeof(ctx.logical_name) - 1] = '\0';
        ctx.status_listen_fd = status_socket_open(g_sock_path);
        if (ctx.status_listen_fd < 0)
            fprintf(stderr, "[runtime] status socket disabled\n");
        else
            fprintf(stderr, "[runtime] status socket at %s\n", g_sock_path);
    }

    last_stats = time(NULL);

    signal(SIGINT,  on_quit);
    signal(SIGTERM, on_quit);
#ifdef SIGINFO
    signal(SIGINFO, on_info);   /* Ctrl-T on macOS / BSD */
#endif

    /* Clear the 3-second RCVTIMEO left from the handshake probe: select()
     * handles readiness now, and a stale timeout would make recv() return
     * EAGAIN spuriously after 3 s of idle traffic. */
    {
        struct timeval tv = {0};
        (void)setsockopt(udp_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    /* Env-var trace cap override: WG_TRACE=N (0 = silent, -1 = unlimited). */
    {
        const char *env = getenv("WG_TRACE");
        if (env) {
            int n = atoi(env);
            g_trace_cap = (n < 0) ? INT_MAX : n;
        }
    }

    printf("[tunnel] entering event loop "
           "(utun_fd=%d, udp_fd=%d, peers=%d, trace_cap=%d)\n",
           utun_fd, udp_fd, ctx.n_peers, g_trace_cap);

    /* Print one wg-show-style snapshot at startup so the operator
     * sees the parsed config / endpoint / peer pubkey. From here on
     * snapshots come on demand via SIGINFO (Ctrl-T on macOS). */
    print_status_snapshot(&ctx);
    fprintf(stderr, "[tunnel] press Ctrl-T (SIGINFO) for a status snapshot at any time\n");

    while (!sig_quit) {
        fd_set rfds;
        int maxfd;
        struct timeval tv;
        int rc;
        time_t now;

        FD_ZERO(&rfds);
        FD_SET(udp_fd,  &rfds);
        FD_SET(utun_fd, &rfds);
        maxfd = (udp_fd > utun_fd) ? udp_fd : utun_fd;
        if (ctx.status_listen_fd >= 0) {
            FD_SET(ctx.status_listen_fd, &rfds);
            if (ctx.status_listen_fd > maxfd) maxfd = ctx.status_listen_fd;
        }

        tv.tv_sec  = 1;
        tv.tv_usec = 0;
        rc = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR) continue;
            perror("select");
            return -1;
        }

        now = time(NULL);
        tunnel_tick(&ctx, now);

        if (sig_info) {
            sig_info = 0;
            print_status_snapshot(&ctx);
        }

        /* Status socket — serve a one-shot snapshot to whichever client
         * connected. Doing this in-line keeps the implementation single-
         * threaded; dumps are O(n_peers) and bounded. */
        if (ctx.status_listen_fd >= 0 && FD_ISSET(ctx.status_listen_fd, &rfds))
            status_socket_accept(&ctx);

        if (rc == 0) {
            if (now - last_stats >= 10) {
                uint64_t total_tx_p = 0, total_tx_b = 0, total_rx_p = 0, total_rx_b = 0;
                for (int i = 0; i < ctx.n_peers; i++) {
                    total_tx_p += ctx.peers[i].tx_pkts;
                    total_tx_b += ctx.peers[i].tx_bytes;
                    total_rx_p += ctx.peers[i].rx_pkts;
                    total_rx_b += ctx.peers[i].rx_bytes;
                }
                printf("[tunnel] tx=%llu pkts/%llu B  rx=%llu pkts/%llu B  "
                       "(across %d peer%s)\n",
                       (unsigned long long)total_tx_p,
                       (unsigned long long)total_tx_b,
                       (unsigned long long)total_rx_p,
                       (unsigned long long)total_rx_b,
                       ctx.n_peers, ctx.n_peers == 1 ? "" : "s");
                last_stats = now;
            }
            continue;
        }

        /* ── utun → udp (encap) ─────────────────────────────────────── */
        if (FD_ISSET(utun_fd, &rfds)) {
            int n = utun_read(utun_fd, inner_buf, sizeof(inner_buf));
            if (n > 0) {
                if (g_trace_tx < g_trace_cap) {
                    g_trace_tx++;
                    fprintf(stderr, "[tx#%d] utun_read %d B, inner IP ver=%u\n",
                            g_trace_tx, n, inner_buf[0] >> 4);
                    trace_hex("plain", inner_buf, (size_t)n);
                }
                /* Cryptokey routing: look up the inner DST IP in the
                 * shared allowedips trie to pick which peer this packet
                 * belongs to. NULL means no peer owns this destination. */
                struct peer_state *dst_peer = NULL;
                int ver = inner_buf[0] >> 4;
                if (ver == 4 && n >= 20)
                    dst_peer = aips_lookup(&ctx.aips->v4, inner_buf + 16);
                else if (ver == 6 && n >= 40)
                    dst_peer = aips_lookup(&ctx.aips->v6, inner_buf + 24);

                if (!dst_peer) {
                    if (g_trace_tx <= g_trace_cap)
                        fprintf(stderr, "[tx#%d] DROP: no peer for inner dst\n",
                                g_trace_tx);
                } else if (wg_encap(udp_fd, dst_peer, inner_buf, (size_t)n) == 0) {
                    dst_peer->tx_pkts++;
                    dst_peer->tx_bytes += (uint64_t)n;
                    dst_peer->last_authd_tx = now;
                } else if (g_trace_tx <= g_trace_cap) {
                    fprintf(stderr, "[tx#%d] wg_encap FAILED\n", g_trace_tx);
                }
            } else if (n < 0 && g_trace_tx < g_trace_cap) {
                fprintf(stderr, "[tx] utun_read returned %d\n", n);
            }
        }

        /* ── udp → utun (decap) ─────────────────────────────────────── */
        if (FD_ISSET(udp_fd, &rfds)) {
            struct sockaddr_storage from_ss;
            socklen_t from_sl = sizeof(from_ss);
            ssize_t n = recvfrom(udp_fd, udp_buf, sizeof(udp_buf), 0,
                                 (struct sockaddr *)&from_ss, &from_sl);
            if (n < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                    perror("[rx] recvfrom");
                continue;
            }

            if (g_trace_rx < g_trace_cap) {
                char addr_s[80];
                fmt_sockaddr((struct sockaddr *)&from_ss, addr_s, sizeof(addr_s));
                g_trace_rx++;
                fprintf(stderr, "[rx#%d] recvfrom %s len=%zd\n",
                        g_trace_rx, addr_s, n);
                trace_hex("wire", udp_buf, (size_t)n);
            }
            if (n >= 4) {
                uint32_t t;
                memcpy(&t, udp_buf, sizeof(t));
                if (t == WG_PKT_DATA) {
                    struct peer_state *src_peer = NULL;
                    int inner = wg_decap(local, udp_buf, (size_t)n,
                                         inner_buf, sizeof(inner_buf),
                                         &src_peer);
                    if (inner > 0 && src_peer) {
                        /* Anti-spoofing: the inner src must belong to
                         * the peer that authenticated the packet. */
                        void *aip_owner = aips_lookup_inner_src(
                            ctx.aips, inner_buf, (size_t)inner);
                        if (aip_owner != (void *)src_peer) {
                            src_peer->rx_dropped_aips++;
                            if (g_trace_rx <= g_trace_cap) {
                                fprintf(stderr, "[rx#%d] DROP: inner src not in "
                                                "this peer's allowed-ips\n",
                                        g_trace_rx);
                            }
                            continue;
                        }
                        if (g_trace_rx <= g_trace_cap) {
                            fprintf(stderr, "[rx#%d] decap OK: %d inner bytes, ver=%u\n",
                                    g_trace_rx, inner, inner_buf[0] >> 4);
                            trace_hex("plain", inner_buf, (size_t)inner);
                        }
                        if (utun_write(utun_fd, inner_buf, (size_t)inner) == 0) {
                            src_peer->rx_pkts++;
                            src_peer->rx_bytes += (uint64_t)inner;
                            /* Roaming: update peer endpoint to where this
                             * authenticated data packet came from. */
                            memcpy(&src_peer->endpoint, &from_ss, from_sl);
                            src_peer->endpoint_len = from_sl;
                        } else if (g_trace_rx <= g_trace_cap) {
                            fprintf(stderr, "[rx#%d] utun_write FAILED\n", g_trace_rx);
                        }
                    } else if (inner == 0 && src_peer) {
                        if (g_trace_rx <= g_trace_cap)
                            fprintf(stderr, "[rx#%d] keepalive (empty inner)\n", g_trace_rx);
                        src_peer->rx_pkts++;
                        memcpy(&src_peer->endpoint, &from_ss, from_sl);
                        src_peer->endpoint_len = from_sl;
                    } else if (g_trace_rx <= g_trace_cap) {
                        fprintf(stderr, "[rx#%d] decap FAILED\n", g_trace_rx);
                    }
                } else if (t == WG_PKT_INITIATION) {
                    if (tunnel_consume_initiation(&ctx, udp_buf, (size_t)n,
                                                  (struct sockaddr *)&from_ss,
                                                  from_sl) != 0) {
                        fprintf(stderr, "[rx] handshake initiation rejected\n");
                    }
                } else if (t == WG_PKT_RESPONSE) {
                    if (tunnel_consume_response(&ctx, udp_buf, (size_t)n) != 0)
                        fprintf(stderr, "[rx] handshake response rejected\n");
                } else if (t == WG_PKT_COOKIE) {
                    /* Cookie replies are addressed to a specific peer
                     * (we track which initiation we sent and to whom),
                     * so dispatch to whichever peer is hs_pending. */
                    if ((size_t)n >= sizeof(struct wg_pkt_cookie)) {
                        struct wg_pkt_cookie pkt;
                        memcpy(&pkt, udp_buf, sizeof(pkt));
                        struct peer_state *p = find_peer_pending_response(&ctx, pkt.r_idx);
                        if (p && cookie_maker_consume_payload(&p->cookie,
                                                              pkt.nonce, pkt.ec) == 0)
                            fprintf(stderr, "[rx] cookie reply consumed for peer\n");
                    }
                } else {
                    fprintf(stderr, "[rx#%d] unknown pkt type=0x%08x len=%zd\n",
                            g_trace_rx, (unsigned)le32toh(t), n);
                }
            }
        }
    }

    if (ctx.status_listen_fd >= 0)
        close(ctx.status_listen_fd);

    {
        uint64_t tot_tx_p = 0, tot_tx_b = 0, tot_rx_p = 0, tot_rx_b = 0, tot_drop = 0;
        for (int i = 0; i < ctx.n_peers; i++) {
            tot_tx_p += ctx.peers[i].tx_pkts;
            tot_tx_b += ctx.peers[i].tx_bytes;
            tot_rx_p += ctx.peers[i].rx_pkts;
            tot_rx_b += ctx.peers[i].rx_bytes;
            tot_drop += ctx.peers[i].rx_dropped_aips;
        }
        printf("\n[tunnel] shutdown. final: tx=%llu pkts/%llu B  rx=%llu pkts/%llu B  "
               "rx_dropped_aips=%llu  (across %d peer%s)\n",
               (unsigned long long)tot_tx_p, (unsigned long long)tot_tx_b,
               (unsigned long long)tot_rx_p, (unsigned long long)tot_rx_b,
               (unsigned long long)tot_drop,
               ctx.n_peers, ctx.n_peers == 1 ? "" : "s");
        return (tot_rx_p > 0) ? 0 : 2;
    }
}

/* Kept as a one-shot smoke test callable from main probe mode. */
static int send_keepalive_data(int udp_fd, struct peer_state *peer)
{
    return wg_encap(udp_fd, peer, NULL, 0);
}

int main(int argc, char *argv[])
{
    const char *config_path  = "test.ini";
    const char *logical_name = NULL;        /* e.g. "wg0" */
    int want_tunnel = 0;
    struct client_config cfg;
    struct noise_local *local = NULL;
    struct cookie_checker checker;
    int checker_inited = 0;
    int udp_fd = -1;
    int utun_fd = -1;
    char utun_name[IFNAMSIZ] = {0};
    struct aips_set aips;
    int aips_inited = 0;
    int ret = 1;

    signal(SIGPIPE, SIG_IGN);
    /* Install termination handlers up-front so probe-mode (which can block
     * for up to ~45 s across 5 handshake attempts) cleans up promptly on
     * SIGTERM. run_tunnel installs them again, which is harmless. */
    signal(SIGINT,  on_quit);
    signal(SIGTERM, on_quit);

    /* Usage: wg_core [--tunnel] [--logical-name NAME] [config_path]
     *   --tunnel             after handshake, open utun and run the
     *                        forwarding loop (otherwise: one-shot probe)
     *   --logical-name NAME  publish /var/run/wireguard/NAME.{pid,name,sock}
     *                        for wgctl up/down/show to track this instance */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--tunnel") == 0 || strcmp(argv[i], "-t") == 0) {
            want_tunnel = 1;
        } else if ((strcmp(argv[i], "--logical-name") == 0 ||
                    strcmp(argv[i], "-n") == 0) && i + 1 < argc) {
            logical_name = argv[++i];
        } else {
            config_path = argv[i];
        }
    }

    if (logical_name) {
        runtime_paths(logical_name, g_pid_path, g_name_path, g_sock_path);
        if (ensure_runtime_dir() != 0)
            return 1;
        /* Best-effort cleanup on exit — atexit covers normal returns;
         * signal handlers run runtime_cleanup explicitly via on_quit. */
        atexit(runtime_cleanup);
    }

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

    /* Per-peer noise / cookie state. The noise_remote stores a pointer
     * to the peer_state in its arg slot so the data plane can recover
     * the peer from a noise_keypair via noise_remote_arg(). */
    int any_endpoint = 0;
    for (int i = 0; i < cfg.n_peers; i++) {
        struct peer_state *p = &cfg.peers[i];
        p->remote = noise_remote_alloc(local, p, p->pubkey);
        if (!p->remote) {
            fprintf(stderr, "noise_remote_alloc failed for peer #%d\n", i);
            goto out;
        }
        if (noise_remote_enable(p->remote) != 0) {
            fprintf(stderr, "noise_remote_enable failed for peer #%d\n", i);
            goto out;
        }
        cookie_maker_init(&p->cookie, p->pubkey);
        p->cookie_inited = true;

        if (p->has_endpoint) {
            struct sockaddr_storage ss;
            socklen_t sl;
            if (resolve_endpoint(p->endpoint_host, p->endpoint_port, &ss, &sl) != 0)
                goto out;
            memcpy(&p->endpoint, &ss, sl);
            p->endpoint_len = sl;
            any_endpoint = 1;
        }
    }

    /* Cookie checker (responder side): keyed on OUR own static pubkey
     * so we can validate mac1/mac2 on incoming initiations. Always
     * initialized — even initiator-only configs may receive unsolicited
     * initiations if a peer wants to drive a rekey. */
    cookie_checker_init(&checker);
    checker_inited = 1;
    {
        uint8_t local_pub[NOISE_PUBLIC_KEY_LEN];
        uint8_t local_priv_unused[NOISE_PUBLIC_KEY_LEN];
        if (noise_local_keys(local, local_pub, local_priv_unused) == 0) {
            cookie_checker_update(&checker, local_pub);
        } else {
            fprintf(stderr, "noise_local_keys failed; cookie_checker not keyed\n");
        }
    }

    /* Bind UDP. ListenPort honored if set; otherwise ephemeral. */
    {
        int family = AF_INET;
        for (int i = 0; i < cfg.n_peers; i++) {
            if (cfg.peers[i].endpoint_len &&
                cfg.peers[i].endpoint.ss_family == AF_INET6) {
                family = AF_INET6;
                break;
            }
        }
        udp_fd = udp_open_unconnected(family, cfg.listen_port);
    }
    if (udp_fd < 0) {
        fprintf(stderr, "failed to open udp socket\n");
        goto out;
    }
    if (any_endpoint) {
        for (int i = 0; i < cfg.n_peers; i++) {
            if (!cfg.peers[i].endpoint_len) continue;
            char addr_s[80];
            fmt_sockaddr((struct sockaddr *)&cfg.peers[i].endpoint,
                         addr_s, sizeof(addr_s));
            fprintf(stderr, "[udp] peer #%d endpoint resolved to %s\n", i, addr_s);
        }
    } else {
        fprintf(stderr, "[udp] pure-responder mode (no peer endpoints), "
                        "listening on UDP %u\n", (unsigned)cfg.listen_port);
    }

    /* Build the shared allowedips trie spanning all peers. Each CIDR
     * maps to its own peer_state*, so encap (dst → peer) and decap
     * (anti-spoof inner src → must equal sender peer) both work. */
    aips_init(&aips.v4, 32);
    aips_init(&aips.v6, 128);
    aips_inited = 1;
    {
        int total_cidrs = 0;
        for (int i = 0; i < cfg.n_peers; i++) {
            struct peer_state *p = &cfg.peers[i];
            for (int j = 0; j < p->n_allowed; j++) {
                struct aips_trie *t = (p->allowed[j].family == AF_INET)
                                          ? &aips.v4 : &aips.v6;
                if (aips_insert(t, p->allowed[j].addr,
                                p->allowed[j].prefix_len, p) != 0) {
                    fprintf(stderr, "aips_insert failed\n");
                    goto out;
                }
                total_cidrs++;
            }
        }
        printf("[tunnel] allowed-ips loaded: %d CIDR(s) across %d peer(s)\n",
               total_cidrs, cfg.n_peers);
    }

    {
        struct timeval tv;
        tv.tv_sec = 3;
        tv.tv_usec = 0;
        if (setsockopt(udp_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0)
            perror("setsockopt SO_RCVTIMEO");
    }

    /* Probe mode: drive the initial handshake against the FIRST peer with
     * an endpoint, send one keepalive, exit. Multi-peer probe is not very
     * useful — operators should use --tunnel for the real thing.
     *
     * Skip probe entirely when --tunnel is set: when BOTH ends initiate
     * (has_endpoint on each side), probe mode's wait_for_response()
     * synchronously rejects the peer's incoming INITIATION as "unexpected
     * packet type/size", and both sides hit "[handshake] failed after
     * retries" and goto out. run_tunnel handles bidirectional initiation
     * correctly via tunnel_consume_initiation. */
    struct peer_state *first_initiator = NULL;
    if (!want_tunnel) {
        for (int i = 0; i < cfg.n_peers; i++) {
            if (cfg.peers[i].has_endpoint) {
                first_initiator = &cfg.peers[i];
                break;
            }
        }
    }

    if (first_initiator) {
        for (int attempt = 1; attempt <= 5 && !sig_quit; ++attempt) {
            uint32_t s_idx = 0;
            int w;
            printf("[handshake] attempt %d\n", attempt);
            if (send_initiation(udp_fd, first_initiator, &s_idx) != 0) {
                /* nanosleep is EINTR-aware, so SIGTERM during the back-off
                 * pops us out and the loop's sig_quit check exits cleanly.
                 * sleep(3) on macOS is also SIGRT-restartable per POSIX —
                 * but using nanosleep avoids that ambiguity. */
                struct timespec ts = { REKEY_TIMEOUT_SEC, 0 };
                (void)nanosleep(&ts, NULL);
                continue;
            }
            w = wait_for_response(udp_fd, local, first_initiator, s_idx);
            if (w == 0) {
                printf("[handshake] success\n");
                peer_stamp_keypair(first_initiator, time(NULL));
                ret = 0;
                break;
            }
            struct timespec ts = { REKEY_TIMEOUT_SEC, 0 };
            (void)nanosleep(&ts, NULL);
        }
        if (sig_quit) {
            fprintf(stderr, "[handshake] interrupted by signal\n");
            ret = 0;
            goto out;
        }
        if (ret != 0) {
            fprintf(stderr, "[handshake] failed after retries\n");
            goto out;
        }
    } else {
        ret = 0;
        printf("[handshake] skipped (no peer with endpoint)\n");
    }

    if (!want_tunnel) {
        if (first_initiator) {
            if (send_keepalive_data(udp_fd, first_initiator) == 0)
                printf("[data] keepalive packet sent\n");
        } else {
            printf("[probe] responder mode — nothing to send, exiting\n");
        }
        goto out;
    }

    /* Tunnel mode: bring up utun and enter the forwarding loop. */
    utun_fd = utun_open(utun_name);
    if (utun_fd < 0) {
        fprintf(stderr, "utun_open failed (need root?)\n");
        ret = 1;
        goto out;
    }
    printf("[tunnel] opened %s (fd=%d)\n", utun_name, utun_fd);

    /* Publish runtime files NOW that we know utun_name + our pid. wgctl
     * down reads <logical>.pid; wgctl show reads <logical>.name to find
     * the actual utun device name. */
    if (logical_name) {
        char buf[64];
        snprintf(buf, sizeof(buf), "%d\n", (int)getpid());
        if (write_text_file(g_pid_path, buf, 0644) != 0)
            fprintf(stderr, "[runtime] failed to write %s\n", g_pid_path);
        snprintf(buf, sizeof(buf), "%s\n", utun_name);
        if (write_text_file(g_name_path, buf, 0644) != 0)
            fprintf(stderr, "[runtime] failed to write %s\n", g_name_path);
    }

    if (cfg.n_if_addrs > 0) {
        if (utun_configure(utun_name, &cfg) != 0) {
            fprintf(stderr, "utun_configure failed, continuing unconfigured\n");
        } else {
            printf("[tunnel] %s configured with %d address(es):", utun_name, cfg.n_if_addrs);
            for (int i = 0; i < cfg.n_if_addrs; i++)
                printf(" %s/%d", cfg.if_addrs[i].addr_str, cfg.if_addrs[i].prefix_len);
            printf("\n");
            /* Dump what the kernel actually installed for cross-check. */
            {
                char cmd[128];
                snprintf(cmd, sizeof(cmd), "/sbin/ifconfig %s", utun_name);
                (void)system(cmd);
            }
        }
    } else {
        fprintf(stderr, "[tunnel] no Interface.Address in config; "
                        "configure %s manually if needed\n", utun_name);
    }

    /* PostUp hook: lets operators inject extra routes / firewall rules,
     * and (more importantly) re-installs the per-peer AllowedIPs routes
     * via the shipped /usr/local/libexec/wg-mac/postup.sh — the
     * defense-in-depth for the route-flushed-after-bring-up case. */
    run_postup_hook(logical_name, config_path, utun_name);

    /* Send one keepalive on the first endpointed peer so the server
     * refreshes its endpoint view for this source port. */
    if (first_initiator)
        (void)send_keepalive_data(udp_fd, first_initiator);

    ret = run_tunnel(udp_fd, utun_fd, utun_name, logical_name,
                     local, &checker, &aips,
                     cfg.peers, cfg.n_peers);

out:
    if (utun_fd >= 0)
        close(utun_fd);
    if (udp_fd >= 0)
        close(udp_fd);
    if (aips_inited) {
        aips_destroy(&aips.v4);
        aips_destroy(&aips.v6);
    }
    if (checker_inited)
        cookie_checker_free(&checker);
    for (int i = 0; i < cfg.n_peers; i++) {
        if (cfg.peers[i].cookie_inited)
            cookie_maker_free(&cfg.peers[i].cookie);
        if (cfg.peers[i].remote)
            noise_remote_put(cfg.peers[i].remote);
    }
    if (local)
        noise_local_put(local);
    crypto_deinit();
    return ret;
}
