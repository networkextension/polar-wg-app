/* SPDX-License-Identifier: MIT
 *
 * wg_session: I/O-agnostic WireGuard session library.
 *
 * Reuses the noise_*, cookie_*, and aips_* primitives from libwg.a.
 * Config parsing, peer-state struct, encap/decap, and the timer wheel
 * are local to this file because they need to be I/O-free (no
 * send/recv/select/utun/ifconfig) for NetworkExtension to host them.
 *
 * The wg_core.c userspace client and this library are deliberately
 * parallel implementations of the same state machine: wg_core.c drives
 * everything from select() + real sockets + utun, while wg_session.c
 * drives everything from three external entry points (handle_udp,
 * handle_tun, tick) and three callbacks (send_udp, deliver_ip, log).
 */

#include "wg_session.h"
#include "allowedips.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

#include "macos_stubs/sys/mbuf.h"
#include "macos_stubs/sys/param.h"
#include "macos_stubs/sys/rwlock.h"
#include "macos_stubs/sys/mutex.h"
#include "wg_cookie.h"

/* ─────────────────────────────────────────────────────────────────────────
 * WireGuard wire format (matches FreeBSD if_wg.c). Duplicated from
 * wg_core.c so this translation unit stays self-contained.
 * ───────────────────────────────────────────────────────────────────────── */

#define WG_KEY_LEN        32
#define WG_AUTHTAG_LEN    16
#define WG_TIMESTAMP_LEN  12
#define WG_PKT_PADDING    16

#define NOISE_PUBLIC_KEY_LEN WG_KEY_LEN

#define WGS_PKT_INITIATION  htole32(1)
#define WGS_PKT_RESPONSE    htole32(2)
#define WGS_PKT_COOKIE      htole32(3)
#define WGS_PKT_DATA        htole32(4)

#define REKEY_TIMEOUT_SEC      5
#define REKEY_AFTER_TIME_SEC   120
#define REJECT_AFTER_TIME_SEC  180
#define MAX_HANDSHAKE_ATTEMPTS 18

struct wgs_pkt_initiation {
    uint32_t t;
    uint32_t s_idx;
    uint8_t  ue[WG_KEY_LEN];
    uint8_t  es[WG_KEY_LEN + WG_AUTHTAG_LEN];
    uint8_t  ets[WG_TIMESTAMP_LEN + WG_AUTHTAG_LEN];
    struct cookie_macs m;
};
struct wgs_pkt_response {
    uint32_t t;
    uint32_t s_idx;
    uint32_t r_idx;
    uint8_t  ue[WG_KEY_LEN];
    uint8_t  en[WG_AUTHTAG_LEN];
    struct cookie_macs m;
};
struct wgs_pkt_cookie {
    uint32_t t;
    uint32_t r_idx;
    uint8_t  nonce[COOKIE_NONCE_SIZE];
    uint8_t  ec[COOKIE_ENCRYPTED_SIZE];
};
struct wgs_pkt_data_hdr {
    uint32_t t;
    uint32_t r_idx;
    uint64_t nonce;
};

_Static_assert(sizeof(struct wgs_pkt_initiation) == 148, "init size");
_Static_assert(sizeof(struct wgs_pkt_response)   == 92,  "resp size");
_Static_assert(sizeof(struct wgs_pkt_cookie)     == 64,  "cookie size");
_Static_assert(sizeof(struct wgs_pkt_data_hdr)   == 16,  "data hdr size");

/* ─────────────────────────────────────────────────────────────────────────
 * Externs from libwg.a (noise + cookie). Kept local to avoid dragging
 * the full wg_noise.h into this file — we only need the signatures.
 * ───────────────────────────────────────────────────────────────────────── */
struct noise_local;
struct noise_remote;
struct noise_keypair;

extern int  crypto_init(void);
extern void crypto_deinit(void);

extern struct noise_local *noise_local_alloc(void *arg);
extern void                noise_local_put(struct noise_local *);
extern void                noise_local_private(struct noise_local *,
                                                const uint8_t priv[WG_KEY_LEN]);
extern int                 noise_local_keys(struct noise_local *,
                                             uint8_t pub[WG_KEY_LEN],
                                             uint8_t priv[WG_KEY_LEN]);

extern struct noise_remote *noise_remote_alloc(struct noise_local *, void *arg,
                                               const uint8_t pub[WG_KEY_LEN]);
extern int                  noise_remote_enable(struct noise_remote *);
extern void                 noise_remote_put(struct noise_remote *);
extern void                *noise_remote_arg(struct noise_remote *);

extern int noise_create_initiation(struct noise_remote *, uint32_t *s_idx,
                                   uint8_t ue[WG_KEY_LEN],
                                   uint8_t es[WG_KEY_LEN + WG_AUTHTAG_LEN],
                                   uint8_t ets[WG_TIMESTAMP_LEN + WG_AUTHTAG_LEN]);
extern int noise_consume_initiation(struct noise_local *, struct noise_remote **,
                                    uint32_t s_idx,
                                    uint8_t ue[WG_KEY_LEN],
                                    uint8_t es[WG_KEY_LEN + WG_AUTHTAG_LEN],
                                    uint8_t ets[WG_TIMESTAMP_LEN + WG_AUTHTAG_LEN]);
extern int noise_create_response(struct noise_remote *, uint32_t *s_idx,
                                 uint32_t *r_idx, uint8_t ue[WG_KEY_LEN],
                                 uint8_t en[WG_AUTHTAG_LEN]);
extern int noise_consume_response(struct noise_local *, struct noise_remote **,
                                  uint32_t s_idx, uint32_t r_idx,
                                  uint8_t ue[WG_KEY_LEN],
                                  uint8_t en[WG_AUTHTAG_LEN]);

extern struct noise_keypair *noise_keypair_current(struct noise_remote *);
extern struct noise_keypair *noise_keypair_lookup(struct noise_local *, uint32_t);
extern struct noise_remote  *noise_keypair_remote(struct noise_keypair *);
extern int                   noise_keypair_nonce_next(struct noise_keypair *, uint64_t *);
extern int                   noise_keypair_encrypt(struct noise_keypair *,
                                                    uint32_t *r_idx, uint64_t nonce,
                                                    struct mbuf *);
extern int                   noise_keypair_decrypt(struct noise_keypair *,
                                                    uint64_t nonce, struct mbuf *);
extern int                   noise_keypair_received_with(struct noise_keypair *);
extern void                  noise_keypair_put(struct noise_keypair *);

/* ─────────────────────────────────────────────────────────────────────────
 * Internal data model (matches the multi-peer shape from wg_core.c)
 * ───────────────────────────────────────────────────────────────────────── */

#define WGS_MAX_ALLOWED_CIDRS 16
#define WGS_MAX_IFACE_ADDRS    4
#define WGS_MAX_PEERS          8

struct wgs_allowed_cidr {
    int     family;
    uint8_t addr[16];
    int     prefix_len;
};

struct wgs_iface_addr {
    int  family;
    char addr_str[64];
    int  prefix_len;
};

struct wgs_peer {
    uint8_t pubkey[WG_KEY_LEN];

    bool                     has_endpoint;
    char                     endpoint_host[128];
    uint16_t                 endpoint_port;
    struct sockaddr_storage  endpoint;
    socklen_t                endpoint_len;

    struct wgs_allowed_cidr  allowed[WGS_MAX_ALLOWED_CIDRS];
    int                      n_allowed;

    int                      pk_sec;

    struct noise_remote *remote;
    struct cookie_maker  cookie;
    bool                 cookie_inited;

    bool      hs_pending;
    time_t    hs_sent_at;
    uint32_t  hs_local_idx;
    int       hs_attempts;

    time_t    keypair_birth;
    time_t    last_authd_tx;

    uint64_t  tx_pkts, tx_bytes, rx_pkts, rx_bytes;
    uint64_t  rx_dropped_aips;
};

struct wg_session {
    /* Parsed config state */
    uint8_t private_key[WG_KEY_LEN];
    uint16_t listen_port;               /* from [Interface] ListenPort */
    struct wgs_iface_addr if_addrs[WGS_MAX_IFACE_ADDRS];
    int                   n_if_addrs;

    struct wgs_peer peers[WGS_MAX_PEERS];
    int             n_peers;

    /* Noise + cookie */
    struct noise_local   *local;
    struct cookie_checker checker;
    bool                  checker_inited;

    /* Allowedips trie spanning all peers */
    struct aips_trie aips_v4;
    struct aips_trie aips_v6;
    bool             aips_inited;

    /* Upcalls to Swift */
    wg_session_callbacks cb;
};

/* ─────────────────────────────────────────────────────────────────────────
 * Logging helper
 * ───────────────────────────────────────────────────────────────────────── */

static void
wgs_log(wg_session_t *s, const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (s->cb.log_line)
        s->cb.log_line(s->cb.user_ctx, buf);
    else
        fprintf(stderr, "[wg_session] %s\n", buf);
}

/* ─────────────────────────────────────────────────────────────────────────
 * Config parser. Simplified fork of wg_core.c's load_config that reads
 * from a text buffer instead of a file so it can be called from inside
 * a sandboxed NE extension where fopen may be restricted.
 * ───────────────────────────────────────────────────────────────────────── */

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

    if (in_len != 44) return -1;
    for (size_t i = 0; i < 44; i += 4) {
        int v0 = b64_value((unsigned char)in[i]);
        int v1 = b64_value((unsigned char)in[i + 1]);
        if (v0 < 0 || v1 < 0) return -1;
        tmp[out_len++] = (uint8_t)((v0 << 2) | (v1 >> 4));
        if (in[i + 2] == '=') break;
        int v2 = b64_value((unsigned char)in[i + 2]);
        if (v2 < 0) return -1;
        tmp[out_len++] = (uint8_t)(((v1 & 0x0f) << 4) | (v2 >> 2));
        if (in[i + 3] == '=') break;
        int v3 = b64_value((unsigned char)in[i + 3]);
        if (v3 < 0) return -1;
        tmp[out_len++] = (uint8_t)(((v2 & 0x03) << 6) | v3);
    }
    if (out_len != WG_KEY_LEN) return -1;
    memcpy(out, tmp, WG_KEY_LEN);
    return 0;
}

static char *wgs_trim(char *s)
{
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    if (*s == '\0') return s;
    char *e = s + strlen(s) - 1;
    while (e > s && (*e == ' ' || *e == '\t' || *e == '\r' || *e == '\n')) {
        *e-- = '\0';
    }
    return s;
}

static int parse_cidr(const char *s, struct wgs_allowed_cidr *out)
{
    char tmp[64]; char *slash; int prefix;
    if (strlen(s) >= sizeof(tmp)) return -1;
    strcpy(tmp, s);
    slash = strchr(tmp, '/');
    if (slash) { *slash = '\0'; prefix = atoi(slash + 1); } else { prefix = -1; }
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

static int parse_iface_addr(const char *s, struct wgs_iface_addr *out)
{
    char tmp[64]; char *slash; int prefix; uint8_t bin[16];
    if (strlen(s) >= sizeof(tmp)) return -1;
    strcpy(tmp, s);
    slash = strchr(tmp, '/');
    if (slash) { *slash = '\0'; prefix = atoi(slash + 1); } else { prefix = -1; }
    if (inet_pton(AF_INET, tmp, bin) == 1) {
        out->family = AF_INET;
        out->prefix_len = (prefix < 0) ? 32 : prefix;
    } else if (inet_pton(AF_INET6, tmp, bin) == 1) {
        out->family = AF_INET6;
        out->prefix_len = (prefix < 0) ? 128 : prefix;
    } else return -1;
    strncpy(out->addr_str, tmp, sizeof(out->addr_str) - 1);
    out->addr_str[sizeof(out->addr_str) - 1] = '\0';
    return 0;
}

static int parse_list_cidrs(const char *s, struct wgs_peer *peer)
{
    char buf[512]; char *p; char *save;
    if (strlen(s) >= sizeof(buf)) return -1;
    strcpy(buf, s);
    for (p = strtok_r(buf, ",", &save); p; p = strtok_r(NULL, ",", &save)) {
        p = wgs_trim(p);
        if (!*p) continue;
        if (peer->n_allowed >= WGS_MAX_ALLOWED_CIDRS) return -1;
        if (parse_cidr(p, &peer->allowed[peer->n_allowed]) != 0) return -1;
        peer->n_allowed++;
    }
    return 0;
}

static int parse_list_iface(const char *s, wg_session_t *sess)
{
    char buf[256]; char *p; char *save;
    if (strlen(s) >= sizeof(buf)) return -1;
    strcpy(buf, s);
    for (p = strtok_r(buf, ",", &save); p; p = strtok_r(NULL, ",", &save)) {
        p = wgs_trim(p);
        if (!*p) continue;
        if (sess->n_if_addrs >= WGS_MAX_IFACE_ADDRS) return -1;
        if (parse_iface_addr(p, &sess->if_addrs[sess->n_if_addrs]) != 0) return -1;
        sess->n_if_addrs++;
    }
    return 0;
}

static int split_endpoint(const char *s, char host[128], uint16_t *port)
{
    const char *colon = strrchr(s, ':');
    if (!colon) return -1;
    size_t hl = (size_t)(colon - s);
    if (hl == 0 || hl >= 128) return -1;
    memcpy(host, s, hl); host[hl] = '\0';
    long p = strtol(colon + 1, NULL, 10);
    if (p < 1 || p > 65535) return -1;
    *port = (uint16_t)p;
    return 0;
}

static int resolve_endpoint(const char *host, uint16_t port,
                            struct sockaddr_storage *out_ss, socklen_t *out_len)
{
    struct addrinfo hints, *res = NULL;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) return -1;
    memcpy(out_ss, res->ai_addr, res->ai_addrlen);
    *out_len = res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}

static int
parse_config_text(wg_session_t *s, const char *text, size_t len)
{
    /* Copy to a NUL-terminated scratch so strtok_r / strcmp work. */
    char *scratch = (char *)malloc(len + 1);
    if (!scratch) return -1;
    memcpy(scratch, text, len);
    scratch[len] = '\0';

    int in_interface = 0, in_peer = 0, cur_peer = -1;
    int got_priv = 0;

    char *save_line;
    for (char *line = strtok_r(scratch, "\n", &save_line); line;
         line = strtok_r(NULL, "\n", &save_line)) {
        char *p = wgs_trim(line);
        if (*p == '\0' || *p == '#' || *p == ';') continue;
        if (*p == '[') {
            in_interface = (strncmp(p, "[Interface]", 11) == 0);
            in_peer      = (strncmp(p, "[Peer]", 6) == 0);
            if (in_peer) {
                if (s->n_peers >= WGS_MAX_PEERS) { free(scratch); return -1; }
                cur_peer = s->n_peers++;
            }
            continue;
        }
        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq++ = '\0';
        p = wgs_trim(p);
        eq = wgs_trim(eq);

        if (in_interface && strcmp(p, "PrivateKey") == 0) {
            if (decode_base64_32(eq, s->private_key) != 0) { free(scratch); return -1; }
            got_priv = 1;
        } else if (in_interface && strcmp(p, "ListenPort") == 0) {
            int lp = atoi(eq);
            if (lp < 1 || lp > 65535) { free(scratch); return -1; }
            s->listen_port = (uint16_t)lp;
        } else if (in_interface && strcmp(p, "Address") == 0) {
            if (parse_list_iface(eq, s) != 0) { free(scratch); return -1; }
        } else if (in_peer && cur_peer >= 0) {
            struct wgs_peer *peer = &s->peers[cur_peer];
            if (strcmp(p, "PublicKey") == 0) {
                if (decode_base64_32(eq, peer->pubkey) != 0) { free(scratch); return -1; }
            } else if (strcmp(p, "Endpoint") == 0) {
                if (split_endpoint(eq, peer->endpoint_host, &peer->endpoint_port) != 0) {
                    free(scratch); return -1;
                }
                peer->has_endpoint = true;
            } else if (strcmp(p, "PersistentKeepalive") == 0) {
                peer->pk_sec = atoi(eq);
            } else if (strcmp(p, "AllowedIPs") == 0) {
                if (parse_list_cidrs(eq, peer) != 0) { free(scratch); return -1; }
            }
        }
    }
    free(scratch);

    if (!got_priv || s->n_peers == 0) return -1;
    for (int i = 0; i < s->n_peers; i++) {
        int has = 0;
        for (int j = 0; j < WG_KEY_LEN; j++) if (s->peers[i].pubkey[j]) { has = 1; break; }
        if (!has) return -1;
    }
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────
 * Encap / decap primitives. I/O-free: encap builds a datagram and
 * invokes cb.send_udp, decap validates + calls cb.deliver_ip.
 * ───────────────────────────────────────────────────────────────────────── */

static struct wgs_peer *
session_lookup_dst(wg_session_t *s, const uint8_t *inner, size_t len)
{
    if (len < 1) return NULL;
    int ver = inner[0] >> 4;
    if (ver == 4 && len >= 20)
        return (struct wgs_peer *)aips_lookup(&s->aips_v4, inner + 16);
    if (ver == 6 && len >= 40)
        return (struct wgs_peer *)aips_lookup(&s->aips_v6, inner + 24);
    return NULL;
}

static void *
session_lookup_inner_src(wg_session_t *s, const uint8_t *inner, size_t len)
{
    if (len < 1) return NULL;
    int ver = inner[0] >> 4;
    if (ver == 4 && len >= 20) return aips_lookup(&s->aips_v4, inner + 12);
    if (ver == 6 && len >= 40) return aips_lookup(&s->aips_v6, inner + 8);
    return NULL;
}

static int
wgs_encap(wg_session_t *s, struct wgs_peer *peer,
          const uint8_t *plain, size_t plain_len)
{
    if (!peer || peer->endpoint_len == 0) return -1;

    size_t padded = (plain_len + 15) & ~(size_t)15;
    if (padded == 0) padded = 16;
    if (padded > 2000) return -1;

    uint8_t scratch[2048];
    memset(scratch, 0, padded);
    if (plain_len) memcpy(scratch, plain, plain_len);

    struct noise_keypair *kp = noise_keypair_current(peer->remote);
    if (!kp) return -1;

    uint64_t nonce = 0;
    uint32_t r_idx = 0;
    if (noise_keypair_nonce_next(kp, &nonce) != 0) {
        noise_keypair_put(kp);
        return -1;
    }
    struct mbuf *m = m_devget(scratch, (int)padded);
    if (!m) { noise_keypair_put(kp); return -1; }
    if (noise_keypair_encrypt(kp, &r_idx, nonce, m) != 0) {
        m_freem(m);
        noise_keypair_put(kp);
        return -1;
    }

    struct wgs_pkt_data_hdr hdr;
    hdr.t = WGS_PKT_DATA;
    hdr.r_idx = r_idx;
    hdr.nonce = htole64(nonce);

    uint8_t out[2048];
    size_t out_len = sizeof(hdr) + (size_t)m->m_len;
    if (out_len > sizeof(out)) {
        m_freem(m);
        noise_keypair_put(kp);
        return -1;
    }
    memcpy(out, &hdr, sizeof(hdr));
    memcpy(out + sizeof(hdr), m->m_data, (size_t)m->m_len);

    /* Upcall. */
    if (s->cb.send_udp) {
        s->cb.send_udp(s->cb.user_ctx, out, out_len,
                       (const struct sockaddr *)&peer->endpoint,
                       peer->endpoint_len);
    }
    peer->tx_pkts++;
    peer->tx_bytes += plain_len;
    peer->last_authd_tx = time(NULL);

    m_freem(m);
    noise_keypair_put(kp);
    return 0;
}

static int
wgs_send_initiation(wg_session_t *s, struct wgs_peer *peer, const char *why)
{
    if (!peer->has_endpoint || peer->endpoint_len == 0) return -1;

    struct wgs_pkt_initiation pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.t = WGS_PKT_INITIATION;
    if (noise_create_initiation(peer->remote, &pkt.s_idx,
                                pkt.ue, pkt.es, pkt.ets) != 0) {
        wgs_log(s, "[hs] %s: noise_create_initiation failed", why);
        return -1;
    }
    cookie_maker_mac(&peer->cookie, &pkt.m, &pkt,
                     sizeof(pkt) - sizeof(pkt.m));

    if (s->cb.send_udp) {
        s->cb.send_udp(s->cb.user_ctx, (uint8_t *)&pkt, sizeof(pkt),
                       (const struct sockaddr *)&peer->endpoint,
                       peer->endpoint_len);
    }
    peer->hs_pending    = true;
    peer->hs_sent_at    = time(NULL);
    peer->hs_local_idx  = pkt.s_idx;
    peer->hs_attempts++;
    peer->last_authd_tx = peer->hs_sent_at;
    wgs_log(s, "[hs] %s: initiation sent (attempt %d)", why, peer->hs_attempts);
    return 0;
}

/* Parse an inner IP header to truncate trailing zero padding. */
static int inner_ip_len(const uint8_t *p, size_t cap)
{
    if (cap < 1) return -1;
    int ver = p[0] >> 4;
    if (ver == 4) {
        if (cap < 20) return -1;
        uint16_t total = ((uint16_t)p[2] << 8) | p[3];
        if (total < 20 || total > cap) return -1;
        return total;
    }
    if (ver == 6) {
        if (cap < 40) return -1;
        uint16_t payload = ((uint16_t)p[4] << 8) | p[5];
        size_t t = (size_t)payload + 40;
        if (t > cap) return -1;
        return (int)t;
    }
    return -1;
}

/* Handle an incoming WG_PKT_DATA. */
static int
wgs_handle_data(wg_session_t *s, const uint8_t *bytes, size_t len,
                const struct sockaddr *from, socklen_t from_len)
{
    struct wgs_pkt_data_hdr hdr;
    if (len < sizeof(hdr) + WG_AUTHTAG_LEN) return -1;
    memcpy(&hdr, bytes, sizeof(hdr));

    struct noise_keypair *kp = noise_keypair_lookup(s->local, hdr.r_idx);
    if (!kp) {
        wgs_log(s, "[rx] no keypair for r_idx 0x%08x", (unsigned)hdr.r_idx);
        return -1;
    }

    uint64_t nonce = le64toh(hdr.nonce);
    struct mbuf *m = m_devget(bytes + sizeof(hdr), (int)(len - sizeof(hdr)));
    if (!m) { noise_keypair_put(kp); return -1; }

    if (noise_keypair_decrypt(kp, nonce, m) != 0) {
        wgs_log(s, "[rx] decrypt failed (nonce=%llu)",
                (unsigned long long)nonce);
        m_freem(m);
        noise_keypair_put(kp);
        return -1;
    }
    (void)noise_keypair_received_with(kp);

    struct noise_remote *rem = noise_keypair_remote(kp);
    struct wgs_peer *src_peer = rem ? (struct wgs_peer *)noise_remote_arg(rem) : NULL;
    if (rem) noise_remote_put(rem);

    if (!src_peer) {
        m_freem(m);
        noise_keypair_put(kp);
        return -1;
    }

    /* Roaming: update endpoint from where this authenticated packet came. */
    memcpy(&src_peer->endpoint, from, from_len);
    src_peer->endpoint_len = from_len;

    if (m->m_len == 0) {
        /* Keepalive. */
        src_peer->rx_pkts++;
        m_freem(m);
        noise_keypair_put(kp);
        return 0;
    }

    int ilen = inner_ip_len(m->m_data, (size_t)m->m_len);
    if (ilen < 0) {
        m_freem(m);
        noise_keypair_put(kp);
        return -1;
    }

    /* Anti-spoof: inner src must belong to the peer that authenticated. */
    void *owner = session_lookup_inner_src(s, m->m_data, (size_t)ilen);
    if (owner != (void *)src_peer) {
        src_peer->rx_dropped_aips++;
        wgs_log(s, "[rx] DROP inner src not in peer's allowed-ips");
        m_freem(m);
        noise_keypair_put(kp);
        return 0;  /* not a hard error */
    }

    src_peer->rx_pkts++;
    src_peer->rx_bytes += (uint64_t)ilen;

    if (s->cb.deliver_ip)
        s->cb.deliver_ip(s->cb.user_ctx, m->m_data, (size_t)ilen);

    m_freem(m);
    noise_keypair_put(kp);
    return 0;
}

/* Find the peer with a pending handshake whose local_idx matches. */
static struct wgs_peer *
find_pending(wg_session_t *s, uint32_t r_idx)
{
    for (int i = 0; i < s->n_peers; i++) {
        if (s->peers[i].hs_pending && s->peers[i].hs_local_idx == r_idx)
            return &s->peers[i];
    }
    return NULL;
}

static int
wgs_handle_initiation(wg_session_t *s, uint8_t *bytes, size_t len,
                      const struct sockaddr *from, socklen_t from_len)
{
    struct wgs_pkt_initiation pkt;
    if (len < sizeof(pkt)) return -1;
    memcpy(&pkt, bytes, sizeof(pkt));

    int rc = cookie_checker_validate_macs(&s->checker, &pkt.m,
                                          bytes, sizeof(pkt) - sizeof(pkt.m),
                                          false /* under_load */,
                                          (struct sockaddr *)from, NULL);
    if (rc != 0) {
        wgs_log(s, "[hs] initiation mac1 failed");
        return -1;
    }

    struct noise_remote *matched = NULL;
    if (noise_consume_initiation(s->local, &matched,
                                 pkt.s_idx, pkt.ue, pkt.es, pkt.ets) != 0) {
        wgs_log(s, "[hs] noise_consume_initiation failed");
        return -1;
    }
    struct wgs_peer *peer = matched
                             ? (struct wgs_peer *)noise_remote_arg(matched)
                             : NULL;
    if (!peer) {
        if (matched) noise_remote_put(matched);
        return -1;
    }

    struct wgs_pkt_response resp;
    memset(&resp, 0, sizeof(resp));
    if (noise_create_response(matched, &resp.s_idx, &resp.r_idx,
                              resp.ue, resp.en) != 0) {
        noise_remote_put(matched);
        return -1;
    }
    resp.t = WGS_PKT_RESPONSE;
    cookie_maker_mac(&peer->cookie, &resp.m, &resp,
                     sizeof(resp) - sizeof(resp.m));
    if (s->cb.send_udp) {
        s->cb.send_udp(s->cb.user_ctx, (uint8_t *)&resp, sizeof(resp),
                       from, from_len);
    }
    noise_remote_put(matched);

    memcpy(&peer->endpoint, from, from_len);
    peer->endpoint_len  = from_len;
    peer->keypair_birth = time(NULL);
    peer->last_authd_tx = peer->keypair_birth;
    peer->hs_pending    = false;
    wgs_log(s, "[hs] responded to incoming initiation");
    return 0;
}

static int
wgs_handle_response(wg_session_t *s, const uint8_t *bytes, size_t len)
{
    struct wgs_pkt_response pkt;
    if (len < sizeof(pkt)) return -1;
    memcpy(&pkt, bytes, sizeof(pkt));

    struct wgs_peer *peer = find_pending(s, pkt.r_idx);
    if (!peer) {
        wgs_log(s, "[hs] response r_idx 0x%08x has no pending peer",
                (unsigned)pkt.r_idx);
        return -1;
    }
    struct noise_remote *matched = NULL;
    if (noise_consume_response(s->local, &matched,
                               pkt.s_idx, pkt.r_idx, pkt.ue, pkt.en) != 0) {
        wgs_log(s, "[hs] noise_consume_response failed");
        return -1;
    }
    if (matched != peer->remote) {
        if (matched) noise_remote_put(matched);
        return -1;
    }
    noise_remote_put(matched);

    peer->hs_pending    = false;
    peer->hs_attempts   = 0;
    peer->keypair_birth = time(NULL);
    wgs_log(s, "[hs] rekey complete");
    return 0;
}

static int
wgs_handle_cookie(wg_session_t *s, const uint8_t *bytes, size_t len)
{
    struct wgs_pkt_cookie pkt;
    if (len < sizeof(pkt)) return -1;
    memcpy(&pkt, bytes, sizeof(pkt));
    struct wgs_peer *peer = find_pending(s, pkt.r_idx);
    if (!peer) return -1;
    if (cookie_maker_consume_payload(&peer->cookie, pkt.nonce, pkt.ec) == 0)
        wgs_log(s, "[rx] cookie reply consumed");
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────
 * Public API
 * ───────────────────────────────────────────────────────────────────────── */

wg_session_t *
wg_session_create(const char *config_text, size_t config_len,
                  wg_session_callbacks cb)
{
    if (!config_text) return NULL;
    if (config_len == 0) config_len = strlen(config_text);

    wg_session_t *s = (wg_session_t *)calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->cb = cb;

    if (crypto_init() != 0) { free(s); return NULL; }

    if (parse_config_text(s, config_text, config_len) != 0) {
        wgs_log(s, "config parse failed");
        crypto_deinit();
        free(s);
        return NULL;
    }

    s->local = noise_local_alloc(NULL);
    if (!s->local) goto err;
    noise_local_private(s->local, s->private_key);

    for (int i = 0; i < s->n_peers; i++) {
        struct wgs_peer *p = &s->peers[i];
        p->remote = noise_remote_alloc(s->local, p, p->pubkey);
        if (!p->remote) goto err;
        if (noise_remote_enable(p->remote) != 0) goto err;
        cookie_maker_init(&p->cookie, p->pubkey);
        p->cookie_inited = true;
        if (p->has_endpoint) {
            if (resolve_endpoint(p->endpoint_host, p->endpoint_port,
                                 &p->endpoint, &p->endpoint_len) != 0) {
                wgs_log(s, "peer #%d: endpoint resolution failed", i);
                /* Not fatal — peer stays in pure-responder state. */
                p->endpoint_len = 0;
            }
        }
    }

    cookie_checker_init(&s->checker);
    s->checker_inited = true;
    {
        uint8_t pub[WG_KEY_LEN], priv[WG_KEY_LEN];
        if (noise_local_keys(s->local, pub, priv) == 0)
            cookie_checker_update(&s->checker, pub);
    }

    aips_init(&s->aips_v4, 32);
    aips_init(&s->aips_v6, 128);
    s->aips_inited = true;
    for (int i = 0; i < s->n_peers; i++) {
        struct wgs_peer *p = &s->peers[i];
        for (int j = 0; j < p->n_allowed; j++) {
            struct aips_trie *t = (p->allowed[j].family == AF_INET)
                                      ? &s->aips_v4 : &s->aips_v6;
            aips_insert(t, p->allowed[j].addr, p->allowed[j].prefix_len, p);
        }
    }

    wgs_log(s, "session created: %d peer(s), listen_port=%u",
            s->n_peers, (unsigned)s->listen_port);
    return s;

err:
    wg_session_destroy(s);
    return NULL;
}

void
wg_session_destroy(wg_session_t *s)
{
    if (!s) return;
    if (s->aips_inited) {
        aips_destroy(&s->aips_v4);
        aips_destroy(&s->aips_v6);
    }
    if (s->checker_inited) cookie_checker_free(&s->checker);
    for (int i = 0; i < s->n_peers; i++) {
        if (s->peers[i].cookie_inited) cookie_maker_free(&s->peers[i].cookie);
        if (s->peers[i].remote) noise_remote_put(s->peers[i].remote);
    }
    if (s->local) noise_local_put(s->local);
    crypto_deinit();
    free(s);
}

int
wg_session_handle_udp(wg_session_t *s, const uint8_t *bytes, size_t len,
                      const struct sockaddr *from, socklen_t from_len)
{
    if (!s || !bytes || len < 4) return -1;
    uint32_t t;
    memcpy(&t, bytes, sizeof(t));
    if (t == WGS_PKT_DATA)       return wgs_handle_data(s, bytes, len, from, from_len);
    if (t == WGS_PKT_INITIATION) return wgs_handle_initiation(s, (uint8_t *)bytes, len, from, from_len);
    if (t == WGS_PKT_RESPONSE)   return wgs_handle_response(s, bytes, len);
    if (t == WGS_PKT_COOKIE)     return wgs_handle_cookie(s, bytes, len);
    wgs_log(s, "[rx] unknown pkt type 0x%08x", (unsigned)le32toh(t));
    return -1;
}

int
wg_session_handle_tun(wg_session_t *s, const uint8_t *bytes, size_t len)
{
    if (!s || !bytes || len < 1) return -1;
    struct wgs_peer *dst = session_lookup_dst(s, bytes, len);
    if (!dst) {
        wgs_log(s, "[tx] no peer owns inner dst; dropping");
        return -1;
    }
    return wgs_encap(s, dst, bytes, len);
}

void
wg_session_tick(wg_session_t *s)
{
    if (!s) return;
    time_t now = time(NULL);
    for (int i = 0; i < s->n_peers; i++) {
        struct wgs_peer *p = &s->peers[i];

        if (p->hs_pending && (now - p->hs_sent_at) >= REKEY_TIMEOUT_SEC) {
            if (p->hs_attempts >= MAX_HANDSHAKE_ATTEMPTS) {
                wgs_log(s, "[hs] giving up after %d attempts", p->hs_attempts);
                p->hs_pending  = false;
                p->hs_attempts = 0;
            } else {
                (void)wgs_send_initiation(s, p, "retransmit");
            }
        }
        if (!p->hs_pending && p->keypair_birth && p->endpoint_len > 0 &&
            (now - p->keypair_birth) >= REKEY_AFTER_TIME_SEC) {
            p->hs_attempts = 0;
            (void)wgs_send_initiation(s, p, "rekey");
        }
        if (p->pk_sec > 0 && p->last_authd_tx > 0 &&
            (now - p->last_authd_tx) >= p->pk_sec) {
            (void)wgs_encap(s, p, NULL, 0);
        }
    }
}

int
wg_session_kick(wg_session_t *s)
{
    if (!s) return -1;
    for (int i = 0; i < s->n_peers; i++) {
        if (s->peers[i].has_endpoint && s->peers[i].endpoint_len > 0)
            return wgs_send_initiation(s, &s->peers[i], "startup");
    }
    return -1;
}

uint16_t wg_session_listen_port(const wg_session_t *s) { return s ? s->listen_port : 0; }

int wg_session_iface_addr_count(const wg_session_t *s) { return s ? s->n_if_addrs : 0; }

int
wg_session_iface_addr_get(const wg_session_t *s, int i,
                          char *addr_out, int *prefix_out, int *family_out)
{
    if (!s || i < 0 || i >= s->n_if_addrs) return -1;
    const struct wgs_iface_addr *a = &s->if_addrs[i];
    if (addr_out) { strncpy(addr_out, a->addr_str, 63); addr_out[63] = 0; }
    if (prefix_out) *prefix_out = a->prefix_len;
    if (family_out) *family_out = a->family;
    return 0;
}

int wg_session_peer_count(const wg_session_t *s) { return s ? s->n_peers : 0; }

int
wg_session_peer_pubkey(const wg_session_t *s, int i, uint8_t *out)
{
    if (!s || i < 0 || i >= s->n_peers || !out) return -1;
    memcpy(out, s->peers[i].pubkey, WG_KEY_LEN);
    return 0;
}

int
wg_session_peer_allowed_count(const wg_session_t *s, int i)
{
    if (!s || i < 0 || i >= s->n_peers) return 0;
    return s->peers[i].n_allowed;
}

int
wg_session_peer_allowed_get(const wg_session_t *s, int i, int j,
                            char *addr_out, int *prefix_out, int *family_out)
{
    if (!s || i < 0 || i >= s->n_peers) return -1;
    if (j < 0 || j >= s->peers[i].n_allowed) return -1;
    const struct wgs_allowed_cidr *c = &s->peers[i].allowed[j];
    if (addr_out) {
        if (!inet_ntop(c->family, c->addr, addr_out, 64))
            addr_out[0] = 0;
    }
    if (prefix_out) *prefix_out = c->prefix_len;
    if (family_out) *family_out = c->family;
    return 0;
}

int
wg_session_peer_endpoint(const wg_session_t *s, int i,
                         char *addr_out, uint16_t *port_out)
{
    if (!s || i < 0 || i >= s->n_peers) return -1;
    const struct wgs_peer *p = &s->peers[i];
    if (p->endpoint_len == 0) return -1;
    if (p->endpoint.ss_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)&p->endpoint;
        if (addr_out) inet_ntop(AF_INET, &sin->sin_addr, addr_out, 80);
        if (port_out) *port_out = ntohs(sin->sin_port);
        return 0;
    }
    if (p->endpoint.ss_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)&p->endpoint;
        if (addr_out) inet_ntop(AF_INET6, &sin6->sin6_addr, addr_out, 80);
        if (port_out) *port_out = ntohs(sin6->sin6_port);
        return 0;
    }
    return -1;
}

int
wg_session_peer_keepalive(const wg_session_t *s, int i)
{
    if (!s || i < 0 || i >= s->n_peers) return 0;
    return s->peers[i].pk_sec;
}

int
wg_session_peer_transfer(const wg_session_t *s, int i,
                         uint64_t *rx_out, uint64_t *tx_out)
{
    if (!s || i < 0 || i >= s->n_peers) return -1;
    if (rx_out) *rx_out = s->peers[i].rx_bytes;
    if (tx_out) *tx_out = s->peers[i].tx_bytes;
    return 0;
}

int
wg_session_peer_handshake_age(const wg_session_t *s, int i)
{
    if (!s || i < 0 || i >= s->n_peers) return -1;
    if (!s->peers[i].keypair_birth) return -1;
    return (int)(time(NULL) - s->peers[i].keypair_birth);
}

/* Emit N hex bytes into out (no leading 0x, lowercase). out must have
 * room for 2*N bytes (no NUL). Used by the UAPI GET formatter. */
static void
hex_encode(char *out, const uint8_t *in, size_t n)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2*i]     = d[(in[i] >> 4) & 0xf];
        out[2*i + 1] = d[ in[i]       & 0xf];
    }
}

/* snprintf-style accumulator that keeps running totals even when the
 * destination buffer is full, so callers can size a buffer by passing
 * NULL/0 first and reading the returned length. */
static void
append_fmt(char **buf, size_t *cap, int *written, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int need = vsnprintf(*cap > 0 ? *buf : NULL,
                         *cap > 0 ? *cap : 0,
                         fmt, ap);
    va_end(ap);
    if (need < 0) return;
    *written += need;
    if ((size_t)need < *cap) {
        *buf += need;
        *cap -= (size_t)need;
    } else if (*cap > 0) {
        *buf += *cap - 1;  /* leave room for NUL */
        *cap = 1;
    }
}

int
wg_session_get_uapi(const wg_session_t *s, char *buf, size_t buf_len)
{
    if (!s) return 0;
    char *p = buf;
    size_t cap = buf_len;
    int written = 0;

    /* Interface. We deliberately do NOT expose the private key:
     * NetworkExtension host apps should not have a way to ask the
     * running extension for its static private key. "none" keeps the
     * wg(8) parser happy — it treats missing/none private_key as
     * "peer-only view". */
    append_fmt(&p, &cap, &written, "private_key=none\n");
    append_fmt(&p, &cap, &written, "listen_port=%u\n", (unsigned)s->listen_port);
    append_fmt(&p, &cap, &written, "fwmark=0\n");

    /* Per peer. */
    for (int i = 0; i < s->n_peers; i++) {
        const struct wgs_peer *peer = &s->peers[i];
        char pkhex[65];
        hex_encode(pkhex, peer->pubkey, WG_KEY_LEN);
        pkhex[64] = '\0';

        append_fmt(&p, &cap, &written, "public_key=%s\n", pkhex);
        /* We don't support PSK yet (the config parser doesn't read
         * PresharedKey), so always emit the all-zero sentinel that
         * wg(8) treats as "no PSK". */
        append_fmt(&p, &cap, &written,
                   "preshared_key=00000000000000000000000000000000"
                   "00000000000000000000000000000000\n");

        if (peer->endpoint_len > 0) {
            char addr[80] = {0}; uint16_t port = 0;
            if (peer->endpoint.ss_family == AF_INET) {
                const struct sockaddr_in *sin =
                    (const struct sockaddr_in *)&peer->endpoint;
                inet_ntop(AF_INET, &sin->sin_addr, addr, sizeof(addr));
                port = ntohs(sin->sin_port);
                append_fmt(&p, &cap, &written, "endpoint=%s:%u\n", addr, port);
            } else if (peer->endpoint.ss_family == AF_INET6) {
                const struct sockaddr_in6 *sin6 =
                    (const struct sockaddr_in6 *)&peer->endpoint;
                inet_ntop(AF_INET6, &sin6->sin6_addr, addr, sizeof(addr));
                port = ntohs(sin6->sin6_port);
                /* IPv6 endpoints use bracket notation per RFC 3986. */
                append_fmt(&p, &cap, &written, "endpoint=[%s]:%u\n", addr, port);
            }
        }

        /* last_handshake_time_{sec,nsec}: wg(8) semantics is "wallclock
         * at which the last handshake completed". We store monotonic
         * keypair_birth, so we emit the approximated wallclock (now -
         * age) as sec and nsec=0. 0/0 = never handshook. */
        if (peer->keypair_birth) {
            append_fmt(&p, &cap, &written,
                       "last_handshake_time_sec=%lld\n"
                       "last_handshake_time_nsec=0\n",
                       (long long)peer->keypair_birth);
        } else {
            append_fmt(&p, &cap, &written,
                       "last_handshake_time_sec=0\n"
                       "last_handshake_time_nsec=0\n");
        }

        append_fmt(&p, &cap, &written,
                   "tx_bytes=%llu\nrx_bytes=%llu\n",
                   (unsigned long long)peer->tx_bytes,
                   (unsigned long long)peer->rx_bytes);

        if (peer->pk_sec > 0) {
            append_fmt(&p, &cap, &written,
                       "persistent_keepalive_interval=%d\n", peer->pk_sec);
        }

        for (int j = 0; j < peer->n_allowed; j++) {
            const struct wgs_allowed_cidr *c = &peer->allowed[j];
            char ipbuf[INET6_ADDRSTRLEN];
            if (!inet_ntop(c->family, c->addr, ipbuf, sizeof(ipbuf))) continue;
            append_fmt(&p, &cap, &written,
                       "allowed_ip=%s/%d\n", ipbuf, c->prefix_len);
        }

        append_fmt(&p, &cap, &written, "protocol_version=1\n");
    }

    /* Trailer per UAPI spec. */
    append_fmt(&p, &cap, &written, "errno=0\n\n");

    /* Ensure NUL termination on success. */
    if (buf_len > 0)
        buf[buf_len - 1 < (size_t)written ? buf_len - 1 : (size_t)written] = '\0';
    return written;
}

int
wg_session_status(const wg_session_t *s, char *buf, size_t buf_len)
{
    if (!s || !buf || buf_len == 0) return 0;
    time_t now = time(NULL);
    int off = 0;
    off += snprintf(buf + off, buf_len - off,
                    "peers: %d  listen_port: %u\n",
                    s->n_peers, (unsigned)s->listen_port);
    for (int i = 0; i < s->n_peers && off < (int)buf_len; i++) {
        const struct wgs_peer *p = &s->peers[i];
        off += snprintf(buf + off, buf_len - off,
                        "peer #%d: tx=%llu/%lluB rx=%llu/%lluB "
                        "kp_age=%lds hs=%s\n",
                        i,
                        (unsigned long long)p->tx_pkts,
                        (unsigned long long)p->tx_bytes,
                        (unsigned long long)p->rx_pkts,
                        (unsigned long long)p->rx_bytes,
                        p->keypair_birth ? (long)(now - p->keypair_birth) : -1L,
                        p->hs_pending ? "pending" : "idle");
    }
    return off;
}
