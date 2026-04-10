/* wg_crypto_impl.c – macOS userspace ChaCha20-Poly1305 + crypto_dispatch
 *
 * Implements:
 *   chacha20_poly1305_encrypt / decrypt   (buffer API used by crypto.h)
 *   xchacha20_poly1305_encrypt / decrypt  (XChaCha variant)
 *   crypto_dispatch                       (mbuf API used by wg_crypto.c)
 *
 * Algorithm: RFC 8439 (ChaCha20-Poly1305).
 * Self-contained pure C; no external crypto dependency.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

#include <sys/endian.h>     /* le32dec, le64dec, le32enc, le64enc */
#include <sys/mbuf.h>
#include <opencrypto/cryptodev.h>
#include "crypto.h"

/* ══════════════════════════════════════════════════════════════════════════
 * ChaCha20 (RFC 8439 §2.1)
 * ══════════════════════════════════════════════════════════════════════════ */

#define ROTL32(v,n) (((v) << (n)) | ((v) >> (32-(n))))

#define QR(a,b,c,d) \
    a += b; d ^= a; d = ROTL32(d,16); \
    c += d; b ^= c; b = ROTL32(b,12); \
    a += b; d ^= a; d = ROTL32(d, 8); \
    c += d; b ^= c; b = ROTL32(b, 7)

static void
chacha20_block(const uint32_t in[16], uint8_t out[64])
{
    uint32_t x[16];
    int i;
    memcpy(x, in, 64);
    for (i = 0; i < 10; i++) {
        QR(x[0],x[4],x[ 8],x[12]);
        QR(x[1],x[5],x[ 9],x[13]);
        QR(x[2],x[6],x[10],x[14]);
        QR(x[3],x[7],x[11],x[15]);
        QR(x[0],x[5],x[10],x[15]);
        QR(x[1],x[6],x[11],x[12]);
        QR(x[2],x[7],x[ 8],x[13]);
        QR(x[3],x[4],x[ 9],x[14]);
    }
    for (i = 0; i < 16; i++) {
        uint32_t v = x[i] + in[i];
        out[i*4+0] = (uint8_t)(v      );
        out[i*4+1] = (uint8_t)(v >>  8);
        out[i*4+2] = (uint8_t)(v >> 16);
        out[i*4+3] = (uint8_t)(v >> 24);
    }
}

/* key: 32 bytes, nonce: 12 bytes (RFC 8439 96-bit), counter starts at ctr0.
 * XORs 'len' bytes of keystream into buf. */
static void
chacha20_xor(uint8_t *buf, size_t len,
             const uint8_t key[32], const uint8_t nonce12[12],
             uint32_t ctr0)
{
    uint32_t state[16];
    uint8_t  block[64];

    state[0]  = 0x61707865u;
    state[1]  = 0x3320646eu;
    state[2]  = 0x79622d32u;
    state[3]  = 0x6b206574u;
    state[4]  = le32dec(key +  0);
    state[5]  = le32dec(key +  4);
    state[6]  = le32dec(key +  8);
    state[7]  = le32dec(key + 12);
    state[8]  = le32dec(key + 16);
    state[9]  = le32dec(key + 20);
    state[10] = le32dec(key + 24);
    state[11] = le32dec(key + 28);
    state[12] = ctr0;
    state[13] = le32dec(nonce12 + 0);
    state[14] = le32dec(nonce12 + 4);
    state[15] = le32dec(nonce12 + 8);

    while (len > 0) {
        chacha20_block(state, block);
        size_t n = len < 64 ? len : 64;
        for (size_t i = 0; i < n; i++)
            buf[i] ^= block[i];
        buf += n;
        len -= n;
        state[12]++;
    }
    memset(block, 0, sizeof(block));
}

/* Generate Poly1305 key (first 32 bytes of ChaCha20 with counter=0) */
static void
poly1305_key_gen(uint8_t poly_key[32],
                 const uint8_t key[32], const uint8_t nonce12[12])
{
    uint32_t state[16];
    uint8_t  block[64];

    state[0]  = 0x61707865u;
    state[1]  = 0x3320646eu;
    state[2]  = 0x79622d32u;
    state[3]  = 0x6b206574u;
    state[4]  = le32dec(key +  0);
    state[5]  = le32dec(key +  4);
    state[6]  = le32dec(key +  8);
    state[7]  = le32dec(key + 12);
    state[8]  = le32dec(key + 16);
    state[9]  = le32dec(key + 20);
    state[10] = le32dec(key + 24);
    state[11] = le32dec(key + 28);
    state[12] = 0;
    state[13] = le32dec(nonce12 + 0);
    state[14] = le32dec(nonce12 + 4);
    state[15] = le32dec(nonce12 + 8);
    chacha20_block(state, block);
    memcpy(poly_key, block, 32);
    memset(block, 0, sizeof(block));
}

/* ══════════════════════════════════════════════════════════════════════════
 * Poly1305 (RFC 8439 §2.5)
 * ══════════════════════════════════════════════════════════════════════════ */

/* 130-bit accumulator using five 26-bit limbs. */
typedef struct {
    uint32_t r[5];       /* key r (clamped) */
    uint32_t s[4];       /* key s           */
    uint32_t h[5];       /* accumulator     */
    uint8_t  buf[16];    /* partial block buffer */
    size_t   buflen;     /* bytes in buf    */
} poly1305_ctx;

static void
poly1305_init(poly1305_ctx *ctx, const uint8_t key[32])
{
    /* r is clamped: low bits of every 4th byte zeroed */
    uint32_t t0 = le32dec(key +  0);
    uint32_t t1 = le32dec(key +  4);
    uint32_t t2 = le32dec(key +  8);
    uint32_t t3 = le32dec(key + 12);

    ctx->r[0] = ( t0                    ) & 0x3ffffff;
    ctx->r[1] = ((t0 >> 26) | (t1 <<  6)) & 0x3ffff03;
    ctx->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
    ctx->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
    ctx->r[4] = ( t3 >>  8               ) & 0x00fffff;

    ctx->s[0] = le32dec(key + 16);
    ctx->s[1] = le32dec(key + 20);
    ctx->s[2] = le32dec(key + 24);
    ctx->s[3] = le32dec(key + 28);

    memset(ctx->h, 0, sizeof(ctx->h));
    ctx->buflen = 0;
}

static void
poly1305_block(poly1305_ctx *ctx, const uint8_t *m, uint32_t hibit)
{
    uint64_t d[5];
    uint32_t h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2],
             h3 = ctx->h[3], h4 = ctx->h[4];
    uint32_t r0 = ctx->r[0], r1 = ctx->r[1], r2 = ctx->r[2],
             r3 = ctx->r[3], r4 = ctx->r[4];
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;

    uint32_t t0 = le32dec(m +  0);
    uint32_t t1 = le32dec(m +  4);
    uint32_t t2 = le32dec(m +  8);
    uint32_t t3 = le32dec(m + 12);

    h0 += ( t0                    ) & 0x3ffffff;
    h1 += ((t0 >> 26) | (t1 <<  6)) & 0x3ffffff;
    h2 += ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
    h3 += ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
    h4 += ( t3 >>  8               ) | hibit;

    d[0] = (uint64_t)h0*r0 + (uint64_t)h1*s4 + (uint64_t)h2*s3
                            + (uint64_t)h3*s2 + (uint64_t)h4*s1;
    d[1] = (uint64_t)h0*r1 + (uint64_t)h1*r0 + (uint64_t)h2*s4
                            + (uint64_t)h3*s3 + (uint64_t)h4*s2;
    d[2] = (uint64_t)h0*r2 + (uint64_t)h1*r1 + (uint64_t)h2*r0
                            + (uint64_t)h3*s4 + (uint64_t)h4*s3;
    d[3] = (uint64_t)h0*r3 + (uint64_t)h1*r2 + (uint64_t)h2*r1
                            + (uint64_t)h3*r0 + (uint64_t)h4*s4;
    d[4] = (uint64_t)h0*r4 + (uint64_t)h1*r3 + (uint64_t)h2*r2
                            + (uint64_t)h3*r1 + (uint64_t)h4*r0;

    uint64_t c;
    c = d[0] >> 26; h0 = (uint32_t)(d[0]) & 0x3ffffff;
    d[1] += c;
    c = d[1] >> 26; h1 = (uint32_t)(d[1]) & 0x3ffffff;
    d[2] += c;
    c = d[2] >> 26; h2 = (uint32_t)(d[2]) & 0x3ffffff;
    d[3] += c;
    c = d[3] >> 26; h3 = (uint32_t)(d[3]) & 0x3ffffff;
    d[4] += c;
    c = d[4] >> 26; h4 = (uint32_t)(d[4]) & 0x3ffffff;
    h0 += (uint32_t)(c * 5);
    c = h0 >> 26;   h0 &= 0x3ffffff;
    h1 += (uint32_t)c;

    ctx->h[0]=h0; ctx->h[1]=h1; ctx->h[2]=h2;
    ctx->h[3]=h3; ctx->h[4]=h4;
}

static void
poly1305_update(poly1305_ctx *ctx, const uint8_t *m, size_t len)
{
    /* Drain any buffered partial block first. */
    if (ctx->buflen > 0) {
        size_t want = 16 - ctx->buflen;
        if (len < want) {
            memcpy(ctx->buf + ctx->buflen, m, len);
            ctx->buflen += len;
            return;
        }
        memcpy(ctx->buf + ctx->buflen, m, want);
        poly1305_block(ctx, ctx->buf, 1u << 24);
        m   += want;
        len -= want;
        ctx->buflen = 0;
    }
    /* Process full 16-byte blocks straight from the input. */
    while (len >= 16) {
        poly1305_block(ctx, m, 1u << 24);
        m   += 16;
        len -= 16;
    }
    /* Stash any remaining partial block for the next update / finish. */
    if (len > 0) {
        memcpy(ctx->buf, m, len);
        ctx->buflen = len;
    }
}

static void
poly1305_finish(poly1305_ctx *ctx, uint8_t tag[16])
{
    uint32_t h0, h1, h2, h3, h4;
    uint32_t c, g0, g1, g2, g3, g4, mask;
    uint64_t f;

    /* Flush any buffered partial block as the final block (hibit = 0 with
     * an explicit 0x01 byte after the data, per RFC 8439 §2.5.2). */
    if (ctx->buflen > 0) {
        uint8_t last[16] = {0};
        memcpy(last, ctx->buf, ctx->buflen);
        last[ctx->buflen] = 1;
        poly1305_block(ctx, last, 0);
        ctx->buflen = 0;
    }

    h0 = ctx->h[0]; h1 = ctx->h[1]; h2 = ctx->h[2];
    h3 = ctx->h[3]; h4 = ctx->h[4];

    /* fully carry h */
    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    /* compute h + -p */
    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    g4 = h4 + c - (1u << 26);

    /* select h if h < p, else h + -p */
    mask = (g4 >> 31) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    /* h = h % (2^128) */
    h0 = (h0      ) | (h1 << 26);
    h1 = (h1 >>  6) | (h2 << 20);
    h2 = (h2 >> 12) | (h3 << 14);
    h3 = (h3 >> 18) | (h4 <<  8);

    /* add s */
    f  = (uint64_t)h0 + ctx->s[0]; h0 = (uint32_t)f; f >>= 32;
    f += (uint64_t)h1 + ctx->s[1]; h1 = (uint32_t)f; f >>= 32;
    f += (uint64_t)h2 + ctx->s[2]; h2 = (uint32_t)f; f >>= 32;
    f += (uint64_t)h3 + ctx->s[3]; h3 = (uint32_t)f;

    uint32_t o[4] = { h0, h1, h2, h3 };
    memcpy(tag, o, 16);
}

/* ══════════════════════════════════════════════════════════════════════════
 * Constant-time tag comparison
 * ══════════════════════════════════════════════════════════════════════════ */
static int
ct_memcmp(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    while (n--) diff |= *a++ ^ *b++;
    return diff;
}

/* ══════════════════════════════════════════════════════════════════════════
 * PAD16 helper: feed zero padding to bring Poly1305 to 16-byte boundary
 * ══════════════════════════════════════════════════════════════════════════ */
static void
poly1305_pad16(poly1305_ctx *ctx, size_t len)
{
    static const uint8_t zeros[16] = {0};
    size_t rem = len & 15;
    if (rem)
        poly1305_update(ctx, zeros, 16 - rem);
}

/* ══════════════════════════════════════════════════════════════════════════
 * RFC 8439 AEAD construction
 *
 * nonce12: 96-bit nonce (4 bytes zeros || 8 bytes LE nonce)
 * dst must have room for src_len + 16 bytes (tag appended).
 * ══════════════════════════════════════════════════════════════════════════ */
static void
aead_encrypt_96(uint8_t *dst, const uint8_t *src, size_t src_len,
                const uint8_t *ad,  size_t ad_len,
                const uint8_t nonce12[12], const uint8_t key[32])
{
    uint8_t        poly_key[32];
    poly1305_ctx   mac;
    uint8_t        len_buf[8];

    poly1305_key_gen(poly_key, key, nonce12);
    poly1305_init(&mac, poly_key);

    /* Encrypt */
    memcpy(dst, src, src_len);
    chacha20_xor(dst, src_len, key, nonce12, 1);

    /* MAC: AAD || pad || ciphertext || pad || len(aad) || len(ct) */
    poly1305_update(&mac, ad,  ad_len);  poly1305_pad16(&mac, ad_len);
    poly1305_update(&mac, dst, src_len); poly1305_pad16(&mac, src_len);
    le64enc(len_buf, (uint64_t)ad_len);  poly1305_update(&mac, len_buf, 8);
    le64enc(len_buf, (uint64_t)src_len); poly1305_update(&mac, len_buf, 8);
    poly1305_finish(&mac, dst + src_len);

    memset(poly_key, 0, sizeof(poly_key));
}

static bool
aead_decrypt_96(uint8_t *dst, const uint8_t *src, size_t src_len,
                const uint8_t *ad, size_t ad_len,
                const uint8_t nonce12[12], const uint8_t key[32])
{
    /* src_len includes the 16-byte tag */
    if (src_len < 16) return false;
    size_t         ct_len = src_len - 16;
    const uint8_t *tag    = src + ct_len;

    uint8_t        poly_key[32];
    poly1305_ctx   mac;
    uint8_t        expected_tag[16];
    uint8_t        len_buf[8];

    poly1305_key_gen(poly_key, key, nonce12);
    poly1305_init(&mac, poly_key);

    poly1305_update(&mac, ad,  ad_len);  poly1305_pad16(&mac, ad_len);
    poly1305_update(&mac, src, ct_len);  poly1305_pad16(&mac, ct_len);
    le64enc(len_buf, (uint64_t)ad_len);  poly1305_update(&mac, len_buf, 8);
    le64enc(len_buf, (uint64_t)ct_len);  poly1305_update(&mac, len_buf, 8);
    poly1305_finish(&mac, expected_tag);
    memset(poly_key, 0, sizeof(poly_key));

    if (ct_memcmp(expected_tag, tag, 16) != 0)
        return false;

    memcpy(dst, src, ct_len);
    chacha20_xor(dst, ct_len, key, nonce12, 1);
    return true;
}

/* Build 96-bit nonce from 8-byte LE nonce */
static void
nonce8_to_12(uint8_t n12[12], const uint8_t nonce8[8])
{
    memset(n12, 0, 4);
    memcpy(n12 + 4, nonce8, 8);
}

/* ══════════════════════════════════════════════════════════════════════════
 * Public buffer API  (declared in crypto/chacha20_poly1305.h)
 * ══════════════════════════════════════════════════════════════════════════ */

void
chacha20_poly1305_encrypt(uint8_t *dst,
    const uint8_t *src, size_t src_len,
    const uint8_t *ad,  size_t ad_len,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *key)
{
    uint8_t n12[12];
    if (nonce_len == 12) {
        memcpy(n12, nonce, 12);
    } else {
        /* 8-byte nonce (WireGuard standard) */
        nonce8_to_12(n12, nonce);
    }
    aead_encrypt_96(dst, src, src_len, ad, ad_len, n12, key);
}

bool
chacha20_poly1305_decrypt(uint8_t *dst,
    const uint8_t *src, size_t src_len,
    const uint8_t *ad,  size_t ad_len,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *key)
{
    uint8_t n12[12];
    if (nonce_len == 12) {
        memcpy(n12, nonce, 12);
    } else {
        nonce8_to_12(n12, nonce);
    }
    return aead_decrypt_96(dst, src, src_len, ad, ad_len, n12, key);
}

/* XChaCha20-Poly1305: derive subkey via HChaCha20, then encrypt with
 * nonce = 0x00..00 || nonce[16..23] */
static void
hchacha20(uint8_t out[32], const uint8_t nonce16[16], const uint8_t key[32])
{
    uint32_t x[16];
    int i;
    x[0]  = 0x61707865u;
    x[1]  = 0x3320646eu;
    x[2]  = 0x79622d32u;
    x[3]  = 0x6b206574u;
    x[4]  = le32dec(key +  0);
    x[5]  = le32dec(key +  4);
    x[6]  = le32dec(key +  8);
    x[7]  = le32dec(key + 12);
    x[8]  = le32dec(key + 16);
    x[9]  = le32dec(key + 20);
    x[10] = le32dec(key + 24);
    x[11] = le32dec(key + 28);
    x[12] = le32dec(nonce16 +  0);
    x[13] = le32dec(nonce16 +  4);
    x[14] = le32dec(nonce16 +  8);
    x[15] = le32dec(nonce16 + 12);
    for (i = 0; i < 10; i++) {
        QR(x[0],x[4],x[ 8],x[12]);
        QR(x[1],x[5],x[ 9],x[13]);
        QR(x[2],x[6],x[10],x[14]);
        QR(x[3],x[7],x[11],x[15]);
        QR(x[0],x[5],x[10],x[15]);
        QR(x[1],x[6],x[11],x[12]);
        QR(x[2],x[7],x[ 8],x[13]);
        QR(x[3],x[4],x[ 9],x[14]);
    }
    uint32_t o[8] = { x[0],x[1],x[2],x[3], x[12],x[13],x[14],x[15] };
    memcpy(out, o, 32);
}

void
xchacha20_poly1305_encrypt(uint8_t *dst,
    const uint8_t *src, size_t src_len,
    const uint8_t *ad,  size_t ad_len,
    const uint8_t nonce[24], const uint8_t key[32])
{
    uint8_t subkey[32];
    uint8_t n12[12];
    hchacha20(subkey, nonce, key);
    memset(n12, 0, 4);
    memcpy(n12 + 4, nonce + 16, 8);
    aead_encrypt_96(dst, src, src_len, ad, ad_len, n12, subkey);
    memset(subkey, 0, sizeof(subkey));
}

bool
xchacha20_poly1305_decrypt(uint8_t *dst,
    const uint8_t *src, size_t src_len,
    const uint8_t *ad,  size_t ad_len,
    const uint8_t nonce[24], const uint8_t key[32])
{
    uint8_t subkey[32];
    uint8_t n12[12];
    bool    ok;
    hchacha20(subkey, nonce, key);
    memset(n12, 0, 4);
    memcpy(n12 + 4, nonce + 16, 8);
    ok = aead_decrypt_96(dst, src, src_len, ad, ad_len, n12, subkey);
    memset(subkey, 0, sizeof(subkey));
    return ok;
}

/* ══════════════════════════════════════════════════════════════════════════
 * crypto_dispatch: mbuf in-place encrypt / decrypt
 *
 * Called from wg_crypto.c's chacha20poly1305_encrypt_mbuf /
 * chacha20poly1305_decrypt_mbuf.  The mbuf is linear (our stub), so we
 * can work directly on m_data.
 *
 * NOTE: This implementation is SPECIFIC TO THE WIREGUARD TRANSPORT PATH.
 * AAD length is hard-coded to 0 because WireGuard data packets carry no
 * additional-authenticated-data. Do not reuse this as a general-purpose
 * crypto_dispatch — the handshake path uses the buffer API
 * (chacha20_poly1305_encrypt / _decrypt) which handles AAD properly.
 * ══════════════════════════════════════════════════════════════════════════ */

#define POLY1305_HASH_LEN 16

int
crypto_dispatch(struct cryptop *crp)
{
    struct mbuf *m        = crp->_crp_mbuf;
    int          pay_len  = crp->crp_payload_length;   /* plaintext/ct len */
    int          tag_off  = crp->crp_digest_start;     /* where tag lives  */
    const uint8_t *key    = crp->crp_cipher_key;

    /* Build 96-bit nonce: 4 zero bytes || 8-byte LE nonce from crp_iv */
    uint8_t n12[12];
    memset(n12, 0, 4);
    memcpy(n12 + 4, crp->crp_iv, 8);

    /* We need a scratch buffer: encrypted output + tag */
    uint8_t *plain  = m->m_data;               /* plaintext starts at 0 */
    uint8_t *ct_buf = plain + tag_off;          /* where to put ciphertext/tag */

    if (crp->crp_op & CRYPTO_OP_ENCRYPT) {
        /* in-place: encrypt pay_len bytes, write 16-byte tag at tag_off */
        uint8_t poly_key[32];
        poly1305_ctx mac;
        uint8_t len_buf[8];

        poly1305_key_gen(poly_key, key, n12);
        poly1305_init(&mac, poly_key);

        /* Encrypt payload in-place (no AAD in WireGuard mbuf path) */
        chacha20_xor(plain, (size_t)pay_len, key, n12, 1);

        poly1305_update(&mac, plain, (size_t)pay_len);
        poly1305_pad16(&mac, (size_t)pay_len);
        le64enc(len_buf, 0);                      /* aad_len = 0 */
        poly1305_update(&mac, len_buf, 8);
        le64enc(len_buf, (uint64_t)pay_len);
        poly1305_update(&mac, len_buf, 8);
        poly1305_finish(&mac, ct_buf);            /* write tag */

        memset(poly_key, 0, sizeof(poly_key));
        (void)ct_buf;
        return 0;
    } else {
        /* Decrypt: verify tag at tag_off, then decrypt pay_len bytes */
        uint8_t poly_key[32];
        poly1305_ctx mac;
        uint8_t expected[16];
        uint8_t len_buf[8];

        poly1305_key_gen(poly_key, key, n12);
        poly1305_init(&mac, poly_key);

        poly1305_update(&mac, plain, (size_t)pay_len);
        poly1305_pad16(&mac, (size_t)pay_len);
        le64enc(len_buf, 0);
        poly1305_update(&mac, len_buf, 8);
        le64enc(len_buf, (uint64_t)pay_len);
        poly1305_update(&mac, len_buf, 8);
        poly1305_finish(&mac, expected);
        memset(poly_key, 0, sizeof(poly_key));

        if (ct_memcmp(expected, plain + tag_off, 16) != 0)
            return EBADMSG;

        chacha20_xor(plain, (size_t)pay_len, key, n12, 1);
        return 0;
    }
}
