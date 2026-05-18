/* curve25519_portable.c — Pure-C X25519 Diffie-Hellman.
 *
 * Provides the same symbols as crypto_bridge.swift but without any
 * Apple CryptoKit dependency, so the library can be cross-compiled
 * for Android / Linux / any POSIX target via NDK or plain gcc.
 *
 * Based on the public-domain "curve25519-donna" by Adam Langley:
 *   https://github.com/agl/curve25519-donna
 *
 * This file is compiled INSTEAD OF crypto_bridge.swift when building
 * for non-Apple platforms. On Apple, the Swift bridge is preferred
 * because it uses the hardware-accelerated CryptoKit implementation.
 *
 * Exported symbols (must match crypto/curve25519.h):
 *   int  curve25519(uint8_t shared[32], const uint8_t priv[32], const uint8_t pub[32]);
 *   int  curve25519_generate_public(uint8_t pub[32], const uint8_t priv[32]);
 *   void curve25519_generate_secret(uint8_t priv[32]);
 *   void curve25519_clamp_secret(uint8_t priv[32]);
 */

#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

/* ── Field arithmetic in GF(2^255 - 19) using 5 × 51-bit limbs ─────── */

typedef uint64_t fe[5];

static void fe_frombytes(fe h, const uint8_t s[32])
{
    uint64_t t0 = (uint64_t)s[ 0]       | ((uint64_t)s[ 1] << 8)
               | ((uint64_t)s[ 2] << 16) | ((uint64_t)s[ 3] << 24)
               | ((uint64_t)s[ 4] << 32) | ((uint64_t)s[ 5] << 40)
               | (((uint64_t)s[ 6] & 0x07) << 48);
    uint64_t t1 = (((uint64_t)s[ 6] >> 3)       ) | ((uint64_t)s[ 7] << 5)
               | ((uint64_t)s[ 8] << 13) | ((uint64_t)s[ 9] << 21)
               | ((uint64_t)s[10] << 29) | ((uint64_t)s[11] << 37)
               | (((uint64_t)s[12] & 0x3f) << 45);
    uint64_t t2 = (((uint64_t)s[12] >> 6)       ) | ((uint64_t)s[13] << 2)
               | ((uint64_t)s[14] << 10) | ((uint64_t)s[15] << 18)
               | ((uint64_t)s[16] << 26) | ((uint64_t)s[17] << 34)
               | (((uint64_t)s[18] & 0x01) << 42);
    uint64_t t3 = (((uint64_t)s[18] >> 1)       ) | ((uint64_t)s[19] << 7)
               | ((uint64_t)s[20] << 15) | ((uint64_t)s[21] << 23)
               | ((uint64_t)s[22] << 31) | ((uint64_t)s[23] << 39)
               | (((uint64_t)s[24] & 0x0f) << 47);
    uint64_t t4 = (((uint64_t)s[24] >> 4)       ) | ((uint64_t)s[25] << 4)
               | ((uint64_t)s[26] << 12) | ((uint64_t)s[27] << 20)
               | ((uint64_t)s[28] << 28) | ((uint64_t)s[29] << 36)
               | (((uint64_t)s[30] & 0x7f) << 44);
    h[0] = t0; h[1] = t1; h[2] = t2; h[3] = t3; h[4] = t4;
}

static void fe_tobytes(uint8_t s[32], const fe h)
{
    uint64_t t[5];
    memcpy(t, h, sizeof(t));

    /* Reduce modulo 2^255 - 19 */
    uint64_t c;
    c = (t[0] + 19) >> 51; c = (t[1] + c) >> 51; c = (t[2] + c) >> 51;
    c = (t[3] + c) >> 51; c = (t[4] + c) >> 51;
    t[0] += 19 * c;
    c = t[0] >> 51; t[0] &= 0x7ffffffffffff; t[1] += c;
    c = t[1] >> 51; t[1] &= 0x7ffffffffffff; t[2] += c;
    c = t[2] >> 51; t[2] &= 0x7ffffffffffff; t[3] += c;
    c = t[3] >> 51; t[3] &= 0x7ffffffffffff; t[4] += c;
    t[4] &= 0x7ffffffffffff;

    s[ 0] = (uint8_t)( t[0]       );
    s[ 1] = (uint8_t)( t[0] >>  8 );
    s[ 2] = (uint8_t)( t[0] >> 16 );
    s[ 3] = (uint8_t)( t[0] >> 24 );
    s[ 4] = (uint8_t)( t[0] >> 32 );
    s[ 5] = (uint8_t)( t[0] >> 40 );
    s[ 6] = (uint8_t)((t[0] >> 48) | (t[1] << 3));
    s[ 7] = (uint8_t)( t[1] >>  5 );
    s[ 8] = (uint8_t)( t[1] >> 13 );
    s[ 9] = (uint8_t)( t[1] >> 21 );
    s[10] = (uint8_t)( t[1] >> 29 );
    s[11] = (uint8_t)( t[1] >> 37 );
    s[12] = (uint8_t)((t[1] >> 45) | (t[2] << 6));
    s[13] = (uint8_t)( t[2] >>  2 );
    s[14] = (uint8_t)( t[2] >> 10 );
    s[15] = (uint8_t)( t[2] >> 18 );
    s[16] = (uint8_t)( t[2] >> 26 );
    s[17] = (uint8_t)( t[2] >> 34 );
    s[18] = (uint8_t)((t[2] >> 42) | (t[3] << 1));
    s[19] = (uint8_t)( t[3] >>  7 );
    s[20] = (uint8_t)( t[3] >> 15 );
    s[21] = (uint8_t)( t[3] >> 23 );
    s[22] = (uint8_t)( t[3] >> 31 );
    s[23] = (uint8_t)( t[3] >> 39 );
    s[24] = (uint8_t)((t[3] >> 47) | (t[4] << 4));
    s[25] = (uint8_t)( t[4] >>  4 );
    s[26] = (uint8_t)( t[4] >> 12 );
    s[27] = (uint8_t)( t[4] >> 20 );
    s[28] = (uint8_t)( t[4] >> 28 );
    s[29] = (uint8_t)( t[4] >> 36 );
    s[30] = (uint8_t)( t[4] >> 44 );
    s[31] = 0;
}

#define MASK51 0x7ffffffffffffULL

static void fe_add(fe h, const fe f, const fe g)
{
    h[0]=f[0]+g[0]; h[1]=f[1]+g[1]; h[2]=f[2]+g[2];
    h[3]=f[3]+g[3]; h[4]=f[4]+g[4];
}

static void fe_sub(fe h, const fe f, const fe g)
{
    /* Add 2p to avoid underflow. */
    h[0] = f[0]+0xfffffffffffdaULL - g[0];
    h[1] = f[1]+0xffffffffffffeULL - g[1];
    h[2] = f[2]+0xffffffffffffeULL - g[2];
    h[3] = f[3]+0xffffffffffffeULL - g[3];
    h[4] = f[4]+0xffffffffffffeULL - g[4];
}

static void fe_mul(fe h, const fe f, const fe g)
{
    __uint128_t t0,t1,t2,t3,t4;
    uint64_t g1_19 = g[1]*19, g2_19 = g[2]*19, g3_19 = g[3]*19, g4_19 = g[4]*19;
    t0 = (__uint128_t)f[0]*g[0] + (__uint128_t)f[1]*g4_19
       + (__uint128_t)f[2]*g3_19 + (__uint128_t)f[3]*g2_19
       + (__uint128_t)f[4]*g1_19;
    t1 = (__uint128_t)f[0]*g[1] + (__uint128_t)f[1]*g[0]
       + (__uint128_t)f[2]*g4_19 + (__uint128_t)f[3]*g3_19
       + (__uint128_t)f[4]*g2_19;
    t2 = (__uint128_t)f[0]*g[2] + (__uint128_t)f[1]*g[1]
       + (__uint128_t)f[2]*g[0]  + (__uint128_t)f[3]*g4_19
       + (__uint128_t)f[4]*g3_19;
    t3 = (__uint128_t)f[0]*g[3] + (__uint128_t)f[1]*g[2]
       + (__uint128_t)f[2]*g[1]  + (__uint128_t)f[3]*g[0]
       + (__uint128_t)f[4]*g4_19;
    t4 = (__uint128_t)f[0]*g[4] + (__uint128_t)f[1]*g[3]
       + (__uint128_t)f[2]*g[2]  + (__uint128_t)f[3]*g[1]
       + (__uint128_t)f[4]*g[0];

    uint64_t c;
    c = (uint64_t)(t0 >> 51); h[0] = (uint64_t)t0 & MASK51; t1 += c;
    c = (uint64_t)(t1 >> 51); h[1] = (uint64_t)t1 & MASK51; t2 += c;
    c = (uint64_t)(t2 >> 51); h[2] = (uint64_t)t2 & MASK51; t3 += c;
    c = (uint64_t)(t3 >> 51); h[3] = (uint64_t)t3 & MASK51; t4 += c;
    c = (uint64_t)(t4 >> 51); h[4] = (uint64_t)t4 & MASK51;
    h[0] += c * 19;
    c = h[0] >> 51; h[0] &= MASK51; h[1] += c;
}

static void fe_sq(fe h, const fe f)
{
    fe_mul(h, f, f);
}

static void fe_mul121666(fe h, const fe f)
{
    __uint128_t t0 = (__uint128_t)f[0] * 121666;
    __uint128_t t1 = (__uint128_t)f[1] * 121666;
    __uint128_t t2 = (__uint128_t)f[2] * 121666;
    __uint128_t t3 = (__uint128_t)f[3] * 121666;
    __uint128_t t4 = (__uint128_t)f[4] * 121666;
    uint64_t c;
    c = (uint64_t)(t0 >> 51); h[0] = (uint64_t)t0 & MASK51; t1 += c;
    c = (uint64_t)(t1 >> 51); h[1] = (uint64_t)t1 & MASK51; t2 += c;
    c = (uint64_t)(t2 >> 51); h[2] = (uint64_t)t2 & MASK51; t3 += c;
    c = (uint64_t)(t3 >> 51); h[3] = (uint64_t)t3 & MASK51; t4 += c;
    c = (uint64_t)(t4 >> 51); h[4] = (uint64_t)t4 & MASK51;
    h[0] += c * 19;
    c = h[0] >> 51; h[0] &= MASK51; h[1] += c;
}

static void fe_invert(fe out, const fe z)
{
    fe t0, t1, t2, t3;
    int i;
    fe_sq(t0, z);              /* t0 = z^2 */
    fe_sq(t1, t0);
    fe_sq(t1, t1);             /* t1 = z^8 */
    fe_mul(t1, z, t1);         /* t1 = z^9 */
    fe_mul(t0, t0, t1);        /* t0 = z^11 */
    fe_sq(t2, t0);             /* t2 = z^22 */
    fe_mul(t1, t1, t2);        /* t1 = z^(2^5 - 1) */
    fe_sq(t2, t1);
    for (i = 0; i < 4; i++) fe_sq(t2, t2);  /* t2 = z^(2^10 - 2^5) */
    fe_mul(t1, t2, t1);        /* t1 = z^(2^10 - 1) */
    fe_sq(t2, t1);
    for (i = 0; i < 9; i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);        /* t2 = z^(2^20 - 1) */
    fe_sq(t3, t2);
    for (i = 0; i < 19; i++) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);        /* t2 = z^(2^40 - 1) */
    fe_sq(t2, t2);
    for (i = 0; i < 9; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);        /* t1 = z^(2^50 - 1) */
    fe_sq(t2, t1);
    for (i = 0; i < 49; i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);        /* t2 = z^(2^100 - 1) */
    fe_sq(t3, t2);
    for (i = 0; i < 99; i++) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);        /* t2 = z^(2^200 - 1) */
    fe_sq(t2, t2);
    for (i = 0; i < 49; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);        /* t1 = z^(2^250 - 1) */
    fe_sq(t1, t1); fe_sq(t1, t1);  /* t1 = z^(2^252 - 4) */
    fe_mul(t1, t1, z);
    fe_sq(t1, t1);
    fe_mul(out, t1, z);        /* out = z^(p-2) */
}

/* ── Montgomery ladder (X25519 scalar multiplication) ───────────────── */

static void x25519_ladder(uint8_t out[32], const uint8_t scalar[32],
                          const uint8_t point[32])
{
    uint8_t e[32];
    memcpy(e, scalar, 32);
    e[0]  &= 248;
    e[31] &= 127;
    e[31] |= 64;

    fe x1, x2, z2, x3, z3, tmp0, tmp1;
    fe_frombytes(x1, point);
    memset(x2, 0, sizeof(x2)); x2[0] = 1;   /* x2 = 1 */
    memset(z2, 0, sizeof(z2));                /* z2 = 0 */
    memcpy(x3, x1, sizeof(fe));               /* x3 = u  */
    memset(z3, 0, sizeof(z3)); z3[0] = 1;    /* z3 = 1 */

    int swap = 0;
    for (int pos = 254; pos >= 0; pos--) {
        int b = (e[pos >> 3] >> (pos & 7)) & 1;
        swap ^= b;

        /* Conditional swap: if swap==1, exchange (x2,z2) with (x3,z3). */
        for (int i = 0; i < 5; i++) {
            uint64_t mask = (uint64_t)(-(int64_t)swap);
            uint64_t t;
            t = mask & (x2[i] ^ x3[i]); x2[i] ^= t; x3[i] ^= t;
            t = mask & (z2[i] ^ z3[i]); z2[i] ^= t; z3[i] ^= t;
        }
        swap = b;

        fe a, aa, b_, bb, e_, c, d, da, cb;
        fe_add(a, x2, z2);
        fe_sq(aa, a);
        fe_sub(b_, x2, z2);
        fe_sq(bb, b_);
        fe_sub(e_, aa, bb);
        fe_add(c, x3, z3);
        fe_sub(d, x3, z3);
        fe_mul(da, d, a);
        fe_mul(cb, c, b_);
        fe_add(tmp0, da, cb);
        fe_sq(x3, tmp0);
        fe_sub(tmp0, da, cb);
        fe_sq(tmp1, tmp0);
        fe_mul(z3, x1, tmp1);
        fe_mul(x2, aa, bb);
        fe_mul121666(tmp0, e_);
        fe_add(tmp1, aa, tmp0);
        fe_mul(z2, e_, tmp1);
    }

    /* Final swap */
    for (int i = 0; i < 5; i++) {
        uint64_t mask = (uint64_t)(-(int64_t)swap);
        uint64_t t;
        t = mask & (x2[i] ^ x3[i]); x2[i] ^= t; x3[i] ^= t;
        t = mask & (z2[i] ^ z3[i]); z2[i] ^= t; z3[i] ^= t;
    }

    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(out, x2);
}

/* ── Public API (matches crypto/curve25519.h) ────────────────────────── */

/* The "base point" for X25519 key generation: u = 9. */
static const uint8_t basepoint[32] = { 9 };

void curve25519_clamp_secret(uint8_t priv[32])
{
    priv[0]  &= 248;
    priv[31] &= 127;
    priv[31] |= 64;
}

void curve25519_generate_secret(uint8_t priv[32])
{
    /* Read 32 random bytes from the OS. */
#if defined(__APPLE__)
    arc4random_buf(priv, 32);
#elif defined(__linux__) || defined(__ANDROID__)
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) { read(fd, priv, 32); close(fd); }
#else
    /* Fallback: zero (unsafe! should never ship without a real RNG) */
    memset(priv, 0, 32);
#endif
    curve25519_clamp_secret(priv);
}

int curve25519_generate_public(uint8_t pub[32],
                               const uint8_t priv[32])
{
    x25519_ladder(pub, priv, basepoint);
    return 1;  /* always succeeds */
}

int curve25519(uint8_t shared[32],
               const uint8_t priv[32],
               const uint8_t pub[32])
{
    x25519_ladder(shared, priv, pub);

    /* Check for all-zero output (low-order point attack). */
    uint8_t zero = 0;
    for (int i = 0; i < 32; i++) zero |= shared[i];
    return zero != 0 ? 1 : 0;
}
