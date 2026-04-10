/* FreeBSD crypto/siphash/siphash.h → self-contained SipHash-c-d stub */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define SIPHASH_KEY_LENGTH 16

typedef struct {
    uint64_t v0, v1, v2, v3;
} SIPHASH_CTX;

/* ---------- internal helpers ---------- */
#define _SH_ROTL64(x, b) (((x) << (b)) | ((x) >> (64 - (b))))

#define _SH_U64LE(p) (                              \
    ((uint64_t)((const uint8_t *)(p))[0])       |   \
    ((uint64_t)((const uint8_t *)(p))[1] <<  8) |   \
    ((uint64_t)((const uint8_t *)(p))[2] << 16) |   \
    ((uint64_t)((const uint8_t *)(p))[3] << 24) |   \
    ((uint64_t)((const uint8_t *)(p))[4] << 32) |   \
    ((uint64_t)((const uint8_t *)(p))[5] << 40) |   \
    ((uint64_t)((const uint8_t *)(p))[6] << 48) |   \
    ((uint64_t)((const uint8_t *)(p))[7] << 56))

#define _SH_ROUND(v0, v1, v2, v3) do {                 \
    (v0) += (v1); (v1) = _SH_ROTL64((v1), 13);         \
    (v1) ^= (v0); (v0) = _SH_ROTL64((v0), 32);         \
    (v2) += (v3); (v3) = _SH_ROTL64((v3), 16);         \
    (v3) ^= (v2);                                       \
    (v0) += (v3); (v3) = _SH_ROTL64((v3), 21);         \
    (v3) ^= (v0);                                       \
    (v2) += (v1); (v1) = _SH_ROTL64((v1), 17);         \
    (v1) ^= (v2); (v2) = _SH_ROTL64((v2), 32);         \
} while (0)

/* SipHash with configurable compression (c) and finalisation (d) rounds */
static inline uint64_t
SipHashX(SIPHASH_CTX *ctx __attribute__((unused)),
         int c_rounds, int d_rounds,
         const uint8_t key[SIPHASH_KEY_LENGTH],
         const void *src, size_t len)
{
    uint64_t k0 = _SH_U64LE(key);
    uint64_t k1 = _SH_U64LE((const uint8_t *)key + 8);
    uint64_t v0 = k0 ^ UINT64_C(0x736f6d6570736575);
    uint64_t v1 = k1 ^ UINT64_C(0x646f72616e646f6d);
    uint64_t v2 = k0 ^ UINT64_C(0x6c7967656e657261);
    uint64_t v3 = k1 ^ UINT64_C(0x7465646279746573);

    const uint8_t *p   = (const uint8_t *)src;
    const uint8_t *end = p + (len & ~(size_t)7);
    int i;

    for (; p != end; p += 8) {
        uint64_t m = _SH_U64LE(p);
        v3 ^= m;
        for (i = 0; i < c_rounds; i++) _SH_ROUND(v0, v1, v2, v3);
        v0 ^= m;
    }

    int left = (int)(len & 7);
    uint64_t b = (uint64_t)len << 56;
    switch (left) {
    case 7: b |= (uint64_t)p[6] << 48; /* fall through */
    case 6: b |= (uint64_t)p[5] << 40; /* fall through */
    case 5: b |= (uint64_t)p[4] << 32; /* fall through */
    case 4: b |= (uint64_t)p[3] << 24; /* fall through */
    case 3: b |= (uint64_t)p[2] << 16; /* fall through */
    case 2: b |= (uint64_t)p[1] <<  8; /* fall through */
    case 1: b |= (uint64_t)p[0];
    }
    v3 ^= b;
    for (i = 0; i < c_rounds; i++) _SH_ROUND(v0, v1, v2, v3);
    v0 ^= b;
    v2 ^= 0xff;
    for (i = 0; i < d_rounds; i++) _SH_ROUND(v0, v1, v2, v3);
    return v0 ^ v1 ^ v2 ^ v3;
}
