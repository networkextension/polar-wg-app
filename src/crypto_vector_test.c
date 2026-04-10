#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "crypto.h"
#include <crypto/curve25519.h>
#include <sys/mbuf.h>

static void print_hex(const uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; ++i)
        printf("%02x", buf[i]);
}

static int test_blake2s_abc(void)
{
    static const uint8_t msg[] = { 'a', 'b', 'c' };
    static const uint8_t expected[32] = {
        0x50, 0x8c, 0x5e, 0x8c, 0x32, 0x7c, 0x14, 0xe2,
        0xe1, 0xa7, 0x2b, 0xa3, 0x4e, 0xeb, 0x45, 0x2f,
        0x37, 0x45, 0x8b, 0x20, 0x9e, 0xd6, 0x3a, 0x29,
        0x4d, 0x99, 0x9b, 0x4c, 0x86, 0x67, 0x59, 0x82
    };
    uint8_t out[32];

    blake2s(out, msg, NULL, sizeof(out), sizeof(msg), 0);
    if (memcmp(out, expected, sizeof(out)) != 0) {
        printf("[FAIL] blake2s(\"abc\")\n");
        printf("  expected: "); print_hex(expected, sizeof(expected)); printf("\n");
        printf("  actual  : "); print_hex(out, sizeof(out)); printf("\n");
        return 1;
    }
    printf("[PASS] blake2s(\"abc\") vector\n");
    return 0;
}

/* Two more well-known Blake2s-256 hashes:
 *   1. Empty string (canonical, see Linux blake2s_testvecs[0])
 *   2. The pangram "The quick brown fox jumps over the lazy dog"
 * Both inputs are < 64 bytes so they don't exercise multi-block on
 * their own — the streaming consistency test below covers that. */
static int test_blake2s_more_kats(void)
{
    static const uint8_t empty_expected[32] = {
        0x69,0x21,0x7a,0x30,0x79,0x90,0x80,0x94,
        0xe1,0x11,0x21,0xd0,0x42,0x35,0x4a,0x7c,
        0x1f,0x55,0xb6,0x48,0x2c,0xa1,0xa5,0x1e,
        0x1b,0x25,0x0d,0xfd,0x1e,0xd0,0xee,0xf9,
    };
    static const char fox_msg[] = "The quick brown fox jumps over the lazy dog";
    static const uint8_t fox_expected[32] = {
        0x60,0x6b,0xee,0xec,0x74,0x3c,0xcb,0xef,
        0xf6,0xcb,0xcd,0xf5,0xd5,0x30,0x2a,0xa8,
        0x55,0xc2,0x56,0xc2,0x9b,0x88,0xc8,0xed,
        0x33,0x1e,0xa1,0xa6,0xbf,0x3c,0x88,0x12,
    };
    uint8_t out[32];
    int fails = 0;

    blake2s(out, NULL, NULL, sizeof(out), 0, 0);
    if (memcmp(out, empty_expected, 32) != 0) {
        printf("[FAIL] blake2s(empty)\n");
        printf("  expected: "); print_hex(empty_expected, 32); printf("\n");
        printf("  actual  : "); print_hex(out,           32); printf("\n");
        fails++;
    } else {
        printf("[PASS] blake2s(empty string) vector\n");
    }

    blake2s(out, (const uint8_t *)fox_msg, NULL, 32, sizeof(fox_msg) - 1, 0);
    if (memcmp(out, fox_expected, 32) != 0) {
        printf("[FAIL] blake2s(\"The quick brown fox...\")\n");
        printf("  expected: "); print_hex(fox_expected, 32); printf("\n");
        printf("  actual  : "); print_hex(out,          32); printf("\n");
        fails++;
    } else {
        printf("[PASS] blake2s(\"The quick brown fox...\") vector\n");
    }
    return fails;
}

/* Streaming consistency: hash a multi-block (>64 byte) input via the
 * one-shot blake2s() helper, then via init/update/final with several
 * different chunk sizes, and require byte-identical output for every
 * mode. This is the regression guard for the same class of bug that
 * crippled poly1305 — partial-block buffering across update calls. */
static int test_blake2s_streaming_consistency(void)
{
    /* 200 bytes is 3+ blocks plus a partial tail (200 = 3*64 + 8). */
    enum { N = 200 };
    uint8_t msg[N];
    uint8_t reference[32];
    uint8_t out[32];
    int fails = 0;

    for (size_t i = 0; i < N; i++) msg[i] = (uint8_t)(i * 7 + 11);

    /* Reference: one-shot blake2s. */
    blake2s(reference, msg, NULL, 32, N, 0);

    static const size_t chunk_sizes[] = {
        1, 7, 13, 31, 32, 33, 63, 64, 65, 100, 199, 200
    };
    for (size_t ci = 0; ci < sizeof(chunk_sizes)/sizeof(chunk_sizes[0]); ci++) {
        size_t cs = chunk_sizes[ci];
        struct blake2s_state st;
        blake2s_init(&st, 32);
        for (size_t off = 0; off < N; off += cs) {
            size_t take = (off + cs > N) ? (N - off) : cs;
            blake2s_update(&st, msg + off, take);
        }
        blake2s_final(&st, out);
        if (memcmp(out, reference, 32) != 0) {
            printf("[FAIL] blake2s streaming(chunk=%zu) != one-shot\n", cs);
            printf("  one-shot : "); print_hex(reference, 32); printf("\n");
            printf("  streaming: "); print_hex(out,       32); printf("\n");
            fails++;
        }
    }
    if (fails == 0)
        printf("[PASS] blake2s streaming consistency (200B input, 12 chunkings)\n");
    return fails;
}

/* RFC 8439 §2.8.2 Known-Answer Test. This is the authoritative KAT that
 * catches sign/shift bugs a pure roundtrip would miss. */
static int test_chacha20_poly1305_rfc8439_kat(void)
{
    static const uint8_t key[32] = {
        0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
        0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
        0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f,
    };
    static const uint8_t nonce[12] = {
        0x07,0x00,0x00,0x00,
        0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
    };
    static const uint8_t aad[12] = {
        0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,
    };
    static const uint8_t pt[] =
        "Ladies and Gentlemen of the class of '99: "
        "If I could offer you only one tip for the future, "
        "sunscreen would be it.";
    static const size_t pt_len = sizeof(pt) - 1;
    static const uint8_t expected[] = {
        0xd3,0x1a,0x8d,0x34,0x64,0x8e,0x60,0xdb,0x7b,0x86,0xaf,0xbc,0x53,0xef,0x7e,0xc2,
        0xa4,0xad,0xed,0x51,0x29,0x6e,0x08,0xfe,0xa9,0xe2,0xb5,0xa7,0x36,0xee,0x62,0xd6,
        0x3d,0xbe,0xa4,0x5e,0x8c,0xa9,0x67,0x12,0x82,0xfa,0xfb,0x69,0xda,0x92,0x72,0x8b,
        0x1a,0x71,0xde,0x0a,0x9e,0x06,0x0b,0x29,0x05,0xd6,0xa5,0xb6,0x7e,0xcd,0x3b,0x36,
        0x92,0xdd,0xbd,0x7f,0x2d,0x77,0x8b,0x8c,0x98,0x03,0xae,0xe3,0x28,0x09,0x1b,0x58,
        0xfa,0xb3,0x24,0xe4,0xfa,0xd6,0x75,0x94,0x55,0x85,0x80,0x8b,0x48,0x31,0xd7,0xbc,
        0x3f,0xf4,0xde,0xf0,0x8e,0x4b,0x7a,0x9d,0xe5,0x76,0xd2,0x65,0x86,0xce,0xc6,0x4b,
        0x61,0x16,
        /* tag */
        0x1a,0xe1,0x0b,0x59,0x4f,0x09,0xe2,0x6a,0x7e,0x90,0x2e,0xcb,0xd0,0x60,0x06,0x91,
    };
    uint8_t enc[sizeof(expected)];

    chacha20_poly1305_encrypt(enc, pt, pt_len, aad, sizeof(aad), nonce, 12, key);
    if (memcmp(enc, expected, sizeof(expected)) != 0) {
        printf("[FAIL] chacha20-poly1305 RFC 8439 KAT\n");
        printf("  expected: "); print_hex(expected, sizeof(expected)); printf("\n");
        printf("  actual  : "); print_hex(enc, sizeof(enc)); printf("\n");
        return 1;
    }
    printf("[PASS] chacha20-poly1305 RFC 8439 §2.8.2 KAT\n");
    return 0;
}

static int test_chacha20_poly1305_roundtrip(void)
{
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t ad[20];
    uint8_t plain[128];
    uint8_t enc[128 + 16];
    uint8_t dec[128];
    size_t i;

    for (i = 0; i < sizeof(key); ++i) key[i] = (uint8_t)(0x10 + i);
    for (i = 0; i < sizeof(nonce); ++i) nonce[i] = (uint8_t)(0xa0 + i);
    for (i = 0; i < sizeof(ad); ++i) ad[i] = (uint8_t)(0x55 ^ i);
    for (i = 0; i < sizeof(plain); ++i) plain[i] = (uint8_t)(i * 3 + 7);

    chacha20_poly1305_encrypt(enc, plain, sizeof(plain), ad, sizeof(ad), nonce, sizeof(nonce), key);
    if (!chacha20_poly1305_decrypt(dec, enc, sizeof(enc), ad, sizeof(ad), nonce, sizeof(nonce), key)) {
        printf("[FAIL] chacha20-poly1305 decrypt failed\n");
        return 1;
    }
    if (memcmp(dec, plain, sizeof(plain)) != 0) {
        printf("[FAIL] chacha20-poly1305 plaintext mismatch\n");
        return 1;
    }

    enc[sizeof(enc) - 1] ^= 0x01;
    if (chacha20_poly1305_decrypt(dec, enc, sizeof(enc), ad, sizeof(ad), nonce, sizeof(nonce), key)) {
        printf("[FAIL] chacha20-poly1305 tamper check failed\n");
        return 1;
    }

    printf("[PASS] chacha20-poly1305 roundtrip + tamper\n");
    return 0;
}

static int test_xchacha20_poly1305_roundtrip(void)
{
    uint8_t key[32];
    uint8_t nonce[24];
    uint8_t ad[17];
    uint8_t plain[111];
    uint8_t enc[111 + 16];
    uint8_t dec[111];
    size_t i;

    for (i = 0; i < sizeof(key); ++i) key[i] = (uint8_t)(0x20 + i);
    for (i = 0; i < sizeof(nonce); ++i) nonce[i] = (uint8_t)(0xc0 + i);
    for (i = 0; i < sizeof(ad); ++i) ad[i] = (uint8_t)(0x33 + i);
    for (i = 0; i < sizeof(plain); ++i) plain[i] = (uint8_t)(0xf0 - i);

    xchacha20_poly1305_encrypt(enc, plain, sizeof(plain), ad, sizeof(ad), nonce, key);
    if (!xchacha20_poly1305_decrypt(dec, enc, sizeof(enc), ad, sizeof(ad), nonce, key)) {
        printf("[FAIL] xchacha20-poly1305 decrypt failed\n");
        return 1;
    }
    if (memcmp(dec, plain, sizeof(plain)) != 0) {
        printf("[FAIL] xchacha20-poly1305 plaintext mismatch\n");
        return 1;
    }

    enc[0] ^= 0x80;
    if (xchacha20_poly1305_decrypt(dec, enc, sizeof(enc), ad, sizeof(ad), nonce, key)) {
        printf("[FAIL] xchacha20-poly1305 tamper check failed\n");
        return 1;
    }

    printf("[PASS] xchacha20-poly1305 roundtrip + tamper\n");
    return 0;
}

/* RFC 7748 §6.1 X25519 test vector. This catches any regression in the
 * Swift CryptoKit bridge — we don't blindly trust it. */
static int test_curve25519_rfc7748(void)
{
    static const uint8_t alice_priv[32] = {
        0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
        0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a,
    };
    static const uint8_t alice_pub[32] = {
        0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54,0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a,
        0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4,0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a,
    };
    static const uint8_t bob_pub[32] = {
        0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4,0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37,
        0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d,0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f,
    };
    static const uint8_t shared[32] = {
        0x4a,0x5d,0x9d,0x5b,0xa4,0xce,0x2d,0xe1,0x72,0x8e,0x3b,0xf4,0x80,0x35,0x0f,0x25,
        0xe0,0x7e,0x21,0xc9,0x47,0xd1,0x9e,0x33,0x76,0xf0,0x9b,0x3c,0x1e,0x16,0x17,0x42,
    };
    uint8_t derived_pub[32];
    uint8_t derived_shared[32];

    /* Alice's pubkey derived from her private. */
    if (curve25519_generate_public(derived_pub, alice_priv) != 1) {
        printf("[FAIL] curve25519_generate_public returned 0\n");
        return 1;
    }
    if (memcmp(derived_pub, alice_pub, 32) != 0) {
        printf("[FAIL] curve25519 pubkey derivation mismatch\n");
        printf("  expected: "); print_hex(alice_pub, 32);   printf("\n");
        printf("  actual  : "); print_hex(derived_pub, 32); printf("\n");
        return 1;
    }

    /* Alice's priv · Bob's pub → shared. */
    if (curve25519(derived_shared, alice_priv, bob_pub) != 1) {
        printf("[FAIL] curve25519 DH returned 0\n");
        return 1;
    }
    if (memcmp(derived_shared, shared, 32) != 0) {
        printf("[FAIL] curve25519 DH shared-secret mismatch\n");
        printf("  expected: "); print_hex(shared,         32); printf("\n");
        printf("  actual  : "); print_hex(derived_shared, 32); printf("\n");
        return 1;
    }

    printf("[PASS] curve25519 RFC 7748 §6.1 KAT (pubkey + DH)\n");
    return 0;
}

/* This is the test that actually catches data-path divergence. The
 * WireGuard transport packet goes through chacha20poly1305_encrypt_mbuf
 * (the mbuf API, wired through crypto_dispatch in wg_crypto_impl.c),
 * NOT through the buffer API that the RFC 8439 KAT above exercises.
 *
 * We encrypt the same plaintext via both paths and require byte-identical
 * output. We sweep multiple lengths including the exact sizes WireGuard
 * uses on the wire (16 = keepalive padded, 96 = 84-byte ICMP padded, etc.)
 * because a length-specific bug in tail handling or AAD accounting would
 * only fire for certain moduli. */
static int test_mbuf_matches_buffer_one(size_t plain_len)
{
    uint8_t plain[256];
    uint8_t ref_buf[256 + 16];
    static const uint8_t key[32] = {
        0x1c,0x92,0x40,0xa5,0xeb,0x55,0xd3,0x8a,0xf3,0x33,0x88,0x86,0x04,0xf6,0xb5,0xf0,
        0x47,0x39,0x17,0xc1,0x40,0x2b,0x80,0x09,0x9d,0xca,0x5c,0xbc,0x20,0x70,0x75,0xc0,
    };
    const uint64_t nonce = 0x0706050403020100ULL;

    if (plain_len > sizeof(plain)) return 1;
    for (size_t i = 0; i < plain_len; i++) plain[i] = (uint8_t)(i * 7 + 3);

    /* Buffer path: KAT-verified known-good reference. Empty AAD. */
    chacha20poly1305_encrypt(ref_buf, plain, plain_len,
                             NULL, 0, nonce, key);

    /* Mbuf path: the production data-plane route. */
    struct mbuf *m = m_devget(plain, (int)plain_len);
    if (!m) {
        printf("[FAIL] mbuf_vs_buffer(len=%zu): m_devget\n", plain_len);
        return 1;
    }
    if (chacha20poly1305_encrypt_mbuf(m, nonce, key) != 0) {
        printf("[FAIL] mbuf_vs_buffer(len=%zu): encrypt_mbuf\n", plain_len);
        m_freem(m);
        return 1;
    }
    if (m->m_len != (int)(plain_len + 16)) {
        printf("[FAIL] mbuf_vs_buffer(len=%zu): wrong length %d (expected %zu)\n",
               plain_len, m->m_len, plain_len + 16);
        m_freem(m);
        return 1;
    }
    int mismatch = memcmp(m->m_data, ref_buf, plain_len + 16);
    if (mismatch != 0) {
        printf("[FAIL] mbuf_vs_buffer(len=%zu): outputs differ\n", plain_len);
        printf("  buffer path : "); print_hex(ref_buf,  plain_len + 16); printf("\n");
        printf("  mbuf   path : "); print_hex((uint8_t*)m->m_data, plain_len + 16); printf("\n");
        printf("  ct match: %s  tag match: %s\n",
               memcmp(m->m_data, ref_buf, plain_len) == 0 ? "YES" : "NO",
               memcmp((uint8_t*)m->m_data + plain_len, ref_buf + plain_len, 16) == 0 ? "YES" : "NO");
        m_freem(m);
        return 1;
    }
    m_freem(m);
    printf("[PASS] chacha20-poly1305 mbuf path == buffer path (len=%zu)\n", plain_len);
    return 0;
}

static int test_mbuf_matches_buffer_path(void)
{
    /* Sweep the exact sizes WireGuard's transport path uses:
     *   16  = keepalive (0 bytes padded to 16)
     *   32  = random non-aligned-ish
     *   48  = also a keepalive wire size check
     *   96  = 84-byte ICMP echo padded to 96 (this is the ping we were
     *         sending that got silently dropped on the server)
     *   112 = next 16-byte boundary up
     *   13  = non-aligned tail that also exercises partial-block path
     */
    int fails = 0;
    static const size_t lens[] = { 0, 13, 16, 32, 48, 96, 112, 113 };
    for (size_t i = 0; i < sizeof(lens)/sizeof(lens[0]); i++) {
        fails += test_mbuf_matches_buffer_one(lens[i]);
    }
    return fails;
}

int main(void)
{
    int fails = 0;

    fails += test_blake2s_abc();
    fails += test_blake2s_more_kats();
    fails += test_blake2s_streaming_consistency();
    fails += test_curve25519_rfc7748();
    fails += test_chacha20_poly1305_rfc8439_kat();
    fails += test_mbuf_matches_buffer_path();
    fails += test_chacha20_poly1305_roundtrip();
    fails += test_xchacha20_poly1305_roundtrip();

    if (fails == 0) {
        printf("\nAll crypto vector tests passed.\n");
        return 0;
    }

    printf("\nCrypto vector tests failed: %d\n", fails);
    return 1;
}

