#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "crypto.h"
#include "wg_noise.h"
#include "allowedips.h"
#include "wg_session.h"
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

/* M4.4 — In-process noise + transport loopback.
 *
 * Stand up two noise_local instances (initiator + responder) inside the
 * same process, do a full Noise_IK handshake, then push a real plaintext
 * through encap on the initiator side and decap it on the responder
 * side. Verify the recovered plaintext matches byte-for-byte.
 *
 * This is the regression guard for the Round 3 r_idx bug: a buggy index
 * field would have caused noise_keypair_lookup() on the responder to
 * return NULL and the test would fail with a clear error pointing at
 * the lookup, instead of "ping just doesn't reply" on a real network.
 *
 * It also exercises the responder code path (noise_consume_initiation /
 * noise_create_response) which the wg_core client never touches in
 * single-peer initiator mode.
 */
static int
do_loopback_handshake(struct noise_local *init_local,
                      struct noise_remote *init_remote_peer_view,
                      struct noise_local *resp_local,
                      struct noise_remote *resp_remote_peer_view)
{
    uint8_t ue[NOISE_PUBLIC_KEY_LEN];
    uint8_t es[NOISE_PUBLIC_KEY_LEN + NOISE_AUTHTAG_LEN];
    uint8_t ets[NOISE_TIMESTAMP_LEN + NOISE_AUTHTAG_LEN];
    uint8_t en[NOISE_AUTHTAG_LEN];
    uint32_t init_s_idx = 0;
    uint32_t resp_s_idx = 0;
    uint32_t resp_r_idx = 0;
    struct noise_remote *matched = NULL;

    /* Step 1: initiator → wire(initiation). */
    if (noise_create_initiation(init_remote_peer_view,
                                &init_s_idx, ue, es, ets) != 0) {
        printf("[FAIL] loopback: create_initiation\n");
        return 1;
    }

    /* Step 2: responder consumes the initiation. */
    if (noise_consume_initiation(resp_local, &matched,
                                 init_s_idx, ue, es, ets) != 0) {
        printf("[FAIL] loopback: consume_initiation\n");
        return 1;
    }
    if (matched != resp_remote_peer_view) {
        printf("[FAIL] loopback: consume_initiation matched wrong remote\n");
        if (matched) noise_remote_put(matched);
        return 1;
    }
    noise_remote_put(matched);

    /* Step 3: responder → wire(response). */
    if (noise_create_response(resp_remote_peer_view,
                              &resp_s_idx, &resp_r_idx, ue, en) != 0) {
        printf("[FAIL] loopback: create_response\n");
        return 1;
    }
    if (resp_r_idx != init_s_idx) {
        printf("[FAIL] loopback: response r_idx 0x%08x != init s_idx 0x%08x\n",
               (unsigned)resp_r_idx, (unsigned)init_s_idx);
        return 1;
    }

    /* Step 4: initiator consumes the response. Note the parameter
     * order — this is the same trap that the wg_core fix had to learn. */
    matched = NULL;
    if (noise_consume_response(init_local, &matched,
                               resp_s_idx, resp_r_idx, ue, en) != 0) {
        printf("[FAIL] loopback: consume_response\n");
        return 1;
    }
    if (matched != init_remote_peer_view) {
        printf("[FAIL] loopback: consume_response matched wrong remote\n");
        if (matched) noise_remote_put(matched);
        return 1;
    }
    noise_remote_put(matched);
    return 0;
}

static int test_noise_loopback(void)
{
    struct noise_local *init_local = NULL;
    struct noise_local *resp_local = NULL;
    struct noise_remote *init_view_of_resp = NULL;  /* used by initiator */
    struct noise_remote *resp_view_of_init = NULL;  /* used by responder */
    uint8_t init_priv[32], init_pub[32];
    uint8_t resp_priv[32], resp_pub[32];
    int rc = 1;

    /* Two random keypairs. */
    curve25519_generate_secret(init_priv);
    curve25519_generate_secret(resp_priv);
    if (curve25519_generate_public(init_pub, init_priv) != 1 ||
        curve25519_generate_public(resp_pub, resp_priv) != 1) {
        printf("[FAIL] loopback: pubkey derivation\n");
        return 1;
    }

    init_local = noise_local_alloc(NULL);
    resp_local = noise_local_alloc(NULL);
    if (!init_local || !resp_local) {
        printf("[FAIL] loopback: noise_local_alloc\n");
        goto out;
    }
    noise_local_private(init_local, init_priv);
    noise_local_private(resp_local, resp_priv);

    /* Each side needs a noise_remote pointing at the other side's pubkey. */
    init_view_of_resp = noise_remote_alloc(init_local, NULL, resp_pub);
    resp_view_of_init = noise_remote_alloc(resp_local, NULL, init_pub);
    if (!init_view_of_resp || !resp_view_of_init) {
        printf("[FAIL] loopback: noise_remote_alloc\n");
        goto out;
    }
    if (noise_remote_enable(init_view_of_resp) != 0 ||
        noise_remote_enable(resp_view_of_init) != 0) {
        printf("[FAIL] loopback: noise_remote_enable\n");
        goto out;
    }

    /* Full handshake in-process. */
    if (do_loopback_handshake(init_local, init_view_of_resp,
                              resp_local, resp_view_of_init) != 0)
        goto out;

    /* Now push a real plaintext through encap on the initiator side
     * and decap it on the responder side. Plaintext is non-trivial
     * length to exercise padding (37 bytes pads to 48). */
    {
        static const uint8_t plain[37] =
            "M4.4 noise + transport loopback test\n";
        struct noise_keypair *init_kp = NULL;
        struct noise_keypair *resp_kp = NULL;
        struct mbuf *m_enc = NULL;
        struct mbuf *m_dec = NULL;
        uint64_t nonce = 0;
        uint32_t r_idx = 0;
        uint8_t scratch[64] = {0};
        int padded_len = 48;  /* 37 rounded up to 16 boundary */

        memcpy(scratch, plain, sizeof(plain));

        init_kp = noise_keypair_current(init_view_of_resp);
        if (!init_kp) {
            printf("[FAIL] loopback: no current keypair on initiator\n");
            goto enc_out;
        }
        if (noise_keypair_nonce_next(init_kp, &nonce) != 0) {
            printf("[FAIL] loopback: nonce_next\n");
            goto enc_out;
        }
        m_enc = m_devget(scratch, padded_len);
        if (!m_enc) {
            printf("[FAIL] loopback: m_devget(enc)\n");
            goto enc_out;
        }
        if (noise_keypair_encrypt(init_kp, &r_idx, nonce, m_enc) != 0) {
            printf("[FAIL] loopback: noise_keypair_encrypt\n");
            goto enc_out;
        }
        /* m_enc now holds [48 ct][16 tag] = 64 bytes, and r_idx is the
         * responder's local index for the keypair we should target. */

        /* Responder side: look up its keypair by r_idx and decrypt. */
        resp_kp = noise_keypair_lookup(resp_local, r_idx);
        if (!resp_kp) {
            printf("[FAIL] loopback: noise_keypair_lookup(0x%08x) returned NULL\n",
                   (unsigned)r_idx);
            goto enc_out;
        }
        m_dec = m_devget(m_enc->m_data, m_enc->m_len);
        if (!m_dec) {
            printf("[FAIL] loopback: m_devget(dec)\n");
            goto enc_out;
        }
        if (noise_keypair_decrypt(resp_kp, nonce, m_dec) != 0) {
            printf("[FAIL] loopback: noise_keypair_decrypt\n");
            goto enc_out;
        }
        /* m_dec is now plaintext (with the original padding intact);
         * the tag has been stripped via m_adj(-16). */
        if (m_dec->m_len != padded_len) {
            printf("[FAIL] loopback: decrypted len %d != %d\n",
                   m_dec->m_len, padded_len);
            goto enc_out;
        }
        if (memcmp(m_dec->m_data, scratch, padded_len) != 0) {
            printf("[FAIL] loopback: decrypted plaintext mismatch\n");
            goto enc_out;
        }
        rc = 0;
        printf("[PASS] noise loopback (handshake + transport, %d-byte plain)\n",
               (int)sizeof(plain));
enc_out:
        if (m_enc) m_freem(m_enc);
        if (m_dec) m_freem(m_dec);
        if (init_kp) noise_keypair_put(init_kp);
        if (resp_kp) noise_keypair_put(resp_kp);
    }

out:
    if (init_view_of_resp) noise_remote_put(init_view_of_resp);
    if (resp_view_of_init) noise_remote_put(resp_view_of_init);
    if (init_local) noise_local_put(init_local);
    if (resp_local) noise_local_put(resp_local);
    return rc;
}

/* ─────────────────────────────────────────────────────────────────────────
 * allowedips trie tests. Pure data-structure unit tests; no crypto.
 * ───────────────────────────────────────────────────────────────────────── */

/* Stand-in "peers". The trie only stores opaque pointers, so we use
 * the address of these globals as cheap unique tags. */
static int peer_a, peer_b, peer_c, peer_default;
#define PA (&peer_a)
#define PB (&peer_b)
#define PC (&peer_c)
#define PD (&peer_default)

static int test_aips_v4_basic_lpm(void)
{
    struct aips_trie t;
    aips_init(&t, 32);

    /* 10.0.0.0/8 → A   ; 10.88.0.0/16 → B   ; 10.88.0.2/32 → C */
    aips_insert_v4(&t, 0x0a000000u,  8, PA);
    aips_insert_v4(&t, 0x0a580000u, 16, PB);
    aips_insert_v4(&t, 0x0a580002u, 32, PC);

    struct { uint32_t addr; void *expect; const char *name; } cases[] = {
        { 0x0a580002u, PC,   "10.88.0.2  /32 exact"   },
        { 0x0a580003u, PB,   "10.88.0.3  /16 fallback" },
        { 0x0a000001u, PA,   "10.0.0.1   /8 fallback"  },
        { 0x0b000000u, NULL, "11.0.0.0   no match"     },
        { 0x0a570000u, PA,   "10.87.0.0  /8 fallback"  },
    };
    int fails = 0;
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        void *got = aips_lookup_v4(&t, cases[i].addr);
        if (got != cases[i].expect) {
            printf("[FAIL] aips v4 LPM: %s — got %p expected %p\n",
                   cases[i].name, got, cases[i].expect);
            fails++;
        }
    }
    if (fails == 0)
        printf("[PASS] allowedips v4 longest-prefix-match (3 CIDRs, 5 lookups)\n");
    aips_destroy(&t);
    return fails;
}

static int test_aips_default_route(void)
{
    struct aips_trie t;
    aips_init(&t, 32);

    aips_insert_v4(&t, 0x00000000u, 0, PD);   /* 0.0.0.0/0 → default */
    aips_insert_v4(&t, 0x0a000000u, 8, PA);   /* 10.0.0.0/8  → A     */

    int fails = 0;
    if (aips_lookup_v4(&t, 0x0a000001u) != PA)         { printf("[FAIL] dr: 10/8\n");      fails++; }
    if (aips_lookup_v4(&t, 0x08080808u) != PD)         { printf("[FAIL] dr: 8.8.8.8\n");   fails++; }
    if (aips_lookup_v4(&t, 0xffffffffu) != PD)         { printf("[FAIL] dr: 255.x\n");     fails++; }
    if (fails == 0)
        printf("[PASS] allowedips default route 0.0.0.0/0\n");
    aips_destroy(&t);
    return fails;
}

static int test_aips_replace_and_remove(void)
{
    struct aips_trie t;
    aips_init(&t, 32);

    aips_insert_v4(&t, 0x0a580002u, 32, PA);
    if (aips_lookup_v4(&t, 0x0a580002u) != PA) {
        printf("[FAIL] aips replace: initial insert\n");
        aips_destroy(&t);
        return 1;
    }
    /* Replace at the same exact CIDR. Entry count must stay 1. */
    aips_insert_v4(&t, 0x0a580002u, 32, PB);
    if (aips_lookup_v4(&t, 0x0a580002u) != PB) {
        printf("[FAIL] aips replace: did not take effect\n");
        aips_destroy(&t);
        return 1;
    }
    if (t.entries != 1) {
        printf("[FAIL] aips replace: entries=%zu (want 1)\n", t.entries);
        aips_destroy(&t);
        return 1;
    }
    /* Remove the exact CIDR — lookup should now return NULL. */
    if (aips_remove(&t, (const uint8_t *)"\x0a\x58\x00\x02", 32) != 0) {
        printf("[FAIL] aips remove: returned -1\n");
        aips_destroy(&t);
        return 1;
    }
    if (aips_lookup_v4(&t, 0x0a580002u) != NULL) {
        printf("[FAIL] aips remove: lookup still finds peer\n");
        aips_destroy(&t);
        return 1;
    }
    if (t.entries != 0) {
        printf("[FAIL] aips remove: entries=%zu (want 0)\n", t.entries);
        aips_destroy(&t);
        return 1;
    }
    /* Removing again must report -1. */
    if (aips_remove(&t, (const uint8_t *)"\x0a\x58\x00\x02", 32) != -1) {
        printf("[FAIL] aips remove: double-remove did not fail\n");
        aips_destroy(&t);
        return 1;
    }
    printf("[PASS] allowedips replace + remove + double-remove\n");
    aips_destroy(&t);
    return 0;
}

static int test_aips_v6(void)
{
    struct aips_trie t;
    aips_init(&t, 128);

    /* fd9f:ee52:46b8::/48 → A
     * fd9f:ee52:46b8:1::/64 → B (more specific)
     * fd9f:ee52:46b8:1::5 /128 → C (most specific)
     */
    static const uint8_t a48[16]  = { 0xfd,0x9f,0xee,0x52,0x46,0xb8 };
    static const uint8_t b64[16]  = { 0xfd,0x9f,0xee,0x52,0x46,0xb8,
                                      0x00,0x01 };
    static const uint8_t c128[16] = { 0xfd,0x9f,0xee,0x52,0x46,0xb8,
                                      0x00,0x01,0,0,0,0,0,0,0,0x05 };
    static const uint8_t miss[16] = { 0x20,0x01,0x0d,0xb8 };

    aips_insert(&t, a48,  48,  PA);
    aips_insert(&t, b64,  64,  PB);
    aips_insert(&t, c128, 128, PC);

    if (aips_lookup(&t, c128) != PC) { printf("[FAIL] v6 /128 exact\n"); aips_destroy(&t); return 1; }
    /* Address inside /64 but not /128 → should fall back to PB. */
    uint8_t addr_in_64[16];
    memcpy(addr_in_64, b64, 16);
    addr_in_64[15] = 0x07;
    if (aips_lookup(&t, addr_in_64) != PB) { printf("[FAIL] v6 /64 fallback\n"); aips_destroy(&t); return 1; }
    /* Address inside /48 but outside /64 → fall back to PA. */
    uint8_t addr_in_48[16];
    memcpy(addr_in_48, a48, 16);
    addr_in_48[7] = 0x09;
    if (aips_lookup(&t, addr_in_48) != PA) { printf("[FAIL] v6 /48 fallback\n"); aips_destroy(&t); return 1; }
    /* Outside the /48 → no match. */
    if (aips_lookup(&t, miss) != NULL) { printf("[FAIL] v6 outside /48\n"); aips_destroy(&t); return 1; }

    printf("[PASS] allowedips v6 longest-prefix-match (/48 /64 /128)\n");
    aips_destroy(&t);
    return 0;
}

/* Exercise wg_session_create + wg_session_get_uapi end-to-end. Parses
 * a small config, pulls the UAPI GET response out, checks a few
 * canonical fields, and verifies the "NULL/0 first to size" contract. */
static void uapi_test_log(void *u, const char *m) { (void)u; (void)m; }
static void uapi_test_send(void *u, const uint8_t *b, size_t l,
                           const struct sockaddr *a, socklen_t al)
{
    (void)u; (void)b; (void)l; (void)a; (void)al;
}
static void uapi_test_deliver(void *u, const uint8_t *b, size_t l)
{
    (void)u; (void)b; (void)l;
}

static int test_wg_session_uapi_get(void)
{
    static const char cfg[] =
        "[Interface]\n"
        "PrivateKey = yPDHiay/NDkJE9OyUT0J8qhuJXpihZw1aD7Xl4JJEVw=\n"
        "Address    = 10.88.0.2/24\n"
        "ListenPort = 51822\n"
        "\n"
        "[Peer]\n"
        "PublicKey  = XXFzbjDln02y/aWfo2RFVZ/foiMC/NEo9QKXDdk9SXk=\n"
        "AllowedIPs = 10.88.0.0/24, fd00::/64\n"
        "PersistentKeepalive = 25\n";

    wg_session_callbacks cb = {0};
    cb.send_udp   = uapi_test_send;
    cb.deliver_ip = uapi_test_deliver;
    cb.log_line   = uapi_test_log;

    wg_session_t *s = wg_session_create(cfg, sizeof(cfg) - 1, cb);
    if (!s) { printf("[FAIL] wg_session_create\n"); return 1; }

    /* Introspection sanity. */
    if (wg_session_peer_count(s) != 1) {
        printf("[FAIL] peer_count\n"); wg_session_destroy(s); return 1;
    }
    if (wg_session_listen_port(s) != 51822) {
        printf("[FAIL] listen_port=%u\n", wg_session_listen_port(s));
        wg_session_destroy(s);
        return 1;
    }
    if (wg_session_peer_allowed_count(s, 0) != 2) {
        printf("[FAIL] allowed_count\n"); wg_session_destroy(s); return 1;
    }

    /* Size-first query pattern. */
    int need = wg_session_get_uapi(s, NULL, 0);
    if (need < 64) {
        printf("[FAIL] uapi size %d too small\n", need);
        wg_session_destroy(s);
        return 1;
    }

    char *buf = (char *)malloc((size_t)need + 1);
    int wrote = wg_session_get_uapi(s, buf, (size_t)need + 1);
    if (wrote != need) {
        printf("[FAIL] uapi re-size %d != %d\n", wrote, need);
        free(buf); wg_session_destroy(s);
        return 1;
    }

    /* Canonical field presence checks. */
    const char *required[] = {
        "private_key=none\n",
        "listen_port=51822\n",
        "fwmark=0\n",
        "public_key=",
        "preshared_key=0000",
        "persistent_keepalive_interval=25\n",
        "allowed_ip=10.88.0.0/24\n",
        "allowed_ip=fd00::/64\n",
        "protocol_version=1\n",
        "errno=0\n",
    };
    for (size_t i = 0; i < sizeof(required)/sizeof(required[0]); i++) {
        if (!strstr(buf, required[i])) {
            printf("[FAIL] uapi GET missing required field '%s'\n", required[i]);
            printf("--- response ---\n%s---\n", buf);
            free(buf);
            wg_session_destroy(s);
            return 1;
        }
    }

    /* The response MUST end with "\n\n" per the UAPI spec so the
     * reader knows where the record ends. */
    if (need < 2 || buf[need - 2] != '\n' || buf[need - 1] != '\n') {
        printf("[FAIL] uapi GET does not end with \\n\\n\n");
        free(buf);
        wg_session_destroy(s);
        return 1;
    }

    free(buf);
    wg_session_destroy(s);
    printf("[PASS] wg_session_create + UAPI GET round trip\n");
    return 0;
}

/* Exercise wg_session_set_uapi: load a config, mutate the peer's
 * endpoint + keepalive + allowed-ips via a SET request, then re-read
 * via GET and verify every change took effect. */
static int test_wg_session_uapi_set(void)
{
    static const char cfg[] =
        "[Interface]\n"
        "PrivateKey = yPDHiay/NDkJE9OyUT0J8qhuJXpihZw1aD7Xl4JJEVw=\n"
        "Address    = 10.88.0.2/24\n"
        "ListenPort = 51823\n"
        "[Peer]\n"
        "PublicKey  = XXFzbjDln02y/aWfo2RFVZ/foiMC/NEo9QKXDdk9SXk=\n"
        "AllowedIPs = 10.88.0.0/24\n"
        "PersistentKeepalive = 25\n";

    wg_session_callbacks cb = {0};
    cb.send_udp   = uapi_test_send;
    cb.deliver_ip = uapi_test_deliver;
    cb.log_line   = uapi_test_log;

    wg_session_t *s = wg_session_create(cfg, sizeof(cfg) - 1, cb);
    if (!s) { printf("[FAIL] set: create\n"); return 1; }

    /* The peer pubkey we'll mutate (XXFzbjDln02y/...) hex-encoded. */
    static const char *peer_hex =
        "5d71736e30e59f4db2fda59fa36445559fdfa22302fcd128f502970dd93d4979";

    /* SET request: change endpoint, change keepalive, replace
     * allowed-ips with two new CIDRs. */
    char setreq[1024];
    snprintf(setreq, sizeof(setreq),
             "set=1\n"
             "public_key=%s\n"
             "endpoint=192.0.2.5:51820\n"
             "persistent_keepalive_interval=42\n"
             "replace_allowed_ips=true\n"
             "allowed_ip=10.99.0.0/16\n"
             "allowed_ip=10.99.0.0/24\n"
             "\n",
             peer_hex);

    if (wg_session_set_uapi(s, setreq, strlen(setreq)) != 0) {
        printf("[FAIL] set: wg_session_set_uapi returned non-zero\n");
        wg_session_destroy(s);
        return 1;
    }

    /* Verify via the introspection getters. */
    char addr[80] = {0};
    uint16_t port = 0;
    if (wg_session_peer_endpoint(s, 0, addr, &port) != 0 ||
        strcmp(addr, "192.0.2.5") != 0 || port != 51820) {
        printf("[FAIL] set: endpoint not updated (got %s:%u)\n", addr, port);
        wg_session_destroy(s);
        return 1;
    }
    if (wg_session_peer_keepalive(s, 0) != 42) {
        printf("[FAIL] set: keepalive=%d\n", wg_session_peer_keepalive(s, 0));
        wg_session_destroy(s);
        return 1;
    }
    if (wg_session_peer_allowed_count(s, 0) != 2) {
        printf("[FAIL] set: allowed_count=%d\n",
               wg_session_peer_allowed_count(s, 0));
        wg_session_destroy(s);
        return 1;
    }

    /* Re-read as UAPI GET and verify the canonical fields reflect the
     * change. */
    int need = wg_session_get_uapi(s, NULL, 0);
    char *out = (char *)malloc((size_t)need + 1);
    wg_session_get_uapi(s, out, (size_t)need + 1);

    const char *required[] = {
        "endpoint=192.0.2.5:51820\n",
        "persistent_keepalive_interval=42\n",
        "allowed_ip=10.99.0.0/16\n",
        "allowed_ip=10.99.0.0/24\n",
    };
    /* And the OLD allowed-ip must be GONE. */
    if (strstr(out, "allowed_ip=10.88.0.0/24") != NULL) {
        printf("[FAIL] set: old allowed_ip still present after replace\n");
        free(out); wg_session_destroy(s); return 1;
    }
    for (size_t i = 0; i < sizeof(required)/sizeof(required[0]); i++) {
        if (!strstr(out, required[i])) {
            printf("[FAIL] set: GET response missing '%s'\n", required[i]);
            printf("--- got ---\n%s---\n", out);
            free(out); wg_session_destroy(s); return 1;
        }
    }
    free(out);

    /* Restricted fields must be rejected. */
    char bad[256];
    snprintf(bad, sizeof(bad),
             "set=1\n"
             "private_key=%s\n"
             "\n", peer_hex);
    if (wg_session_set_uapi(s, bad, strlen(bad)) == 0) {
        printf("[FAIL] set: private_key was not rejected\n");
        wg_session_destroy(s);
        return 1;
    }

    snprintf(bad, sizeof(bad), "set=1\nlisten_port=12345\n\n");
    if (wg_session_set_uapi(s, bad, strlen(bad)) == 0) {
        printf("[FAIL] set: listen_port was not rejected\n");
        wg_session_destroy(s);
        return 1;
    }

    /* Unknown peer must be rejected. */
    snprintf(bad, sizeof(bad),
             "set=1\n"
             "public_key=0000000000000000000000000000000000000000000000000000000000000000\n"
             "endpoint=1.2.3.4:5\n"
             "\n");
    if (wg_session_set_uapi(s, bad, strlen(bad)) == 0) {
        printf("[FAIL] set: unknown peer was not rejected\n");
        wg_session_destroy(s);
        return 1;
    }

    wg_session_destroy(s);
    printf("[PASS] wg_session_set_uapi (endpoint + keepalive + replace allowed-ips + rejects)\n");
    return 0;
}

static int test_aips_edge_cases(void)
{
    struct aips_trie t;
    int fails = 0;

    /* Empty trie: lookup must return NULL, not crash. */
    aips_init(&t, 32);
    if (aips_lookup_v4(&t, 0x01020304u) != NULL) {
        printf("[FAIL] aips edge: empty trie lookup\n"); fails++;
    }
    /* Bad arguments rejected. */
    if (aips_insert(&t, NULL, 8, PA) == 0)               { printf("[FAIL] insert(NULL)\n"); fails++; }
    if (aips_insert_v4(&t, 0, 33, PA) == 0)              { printf("[FAIL] insert(/33)\n"); fails++; }
    if (aips_insert_v4(&t, 0, 0, NULL) == 0)             { printf("[FAIL] insert(NULL peer)\n"); fails++; }
    aips_destroy(&t);

    if (fails == 0)
        printf("[PASS] allowedips edge cases (empty / bad args)\n");
    return fails;
}

int main(void)
{
    int fails = 0;

    if (crypto_init() != 0) {
        printf("crypto_init failed\n");
        return 1;
    }

    fails += test_blake2s_abc();
    fails += test_blake2s_more_kats();
    fails += test_blake2s_streaming_consistency();
    fails += test_curve25519_rfc7748();
    fails += test_chacha20_poly1305_rfc8439_kat();
    fails += test_mbuf_matches_buffer_path();
    fails += test_chacha20_poly1305_roundtrip();
    fails += test_xchacha20_poly1305_roundtrip();
    fails += test_noise_loopback();

    fails += test_aips_v4_basic_lpm();
    fails += test_aips_default_route();
    fails += test_aips_replace_and_remove();
    fails += test_aips_v6();
    fails += test_aips_edge_cases();
    fails += test_wg_session_uapi_get();
    fails += test_wg_session_uapi_set();

    crypto_deinit();

    if (fails == 0) {
        printf("\nAll crypto vector tests passed.\n");
        return 0;
    }

    printf("\nCrypto vector tests failed: %d\n", fails);
    return 1;
}

