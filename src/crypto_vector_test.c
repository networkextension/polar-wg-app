#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "crypto.h"
#include <crypto/curve25519.h>

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

int main(void)
{
    int fails = 0;

    fails += test_blake2s_abc();
    fails += test_curve25519_rfc7748();
    fails += test_chacha20_poly1305_rfc8439_kat();
    fails += test_chacha20_poly1305_roundtrip();
    fails += test_xchacha20_poly1305_roundtrip();

    if (fails == 0) {
        printf("\nAll crypto vector tests passed.\n");
        return 0;
    }

    printf("\nCrypto vector tests failed: %d\n", fails);
    return 1;
}

