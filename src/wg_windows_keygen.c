/* SPDX-License-Identifier: MIT
 *
 * wg_windows_keygen: minimal Windows CLI for the three wgctl keygen
 * subcommands (genkey/pubkey/genpsk). wgctl.c itself is macOS-specific
 * (dirent.h, sys/un.h, sys/wait.h, launchd-adjacent up/down/show logic)
 * and out of scope to port wholesale; this pulls out just the
 * self-contained keygen path — base64 helpers copied verbatim from
 * wgctl.c, Curve25519 calls against curve25519_portable.c (already
 * validated against the RFC 7748 KAT on Windows via crypto_vector_test).
 *
 * Usage:
 *   wg_windows_keygen.exe genkey            -> prints a new private key
 *   wg_windows_keygen.exe pubkey <priv_b64>  -> prints the derived public key
 *   wg_windows_keygen.exe genpsk             -> prints a new preshared key
 *
 * (pubkey takes the private key as an argv, not stdin, since PowerShell's
 * pipe-to-stdin quoting across a curl-style script is more error-prone
 * than just passing it as one argument.)
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* rand_s's declaration is gated behind _CRT_RAND_S defined before
 * <stdlib.h>'s FIRST inclusion — fragile to depend on across a file with
 * multiple stdlib.h consumers, so (as in windows_stubs/sys/systm.h)
 * declare it directly; the symbol exists in the CRT import lib regardless
 * of the macro gate. */
extern int rand_s(unsigned int *randomValue);

extern void curve25519_generate_secret(uint8_t out[32]);
extern void curve25519_clamp_secret(uint8_t secret[32]);
extern int  curve25519_generate_public(uint8_t out[32], const uint8_t priv[32]);

/* ── base64 (WireGuard's canonical 32-byte form, 44 chars incl. '=') ────────
 * Copied verbatim from src/wgctl.c — same wire format, no platform deps. */

static const char B64_ENC[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void b64_encode_32(char out[45], const uint8_t in[32])
{
    int oi = 0;
    for (int i = 0; i < 30; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8) | in[i+2];
        out[oi++] = B64_ENC[(v >> 18) & 0x3f];
        out[oi++] = B64_ENC[(v >> 12) & 0x3f];
        out[oi++] = B64_ENC[(v >>  6) & 0x3f];
        out[oi++] = B64_ENC[ v        & 0x3f];
    }
    uint32_t v = ((uint32_t)in[30] << 16) | ((uint32_t)in[31] << 8);
    out[oi++] = B64_ENC[(v >> 18) & 0x3f];
    out[oi++] = B64_ENC[(v >> 12) & 0x3f];
    out[oi++] = B64_ENC[(v >>  6) & 0x3f];
    out[oi++] = '=';
    out[oi]   = '\0';
}

static int b64_value(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') return (int)(c - 'A');
    if (c >= 'a' && c <= 'z') return (int)(c - 'a') + 26;
    if (c >= '0' && c <= '9') return (int)(c - '0') + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int b64_decode_32(const char *in, uint8_t out[32])
{
    size_t in_len = strlen(in);
    uint8_t tmp[64] = {0};
    int out_len = 0;

    if (in_len != 44) return -1;
    for (int i = 0; i < 44; i += 4) {
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
    if (out_len != 32) return -1;
    memcpy(out, tmp, 32);
    return 0;
}

/* ── subcommands ─────────────────────────────────────────────────────────── */

static int cmd_genkey(void)
{
    uint8_t sk[32];
    char out[45];
    curve25519_generate_secret(sk);
    curve25519_clamp_secret(sk);
    b64_encode_32(out, sk);
    printf("%s\n", out);
    return 0;
}

static int cmd_pubkey(const char *priv_b64)
{
    uint8_t sk[32], pk[32];
    if (b64_decode_32(priv_b64, sk) != 0) {
        fprintf(stderr, "wg_windows_keygen pubkey: not a valid 44-char base64 key\n");
        return 1;
    }
    if (!curve25519_generate_public(pk, sk)) {
        fprintf(stderr, "wg_windows_keygen pubkey: derivation failed\n");
        return 1;
    }
    char out[45];
    b64_encode_32(out, pk);
    printf("%s\n", out);
    return 0;
}

static int cmd_genpsk(void)
{
    /* Unclamped 32 random bytes — a PSK is not a Curve25519 scalar, so
     * it must NOT go through curve25519_clamp_secret. Same rand_s-backed
     * CSPRNG as curve25519_generate_secret uses. */
    uint8_t psk[32];
    for (int i = 0; i < 8; i++) {
        unsigned int w;
        rand_s(&w);
        memcpy(psk + i * 4, &w, 4);
    }
    char out[45];
    b64_encode_32(out, psk);
    printf("%s\n", out);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
            "usage: %s genkey | pubkey <priv_b64> | genpsk\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "genkey") == 0) return cmd_genkey();
    if (strcmp(argv[1], "genpsk") == 0) return cmd_genpsk();
    if (strcmp(argv[1], "pubkey") == 0) {
        if (argc < 3) {
            fprintf(stderr, "usage: %s pubkey <priv_b64>\n", argv[0]);
            return 1;
        }
        return cmd_pubkey(argv[2]);
    }
    fprintf(stderr, "unknown subcommand: %s\n", argv[1]);
    return 1;
}
