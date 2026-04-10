/* FreeBSD crypto/curve25519.h → macOS stub (prototypes only) */
#pragma once
#include <stdint.h>

#define CURVE25519_KEY_SIZE 32

/* Generate a random private key (fills buf with random bytes + clamps) */
void curve25519_generate_secret(uint8_t private_key[CURVE25519_KEY_SIZE]);

/* Clamp a private key in-place per RFC 7748 */
void curve25519_clamp_secret(uint8_t private_key[CURVE25519_KEY_SIZE]);

/* Compute public key from private; returns 1 on success, 0 on failure */
int  curve25519_generate_public(uint8_t public_key[CURVE25519_KEY_SIZE],
         const uint8_t private_key[CURVE25519_KEY_SIZE]);

/* DH shared-secret: shared = clamp(private) * public; returns 1 on success */
int  curve25519(uint8_t shared_secret[CURVE25519_KEY_SIZE],
         const uint8_t private_key[CURVE25519_KEY_SIZE],
         const uint8_t public_key[CURVE25519_KEY_SIZE]);
