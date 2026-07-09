/* FreeBSD crypto/curve25519.h -> Windows stub (prototypes only) */
#pragma once
#include <stdint.h>

#define CURVE25519_KEY_SIZE 32

void curve25519_generate_secret(uint8_t private_key[CURVE25519_KEY_SIZE]);
void curve25519_clamp_secret(uint8_t private_key[CURVE25519_KEY_SIZE]);
int  curve25519_generate_public(uint8_t public_key[CURVE25519_KEY_SIZE],
         const uint8_t private_key[CURVE25519_KEY_SIZE]);
int  curve25519(uint8_t shared_secret[CURVE25519_KEY_SIZE],
         const uint8_t private_key[CURVE25519_KEY_SIZE],
         const uint8_t public_key[CURVE25519_KEY_SIZE]);
