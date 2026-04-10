/* FreeBSD crypto/chacha20_poly1305.h → macOS stub (prototypes only) */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

struct mbuf; /* forward declaration */

void chacha20_poly1305_encrypt(
    uint8_t       *dst,
    const uint8_t *src,   size_t src_len,
    const uint8_t *ad,    size_t ad_len,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *key);

bool chacha20_poly1305_decrypt(
    uint8_t       *dst,
    const uint8_t *src,   size_t src_len,
    const uint8_t *ad,    size_t ad_len,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *key);

void xchacha20_poly1305_encrypt(
    uint8_t       *dst,
    const uint8_t *src,   size_t src_len,
    const uint8_t *ad,    size_t ad_len,
    const uint8_t *nonce,
    const uint8_t *key);

bool xchacha20_poly1305_decrypt(
    uint8_t       *dst,
    const uint8_t *src,   size_t src_len,
    const uint8_t *ad,    size_t ad_len,
    const uint8_t *nonce,
    const uint8_t *key);
