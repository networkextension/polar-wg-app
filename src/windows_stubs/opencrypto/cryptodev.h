/* FreeBSD opencrypto/cryptodev.h -> Windows userspace stub
 *
 * Instead of the kernel session/dispatch framework we implement
 * crypto_dispatch() directly using the pure-C ChaCha20-Poly1305 in
 * wg_crypto_impl.c. All types and macros are defined here so
 * wg_crypto.c compiles unchanged.
 */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <sys/mbuf.h>

typedef uintptr_t crypto_session_t;

#define CRYPTO_OP_ENCRYPT        0x01
#define CRYPTO_OP_DECRYPT        0x02
#define CRYPTO_OP_COMPUTE_DIGEST 0x04
#define CRYPTO_OP_VERIFY_DIGEST  0x08

#define CRYPTO_F_IV_SEPARATE  0x0001
#define CRYPTO_F_CBIMM        0x0002

#define CSP_MODE_AEAD          1
#define CRYPTO_CHACHA20_POLY1305 1
#define CSP_F_SEPARATE_AAD     0x01
#define CSP_F_SEPARATE_OUTPUT  0x02
#define CRYPTOCAP_F_SOFTWARE   0x01

struct crypto_session_params {
    int      csp_mode;
    int      csp_ivlen;
    int      csp_cipher_alg;
    int      csp_cipher_klen;
    int      csp_flags;
};

#define CHACHA20_IV_LEN   16
#define POLY1305_HASH_LEN 16

struct cryptop {
    int              crp_op;
    int              crp_flags;
    int              crp_payload_length;
    int              crp_digest_start;
    uint8_t          crp_iv[CHACHA20_IV_LEN];
    const uint8_t   *crp_cipher_key;
    int            (*crp_callback)(struct cryptop *);
    struct mbuf     *_crp_mbuf;
    crypto_session_t _crp_sid;
};

static __inline int
crypto_newsession(crypto_session_t *sidp,
                  const struct crypto_session_params *csp,
                  int flags)
{
    (void)csp; (void)flags;
    static uintptr_t _sid_counter = 1;
    *sidp = _sid_counter++;
    return 0;
}

static __inline void
crypto_freesession(crypto_session_t sid) { (void)sid; }

static __inline void
crypto_initreq(struct cryptop *crp, crypto_session_t sid)
{
    memset(crp, 0, sizeof(*crp));
    crp->_crp_sid = sid;
}

static __inline void
crypto_use_mbuf(struct cryptop *crp, struct mbuf *m)
{
    crp->_crp_mbuf = m;
}

static __inline void
crypto_destroyreq(struct cryptop *crp) { (void)crp; }

int crypto_dispatch(struct cryptop *crp);
