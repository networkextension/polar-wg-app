/* SPDX-License-Identifier: MIT
 *
 * allowedips: a longest-prefix-match trie that maps IPv4/IPv6 CIDRs to
 * opaque "peer" pointers. Used by the WireGuard data plane on both
 * directions:
 *   - encap: given an outbound dst IP, find the peer it routes through
 *   - decap: given a freshly decrypted inner src IP, verify it belongs
 *     to the peer that sent the packet (anti-spoofing)
 *
 * The implementation is a simple binary bit trie. No locking, no RCU,
 * no concurrent mutation. Single-threaded use only — fits the wg_core
 * select() loop. If we ever go multi-threaded, replace with the Linux
 * kernel wireguard's rcu-protected variant.
 *
 * The trie is parameterized by max_bits at init time:
 *   - 32  for AF_INET
 *   - 128 for AF_INET6
 *
 * The peer pointer is opaque to the trie. The caller owns the lifetime
 * of whatever it points at; aips_destroy() does NOT free the peers.
 */
#ifndef _ALLOWEDIPS_H
#define _ALLOWEDIPS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct aips_node;

struct aips_trie {
    struct aips_node *root;
    unsigned int      max_bits;   /* 32 or 128 */
    size_t            entries;    /* number of CIDRs currently inserted */
};

/* Initialize an empty trie. max_bits must be 32 (IPv4) or 128 (IPv6). */
void  aips_init(struct aips_trie *t, unsigned int max_bits);

/* Free every internal node. Does NOT free peer pointers. */
void  aips_destroy(struct aips_trie *t);

/* Insert a CIDR mapping. addr is big-endian (network order) byte array
 * of (max_bits / 8) bytes. prefix_len is in bits, [0 .. max_bits].
 * peer must be non-NULL. Returns 0 on success, -1 on alloc failure or
 * bad arguments. Inserting at an existing exact CIDR replaces the old
 * peer pointer. */
int   aips_insert(struct aips_trie *t,
                  const uint8_t *addr, unsigned int prefix_len,
                  void *peer);

/* Longest-prefix-match lookup. Returns the peer for the most specific
 * CIDR that contains addr, or NULL if no CIDR matches. */
void *aips_lookup(const struct aips_trie *t, const uint8_t *addr);

/* Remove the exact (addr, prefix_len) CIDR. Returns 0 on success, -1
 * if no such CIDR exists. Does NOT prune empty subtrees — re-insert
 * is cheap so we don't bother. */
int   aips_remove(struct aips_trie *t,
                  const uint8_t *addr, unsigned int prefix_len);

/* Convenience helpers for IPv4 (host-order uint32_t input). */
int   aips_insert_v4(struct aips_trie *t, uint32_t addr_host,
                     unsigned int prefix_len, void *peer);
void *aips_lookup_v4(const struct aips_trie *t, uint32_t addr_host);

#endif /* _ALLOWEDIPS_H */
