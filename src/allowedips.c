/* SPDX-License-Identifier: MIT
 *
 * allowedips: simple binary bit trie for longest-prefix-match.
 * See allowedips.h for the API contract.
 */

#include "allowedips.h"

#include <stdlib.h>
#include <string.h>

struct aips_node {
    void             *peer;     /* non-NULL iff a CIDR ends at this node */
    struct aips_node *child[2]; /* index by next bit */
};

static struct aips_node *
node_alloc(void)
{
    return (struct aips_node *)calloc(1, sizeof(struct aips_node));
}

static void
node_free_recursive(struct aips_node *n)
{
    if (!n) return;
    node_free_recursive(n->child[0]);
    node_free_recursive(n->child[1]);
    free(n);
}

/* Extract bit i (0 = MSB of byte 0) from a network-order byte array. */
static inline int
bit_at(const uint8_t *addr, unsigned int i)
{
    return (addr[i >> 3] >> (7 - (i & 7))) & 1;
}

void
aips_init(struct aips_trie *t, unsigned int max_bits)
{
    t->root     = NULL;
    t->max_bits = max_bits;
    t->entries  = 0;
}

void
aips_destroy(struct aips_trie *t)
{
    if (!t) return;
    node_free_recursive(t->root);
    t->root    = NULL;
    t->entries = 0;
}

int
aips_insert(struct aips_trie *t,
            const uint8_t *addr, unsigned int prefix_len, void *peer)
{
    if (!t || !addr || !peer || prefix_len > t->max_bits)
        return -1;

    if (!t->root) {
        t->root = node_alloc();
        if (!t->root) return -1;
    }

    struct aips_node *n = t->root;
    for (unsigned int i = 0; i < prefix_len; i++) {
        int b = bit_at(addr, i);
        if (!n->child[b]) {
            n->child[b] = node_alloc();
            if (!n->child[b]) return -1;
        }
        n = n->child[b];
    }
    if (n->peer == NULL) t->entries++;
    n->peer = peer;
    return 0;
}

void *
aips_lookup(const struct aips_trie *t, const uint8_t *addr)
{
    if (!t || !t->root || !addr) return NULL;

    void *best = NULL;
    const struct aips_node *n = t->root;
    if (n->peer) best = n->peer;  /* default route case (prefix_len == 0) */

    for (unsigned int i = 0; i < t->max_bits; i++) {
        int b = bit_at(addr, i);
        n = n->child[b];
        if (!n) break;
        if (n->peer) best = n->peer;  /* longest match wins */
    }
    return best;
}

int
aips_remove(struct aips_trie *t,
            const uint8_t *addr, unsigned int prefix_len)
{
    if (!t || !t->root || prefix_len > t->max_bits)
        return -1;

    struct aips_node *n = t->root;
    for (unsigned int i = 0; i < prefix_len; i++) {
        int b = bit_at(addr, i);
        if (!n->child[b]) return -1;
        n = n->child[b];
    }
    if (n->peer == NULL) return -1;
    n->peer = NULL;
    if (t->entries > 0) t->entries--;
    return 0;
}

/* IPv4 convenience: take a host-order uint32_t and split into 4 bytes. */
static void
v4_to_be(uint8_t out[4], uint32_t addr_host)
{
    out[0] = (uint8_t)((addr_host >> 24) & 0xff);
    out[1] = (uint8_t)((addr_host >> 16) & 0xff);
    out[2] = (uint8_t)((addr_host >>  8) & 0xff);
    out[3] = (uint8_t)( addr_host        & 0xff);
}

int
aips_insert_v4(struct aips_trie *t, uint32_t addr_host,
               unsigned int prefix_len, void *peer)
{
    uint8_t buf[4];
    v4_to_be(buf, addr_host);
    return aips_insert(t, buf, prefix_len, peer);
}

void *
aips_lookup_v4(const struct aips_trie *t, uint32_t addr_host)
{
    uint8_t buf[4];
    v4_to_be(buf, addr_host);
    return aips_lookup(t, buf);
}
