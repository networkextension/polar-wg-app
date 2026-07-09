/* FreeBSD vm/uma.h -> Windows stub: Universal Memory Allocator -> malloc/free */
#pragma once
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifndef M_ZERO
#define M_ZERO   0x0100
#endif
#ifndef M_NOWAIT
#define M_NOWAIT 0x0001
#endif

struct uma_zone {
    size_t _itemsize;
};
typedef struct uma_zone *uma_zone_t;

static __inline uma_zone_t
uma_zcreate(const char *name, size_t size, void *ctor, void *dtor,
            void *zinit, void *zfini, int align, uint32_t flags)
{
    (void)name; (void)ctor; (void)dtor; (void)zinit; (void)zfini;
    (void)align; (void)flags;
    uma_zone_t z = (uma_zone_t)calloc(1, sizeof(*z));
    if (z)
        z->_itemsize = size;
    return z;
}

static __inline void
uma_zdestroy(uma_zone_t z)
{
    free(z);
}

static __inline void *
uma_zalloc(uma_zone_t z, int flags)
{
    (void)flags;
    return calloc(1, z->_itemsize);
}

static __inline void
uma_zfree(uma_zone_t z, void *item)
{
    (void)z;
    free(item);
}
