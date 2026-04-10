/* FreeBSD vm/uma.h → macOS stub: Universal Memory Allocator → malloc/free */
#pragma once
/* Use stdlib directly – avoid the 3-arg malloc macro from sys/malloc.h */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Reproduce only the flag bits we need (M_ZERO) without pulling sys/malloc.h */
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

/* uma_zcreate: create a zone that allocates objects of 'size' bytes.
 * The ctor/dtor/init/fini/align/flags arguments are kernel-only; ignored. */
static inline uma_zone_t
uma_zcreate(const char *name     __attribute__((unused)),
            size_t       size,
            void        *ctor    __attribute__((unused)),
            void        *dtor    __attribute__((unused)),
            void        *zinit   __attribute__((unused)),
            void        *zfini   __attribute__((unused)),
            int          align   __attribute__((unused)),
            uint32_t     flags   __attribute__((unused)))
{
    uma_zone_t z = (uma_zone_t)calloc(1, sizeof(*z));
    if (z)
        z->_itemsize = size;
    return z;
}

static inline void
uma_zdestroy(uma_zone_t z)
{
    free(z);
}

/* uma_zalloc: allocate one item from zone z.
 * Flags: M_ZERO zeroes the allocation; M_NOWAIT never blocks (same here). */
static inline void *
uma_zalloc(uma_zone_t z, int flags)
{
    /* Always zero-initialise for safety; M_NOWAIT is a no-op in userspace. */
    (void)flags;
    return calloc(1, z->_itemsize);
}

static inline void
uma_zfree(uma_zone_t z __attribute__((unused)), void *item)
{
    free(item);
}
