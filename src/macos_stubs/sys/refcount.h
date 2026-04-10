/* FreeBSD sys/refcount.h → macOS stub using __atomic builtins */
#pragma once
#include <sys/types.h>   /* u_int */

static inline void
refcount_init(u_int *count, u_int val)
{
    __atomic_store_n(count, val, __ATOMIC_RELAXED);
}

static inline void
refcount_acquire(u_int *count)
{
    __atomic_fetch_add(count, 1u, __ATOMIC_RELAXED);
}

/* Returns 1 when the count drops to zero (last reference released) */
static inline int
refcount_release(u_int *count)
{
    return __atomic_sub_fetch(count, 1u, __ATOMIC_ACQ_REL) == 0;
}

/* Atomically increment if > 0; returns 1 on success, 0 if already zero */
static inline int
refcount_acquire_if_not_zero(u_int *count)
{
    u_int v = __atomic_load_n(count, __ATOMIC_RELAXED);
    do {
        if (v == 0)
            return 0;
    } while (!__atomic_compare_exchange_n(count, &v, v + 1u,
                                          /*weak=*/1,
                                          __ATOMIC_ACQ_REL,
                                          __ATOMIC_RELAXED));
    return 1;
}
