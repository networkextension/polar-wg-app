/* FreeBSD sys/refcount.h -> Windows stub using _Interlocked* intrinsics.
 * u_int and `long` are both 32-bit on all Windows targets, so a cast to
 * `long volatile *` is safe here. */
#pragma once
#include <sys/types.h>   /* u_int */
#include <intrin.h>

static __inline void
refcount_init(u_int *count, u_int val)
{
    _InterlockedExchange((long volatile *)count, (long)val);
}

static __inline void
refcount_acquire(u_int *count)
{
    _InterlockedExchangeAdd((long volatile *)count, 1);
}

/* Returns 1 when the count drops to zero (last reference released) */
static __inline int
refcount_release(u_int *count)
{
    long prev = _InterlockedExchangeAdd((long volatile *)count, -1);
    return (prev - 1) == 0;
}

/* Atomically increment if > 0; returns 1 on success, 0 if already zero */
static __inline int
refcount_acquire_if_not_zero(u_int *count)
{
    long v = *(long volatile *)count;
    for (;;) {
        if (v == 0)
            return 0;
        long prev = _InterlockedCompareExchange((long volatile *)count, v + 1, v);
        if (prev == v)
            return 1;
        v = prev;
    }
}
