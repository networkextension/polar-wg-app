/* FreeBSD sys/callout.h → macOS stub using Grand Central Dispatch
 *
 * FreeBSD semantics replicated here:
 *   - callout_init_mtx: associates a mutex that is auto-acquired before
 *     the callback fires (and released after).
 *   - callout_reset:    schedules the callback after `ticks` kernel ticks.
 *   - callout_stop:     cancels any pending/future firing.
 *   - callout_pending:  returns non-zero if a firing is scheduled.
 *
 * Thread-safety note: a generation counter ensures that a block queued by
 * an earlier callout_reset does nothing if callout_stop or a later
 * callout_reset runs before the block executes.
 */
#pragma once
#include <dispatch/dispatch.h>
#include <stdint.h>
#include <string.h>
#include <sys/mutex.h>  /* struct mtx, mtx_lock/unlock */

/* Emulated kernel tick rate (FreeBSD default: 1000 Hz) */
#ifndef hz
#define hz 1000
#endif

struct callout {
    struct mtx       *co_lock;
    dispatch_queue_t  co_queue;
    volatile int      co_generation; /* bumped on each reset/stop */
};

static inline void
callout_init_mtx(struct callout *c, struct mtx *lock,
                 int flags __attribute__((unused)))
{
    memset(c, 0, sizeof(*c));
    c->co_lock  = lock;
    c->co_queue = dispatch_queue_create("wg.ratelimit.gc",
                                        DISPATCH_QUEUE_SERIAL);
}

static inline int
callout_pending(struct callout *c)
{
    /* Non-zero generation means at least one reset has been issued
     * that has not yet been cancelled by a matching stop/reset. */
    return __atomic_load_n(&c->co_generation, __ATOMIC_ACQUIRE) != 0;
}

static inline void
callout_stop(struct callout *c)
{
    /* Invalidate any block currently scheduled on co_queue. */
    __atomic_fetch_add(&c->co_generation, 1, __ATOMIC_SEQ_CST);
}

static inline void
callout_reset(struct callout *c, int ticks,
              void (*fn)(void *), void *arg)
{
    /* Bump generation: this cancels any previously scheduled block
     * and produces a new token that the new block must match. */
    int gen = __atomic_add_fetch(&c->co_generation, 1, __ATOMIC_SEQ_CST);

    int64_t delay_ns = (int64_t)ticks * (1000000000LL / hz);

    /* Capture everything by value so the block is self-contained. */
    struct callout *cap_c   = c;
    void          (*cap_fn)(void *) = fn;
    void           *cap_arg = arg;

    dispatch_after(
        dispatch_time(DISPATCH_TIME_NOW, delay_ns),
        c->co_queue,
        ^{
            /* Bail if a newer reset/stop has already superseded us. */
            if (__atomic_load_n(&cap_c->co_generation,
                                __ATOMIC_SEQ_CST) != gen)
                return;

            /* FreeBSD callout_init_mtx: lock is held across the callback. */
            mtx_lock(cap_c->co_lock);
            /* Re-check inside the lock in case stop raced with us. */
            if (__atomic_load_n(&cap_c->co_generation,
                                __ATOMIC_SEQ_CST) == gen)
                cap_fn(cap_arg);
            mtx_unlock(cap_c->co_lock);
        });
}
