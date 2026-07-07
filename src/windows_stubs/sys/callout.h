/* FreeBSD sys/callout.h -> Windows stub.
 *
 * No real timer backend yet (no tunnel event loop on this platform yet)
 * — same no-op behavior as the Android/Linux branch of the macOS stub:
 * callout_reset() does nothing, and whatever host drives the session
 * (once one exists) is expected to call wg_session_tick() on its own
 * schedule instead.
 */
#pragma once
#include <stdint.h>
#include <string.h>
#include <sys/mutex.h>

#ifndef hz
#define hz 1000
#endif

struct callout {
    struct mtx  *co_lock;
    volatile long co_generation;
};

static __inline void
callout_init_mtx(struct callout *c, struct mtx *lock, int flags)
{
    (void)flags;
    memset(c, 0, sizeof(*c));
    c->co_lock = lock;
}

static __inline int
callout_pending(struct callout *c)
{
    return c->co_generation != 0;
}

static __inline void
callout_stop(struct callout *c)
{
    c->co_generation++;
}

static __inline void
callout_reset(struct callout *c, int ticks, void (*fn)(void *), void *arg)
{
    (void)ticks; (void)fn; (void)arg;
    c->co_generation++;
}
