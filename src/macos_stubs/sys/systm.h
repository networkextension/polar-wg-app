/* FreeBSD sys/systm.h → macOS userspace stub */
#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/queue.h>    /* LIST_*, TAILQ_*, LIST_FOREACH_SAFE, ... */
#include <sys/callout.h>  /* struct callout, callout_*, hz */

/* getnanotime: current real-time wall clock into timespec */
static inline void
getnanotime(struct timespec *ts)
{
    clock_gettime(CLOCK_REALTIME, ts);
}

/* timingsafe_bcmp, arc4random, arc4random_buf, bzero from macOS libc */

/*
 * explicit_bzero: macOS gating via __BSD_VISIBLE can hide it.
 * Provide a safe macro that shadows any library declaration.
 */
#undef explicit_bzero
#define explicit_bzero(buf, len)                                \
    do {                                                        \
        volatile unsigned char *_eb_p =                        \
            (volatile unsigned char *)(buf);                   \
        size_t _eb_n = (len);                                   \
        while (_eb_n--) *_eb_p++ = '\0';                       \
    } while (0)
