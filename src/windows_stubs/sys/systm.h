/* FreeBSD sys/systm.h -> Windows stub */
#pragma once
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef bcmp
#define bcmp(a, b, n) memcmp((a), (b), (n))
#endif
#ifndef bzero
#define bzero(s, n) memset((s), 0, (n))
#endif

/* rand_s: MSVC's own declaration is gated behind _CRT_RAND_S defined
 * before <stdlib.h>'s FIRST inclusion in the translation unit, which we
 * can't guarantee this deep in the include chain (some earlier header
 * may have pulled in <stdlib.h> first without it). Declare it directly —
 * the symbol exists in the CRT import lib regardless of the macro gate. */
extern int rand_s(unsigned int *randomValue);

/* arc4random/arc4random_buf: BSD CSPRNG calls wg_noise.c/wg_cookie.c use
 * directly. rand_s draws from the OS CSPRNG (RtlGenRandom), same source
 * curve25519_portable.c uses for key generation. */
static __inline void
arc4random_buf(void *buf, size_t n)
{
    unsigned char *p = (unsigned char *)buf;
    while (n >= 4) {
        unsigned int w;
        rand_s(&w);
        memcpy(p, &w, 4);
        p += 4;
        n -= 4;
    }
    if (n) {
        unsigned int w;
        rand_s(&w);
        memcpy(p, &w, n);
    }
}

static __inline uint32_t
arc4random(void)
{
    unsigned int w;
    rand_s(&w);
    return (uint32_t)w;
}

#include <sys/queue.h>    /* our LIST_* macros */
#include <sys/callout.h>  /* struct callout, callout_*, hz */

/* getnanotime: current real-time wall clock into timespec */
static __inline void
getnanotime(struct timespec *ts)
{
    timespec_get(ts, TIME_UTC);
}

/* timingsafe_bcmp: constant-time comparison (prevents timing attacks).
 * MSVC's UCRT doesn't have it. */
static __inline int
timingsafe_bcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;
    unsigned char diff = 0;
    while (n--) diff |= *pa++ ^ *pb++;
    return diff != 0;
}

/*
 * explicit_bzero: MSVC's UCRT doesn't have it either.
 */
#undef explicit_bzero
#define explicit_bzero(buf, len)                                \
    do {                                                        \
        volatile unsigned char *_eb_p =                        \
            (volatile unsigned char *)(buf);                   \
        size_t _eb_n = (len);                                   \
        while (_eb_n--) *_eb_p++ = '\0';                       \
    } while (0)
