/* FreeBSD sys/systm.h → cross-platform userspace stub */
#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>    /* bzero on Android/Linux (strict C11 needs this) */

/* bcmp: Android bionic C11 strict mode may not declare it. */
#if !defined(bcmp) && !defined(__APPLE__)
#define bcmp(a, b, n) memcmp((a), (b), (n))
#endif
#include <time.h>

#if defined(__APPLE__)
  #include <sys/queue.h>    /* LIST_*, TAILQ_*, LIST_FOREACH_SAFE, ... */
#elif defined(__ANDROID__) || defined(__linux__)
  #include <sys/queue.h>    /* bionic/glibc also has this */
#endif

#include <sys/callout.h>  /* struct callout, callout_*, hz */

/* getnanotime: current real-time wall clock into timespec */
static inline void
getnanotime(struct timespec *ts)
{
    clock_gettime(CLOCK_REALTIME, ts);
}

/* timingsafe_bcmp: constant-time comparison (prevents timing attacks).
 * macOS libc has it; Android/Linux don't. Provide a portable version. */
#if !defined(__APPLE__)
static inline int
timingsafe_bcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;
    unsigned char diff = 0;
    while (n--) diff |= *pa++ ^ *pb++;
    return diff != 0;
}
#endif

/* arc4random_buf: available on macOS libc and Android API 28+.
 * On older Android APIs (our min is 24), bionic still has it
 * declared in <stdlib.h> since NDK r21. No fallback needed. */

/* LIST_FOREACH_SAFE: Android/Linux sys/queue.h may not have it.
 * Provide a portable version. */
#if !defined(LIST_FOREACH_SAFE)
#define LIST_FOREACH_SAFE(var, head, field, tvar) \
    for ((var) = LIST_FIRST((head)); \
         (var) && ((tvar) = LIST_NEXT((var), field), 1); \
         (var) = (tvar))
#endif

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
