/* FreeBSD sys/param.h → macOS stub: include real macOS header then add extras */
#pragma once
#include_next <sys/param.h>

#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>

/* ---- sbintime (FreeBSD binary-time, mapped to nanoseconds) ---- */
typedef int64_t sbintime_t;
#define SBT_1S  ((sbintime_t)1000000000LL)

static inline sbintime_t
getsbinuptime(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (sbintime_t)ts.tv_sec * SBT_1S + (sbintime_t)ts.tv_nsec;
}

static inline sbintime_t
nstosbt(uint32_t ns)
{
    return (sbintime_t)ns;
}

/* ---- compiler helpers ---- */
#ifndef __aligned
#define __aligned(n)        __attribute__((aligned(n)))
#endif

#ifndef __predict_false
#define __predict_false(x)  __builtin_expect(!!(x), 0)
#define __predict_true(x)   __builtin_expect(!!(x), 1)
#endif

#ifndef __containerof
#define __containerof(x, s, m) \
    ((s *)((char *)(x) - __builtin_offsetof(s, m)))
#endif

/* ---- FreeBSD atomic operations (mapped to GCC/Clang __atomic builtins) ---- */
#define atomic_load_ptr(p)       __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define atomic_store_ptr(p, v)   __atomic_store_n((p), (v), __ATOMIC_RELEASE)
#define atomic_load_bool(p)      ((_Bool)__atomic_load_n((p), __ATOMIC_ACQUIRE))
#define atomic_store_bool(p, v)  __atomic_store_n((p), (_Bool)(v), __ATOMIC_RELEASE)
#define atomic_fetchadd_64(p, v) __atomic_fetch_add((p), (v), __ATOMIC_ACQ_REL)
#define atomic_store_64(p, v)    __atomic_store_n((p), (v), __ATOMIC_RELEASE)
#define atomic_load_64(p)        __atomic_load_n((p), __ATOMIC_ACQUIRE)
