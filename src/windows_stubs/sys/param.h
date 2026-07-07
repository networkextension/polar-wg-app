/* FreeBSD sys/param.h -> Windows stub (no #include_next; MSVC doesn't
 * support it, so everything needed is provided here directly). */
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>

/* ESTALE: POSIX/NFS errno MSVC's UCRT doesn't define. Used here only as
 * a distinct internal sentinel value, not for real filesystem I/O. */
#ifndef ESTALE
#define ESTALE 133
#endif

/* Legacy BSD integer aliases used directly as struct field types in
 * wg_noise.c / wg_cookie.c. MSVC's own <sys/types.h> doesn't define
 * these (they're a BSD-ism, not part of the UCRT). */
#if !defined(_WG_BSD_INT_TYPES_DEFINED)
#define _WG_BSD_INT_TYPES_DEFINED 1
typedef unsigned char  u_char;
typedef unsigned short u_short;
typedef unsigned int   u_int;
typedef unsigned long  u_long;
#endif

/* ---- sbintime (FreeBSD binary-time, mapped to nanoseconds) ---- */
typedef int64_t sbintime_t;
#define SBT_1S  ((sbintime_t)1000000000LL)

static __inline sbintime_t
getsbinuptime(void)
{
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    return (sbintime_t)ts.tv_sec * SBT_1S + (sbintime_t)ts.tv_nsec;
}

static __inline sbintime_t
nstosbt(uint32_t ns)
{
    return (sbintime_t)ns;
}

/* ---- compiler helpers (MSVC has no __attribute__/__builtin_*) ---- */
/* __aligned(n) is used postfix (GCC/Clang attribute style: `TYPE var
 * __aligned(n);`), which MSVC's prefix-only __declspec(align(n)) can't
 * express in that position. Drop it: x86/x64 handles unaligned uint32_t
 * access fine, just not necessarily at peak speed. */
#ifndef __aligned
#define __aligned(n)
#endif

#ifndef __predict_false
#define __predict_false(x)  (x)
#define __predict_true(x)   (x)
#endif

#ifndef __containerof
#define __containerof(x, s, m) \
    ((s *)((char *)(x) - offsetof(s, m)))
#endif

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

/* ---- FreeBSD atomic operations (mapped to MSVC intrinsics) ---- */
#include <intrin.h>

#define atomic_load_ptr(p)       (*(p))
#define atomic_store_ptr(p, v)   (*(p) = (v))
#define atomic_load_bool(p)      (*(p))
#define atomic_store_bool(p, v)  (*(p) = (v))
#define atomic_fetchadd_64(p, v) _InterlockedExchangeAdd64((__int64 volatile *)(p), (__int64)(v))
#define atomic_store_64(p, v)    (*(p) = (v))
#define atomic_load_64(p)        (*(p))
