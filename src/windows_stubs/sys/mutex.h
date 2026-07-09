/* FreeBSD sys/mutex.h -> Windows stub using CRITICAL_SECTION */
#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

struct mtx { CRITICAL_SECTION _m; };

#define MTX_DEF  0
#define MTX_SPIN 1

static __inline void
mtx_init(struct mtx *m, const char *name, const char *type, int opts)
{
    (void)name; (void)type; (void)opts;
    InitializeCriticalSection(&m->_m);
}

static __inline void mtx_lock(struct mtx *m)    { EnterCriticalSection(&m->_m); }
static __inline void mtx_unlock(struct mtx *m)  { LeaveCriticalSection(&m->_m); }
static __inline void mtx_destroy(struct mtx *m) { DeleteCriticalSection(&m->_m); }

#define MA_OWNED    0x01
#define MA_NOTOWNED 0x02

static __inline void
mtx_assert(struct mtx *m, int what) { (void)m; (void)what; }
