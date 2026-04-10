/* FreeBSD sys/mutex.h → macOS stub using pthread_mutex_t */
#pragma once
#include <pthread.h>

struct mtx { pthread_mutex_t _m; };

#define MTX_DEF  0
#define MTX_SPIN 1

static inline void
mtx_init(struct mtx *m,
    const char *name   __attribute__((unused)),
    const char *type   __attribute__((unused)),
    int         opts   __attribute__((unused)))
{
    pthread_mutex_init(&m->_m, NULL);
}

static inline void mtx_lock(struct mtx *m)    { pthread_mutex_lock(&m->_m); }
static inline void mtx_unlock(struct mtx *m)  { pthread_mutex_unlock(&m->_m); }
static inline void mtx_destroy(struct mtx *m) { pthread_mutex_destroy(&m->_m); }

/* FreeBSD mutex assertion flags */
#define MA_OWNED    0x01
#define MA_NOTOWNED 0x02

/* mtx_assert: debug assertion — no-op in userspace stub */
static inline void
mtx_assert(struct mtx *m   __attribute__((unused)),
           int          what __attribute__((unused))) { }
