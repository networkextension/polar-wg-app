/* FreeBSD sys/rwlock.h → macOS stub using pthread_rwlock_t */
#pragma once
#include <pthread.h>
#include <sys/lock.h>   /* RA_* flags */

struct rwlock { pthread_rwlock_t _rw; };

static inline void
rw_init(struct rwlock *rw, const char *name __attribute__((unused)))
{
    pthread_rwlock_init(&rw->_rw, NULL);
}

static inline void rw_rlock(struct rwlock *rw)    { pthread_rwlock_rdlock(&rw->_rw); }
static inline void rw_runlock(struct rwlock *rw)  { pthread_rwlock_unlock(&rw->_rw); }
static inline void rw_wlock(struct rwlock *rw)    { pthread_rwlock_wrlock(&rw->_rw); }
static inline void rw_wunlock(struct rwlock *rw)  { pthread_rwlock_unlock(&rw->_rw); }
static inline void rw_destroy(struct rwlock *rw)  { pthread_rwlock_destroy(&rw->_rw); }

static inline void
rw_assert(struct rwlock *rw   __attribute__((unused)),
          int            flags __attribute__((unused)))
{
    /* no-op in userspace stub */
}
