/* FreeBSD sys/rwlock.h -> Windows stub using SRWLOCK.
 * Note: SRWLOCK has no upgrade/downgrade and readers/writers are not
 * re-entrant, same restriction as the pthread_rwlock_t used on macOS. */
#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sys/lock.h>   /* RA_* flags */

struct rwlock { SRWLOCK _rw; };

static __inline void
rw_init(struct rwlock *rw, const char *name)
{
    (void)name;
    InitializeSRWLock(&rw->_rw);
}

static __inline void rw_rlock(struct rwlock *rw)    { AcquireSRWLockShared(&rw->_rw); }
static __inline void rw_runlock(struct rwlock *rw)  { ReleaseSRWLockShared(&rw->_rw); }
static __inline void rw_wlock(struct rwlock *rw)    { AcquireSRWLockExclusive(&rw->_rw); }
static __inline void rw_wunlock(struct rwlock *rw)  { ReleaseSRWLockExclusive(&rw->_rw); }
static __inline void rw_destroy(struct rwlock *rw)  { (void)rw; /* SRWLOCK needs no destroy */ }

static __inline void
rw_assert(struct rwlock *rw, int flags) { (void)rw; (void)flags; }
