/* FreeBSD sys/epoch.h -> Windows stub (simplified: no deferred reclamation) */
#pragma once

struct epoch_tracker { int _dummy; };
struct epoch_context { void (*ec_callback)(struct epoch_context *); };

#define NET_EPOCH_ENTER(et)     ((void)(et))
#define NET_EPOCH_EXIT(et)      ((void)(et))
#define NET_EPOCH_CALL(fn, ctx) ((fn)(ctx))
