/* FreeBSD sys/ck.h → macOS stub: map CK_LIST to BSD sys/queue.h LIST */
#pragma once
#include <sys/queue.h>

#define CK_LIST_ENTRY(type)                     LIST_ENTRY(type)
#define CK_LIST_HEAD(name, type)                LIST_HEAD(name, type)
#define CK_LIST_INIT(head)                      LIST_INIT(head)
#define CK_LIST_INSERT_HEAD(head, elm, field)   LIST_INSERT_HEAD(head, elm, field)
#define CK_LIST_INSERT_BEFORE(le, elm, field)   LIST_INSERT_BEFORE(le, elm, field)
#define CK_LIST_REMOVE(elm, field)              LIST_REMOVE(elm, field)
#define CK_LIST_FOREACH(var, head, field)       LIST_FOREACH(var, head, field)
