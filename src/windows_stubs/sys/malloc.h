/* FreeBSD sys/malloc.h -> Windows userspace stub */
#pragma once
#include <stdlib.h>
#include <sys/kernel.h>

#define M_WAITOK  0x0002
#define M_NOWAIT  0x0001
#define M_ZERO    0x0100

/* Override 3-argument FreeBSD malloc -> calloc (always zero-initialises) */
#undef malloc
#define malloc(size, type, flags)  calloc(1, (size_t)(size))

#define zfree(ptr, type)  free(ptr)
