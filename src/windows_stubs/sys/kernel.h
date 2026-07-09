/* FreeBSD sys/kernel.h -> Windows stub */
#pragma once

typedef void *malloc_type_t;

#define MALLOC_DEFINE(type, shortdesc, longdesc) \
    malloc_type_t type = NULL

#define MALLOC_DECLARE(type) \
    extern malloc_type_t type
