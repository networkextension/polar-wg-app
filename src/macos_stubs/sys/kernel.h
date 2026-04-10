/* FreeBSD sys/kernel.h → macOS stub */
#pragma once

/* malloc type tokens are opaque void* in userspace */
typedef void *malloc_type_t;

/* MALLOC_DEFINE: declare a malloc type at file scope */
#define MALLOC_DEFINE(type, shortdesc, longdesc) \
    malloc_type_t type __attribute__((unused)) = NULL

#define MALLOC_DECLARE(type) \
    extern malloc_type_t type
