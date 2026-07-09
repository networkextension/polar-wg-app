/* POSIX strings.h -> Windows stub. Nothing in this tree actually calls
 * bzero/strcasecmp from here; the include exists defensively for other
 * platforms, so an empty header satisfies it. */
#pragma once
#include <string.h>

/* strtok_r isn't declared by MSVC's CRT (which was silently falling back
 * to an implicit int-returning declaration — a real bug, not just a
 * warning: it truncated the returned pointer on 64-bit). MSVC's own
 * strtok_s has the identical (str, delim, **context) signature. */
#ifndef strtok_r
#define strtok_r strtok_s
#endif
