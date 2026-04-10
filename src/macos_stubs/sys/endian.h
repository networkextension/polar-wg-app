/* FreeBSD sys/endian.h → include real macOS endian header */
#pragma once
#include_next <sys/endian.h>

/* macOS sys/endian.h already provides le64enc, be64enc, htobe64, etc. */
