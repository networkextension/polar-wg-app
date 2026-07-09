/* FreeBSD sys/endian.h -> Windows stub. All Windows targets (x86/x64/ARM64)
 * are little-endian, so le-prefixed helpers are no-ops and the be/ntoh/hton
 * ones byteswap. */
#pragma once
#include <stdint.h>
#include <stdlib.h>   /* _byteswap_ulong/_byteswap_uint64 */

static __inline uint32_t le32dec(const void *pp) {
    const uint8_t *p = (const uint8_t *)pp;
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static __inline uint64_t le64dec(const void *pp) {
    const uint8_t *p = (const uint8_t *)pp;
    return (uint64_t)le32dec(p) | ((uint64_t)le32dec((const uint8_t *)p+4) << 32);
}
static __inline void le32enc(void *pp, uint32_t v) {
    uint8_t *p = (uint8_t *)pp;
    p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
}
static __inline void le64enc(void *pp, uint64_t v) {
    le32enc(pp, (uint32_t)v);
    le32enc((uint8_t*)pp + 4, (uint32_t)(v >> 32));
}
static __inline void be32enc(void *pp, uint32_t v) {
    uint8_t *p = (uint8_t *)pp;
    p[0]=(uint8_t)(v>>24); p[1]=(uint8_t)(v>>16); p[2]=(uint8_t)(v>>8); p[3]=(uint8_t)v;
}
static __inline void be64enc(void *pp, uint64_t v) {
    be32enc(pp, (uint32_t)(v >> 32));
    be32enc((uint8_t*)pp + 4, (uint32_t)v);
}

#define htobe64(x) _byteswap_uint64(x)
#define htobe32(x) _byteswap_ulong(x)

#define le32toh(x) (x)
#define htole32(x) (x)
#define le64toh(x) (x)
#define htole64(x) (x)

/* ntohs/htons intentionally NOT defined here: any file that needs them
 * pulls in <winsock2.h> (via windows_stubs/netinet/in.h), which declares
 * them as real functions — a macro here would collide with that. */
