/* FreeBSD sys/endian.h → cross-platform endian helpers.
 *
 * On macOS: #include_next <sys/endian.h> which provides le32dec, le64enc, etc.
 * On Android/Linux: provide our own inline implementations since bionic
 *   has <endian.h> but NOT the FreeBSD-style le32dec/le64enc helpers.
 */
#pragma once

#if defined(__APPLE__)
  #include_next <sys/endian.h>
#elif defined(__ANDROID__) || defined(__linux__)
  #include <endian.h>
  #include <stdint.h>
  #include <string.h>

  /* le32dec / le64dec — decode little-endian from byte array */
  static inline uint32_t le32dec(const void *pp) {
      const uint8_t *p = (const uint8_t *)pp;
      return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
  }
  static inline uint64_t le64dec(const void *pp) {
      const uint8_t *p = (const uint8_t *)pp;
      return (uint64_t)le32dec(p) | ((uint64_t)le32dec(p+4) << 32);
  }

  /* le32enc / le64enc — encode little-endian to byte array */
  static inline void le32enc(void *pp, uint32_t v) {
      uint8_t *p = (uint8_t *)pp;
      p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
  }
  static inline void le64enc(void *pp, uint64_t v) {
      le32enc(pp, (uint32_t)v);
      le32enc((uint8_t*)pp + 4, (uint32_t)(v >> 32));
  }

  /* be64enc / be32enc — for TAI64N timestamps */
  static inline void be32enc(void *pp, uint32_t v) {
      uint8_t *p = (uint8_t *)pp;
      p[0]=(uint8_t)(v>>24); p[1]=(uint8_t)(v>>16); p[2]=(uint8_t)(v>>8); p[3]=(uint8_t)v;
  }
  static inline void be64enc(void *pp, uint64_t v) {
      be32enc(pp, (uint32_t)(v >> 32));
      be32enc((uint8_t*)pp + 4, (uint32_t)v);
  }

  /* htobe64 / htobe32 — host to big-endian */
  #ifndef htobe64
    #if __BYTE_ORDER == __LITTLE_ENDIAN
      #define htobe64(x) __builtin_bswap64(x)
      #define htobe32(x) __builtin_bswap32(x)
    #else
      #define htobe64(x) (x)
      #define htobe32(x) (x)
    #endif
  #endif

  /* ntohs / htons — bionic sometimes hides these behind feature macros */
  #ifndef ntohs
    static inline uint16_t _stub_ntohs(uint16_t x) {
        return (uint16_t)((x >> 8) | (x << 8));
    }
    #define ntohs(x) _stub_ntohs(x)
    #define htons(x) _stub_ntohs(x)
  #endif

  /* le32toh etc. — already defined by <endian.h> on most Linux */
  #ifndef le32toh
    #if __BYTE_ORDER == __LITTLE_ENDIAN
      #define le32toh(x) (x)
      #define htole32(x) (x)
      #define le64toh(x) (x)
      #define htole64(x) (x)
    #else
      #define le32toh(x) __builtin_bswap32(x)
      #define htole32(x) __builtin_bswap32(x)
      #define le64toh(x) __builtin_bswap64(x)
      #define htole64(x) __builtin_bswap64(x)
    #endif
  #endif
#else
  #error "Unsupported platform for sys/endian.h stub"
#endif
