/* FreeBSD netinet/in.h -> Windows stub via Winsock2 */
#pragma once
#define WIN32_LEAN_AND_MEAN
#ifndef _WINSOCKAPI_
#include <winsock2.h>
#endif
#include <ws2tcpip.h>

/* in_port_t: POSIX typedef for a 16-bit port number. Windows' Winsock
 * headers use USHORT/unsigned short directly and never define this name. */
#ifndef _IN_PORT_T_DEFINED_WG
#define _IN_PORT_T_DEFINED_WG 1
typedef unsigned short in_port_t;
#endif

/* satosin / satosin6: cast struct sockaddr* to typed pointer.
 * FreeBSD helpers; Winsock headers don't define them. */
#ifndef satosin
#define satosin(sa)   ((struct sockaddr_in  *)(sa))
#endif
#ifndef satosin6
#define satosin6(sa)  ((struct sockaddr_in6 *)(sa))
#endif
