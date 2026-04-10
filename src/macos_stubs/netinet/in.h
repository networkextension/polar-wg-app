/* FreeBSD netinet/in.h extras → wrap real macOS header and add BSD helpers */
#pragma once
#include_next <netinet/in.h>

/* satosin / satosin6: cast struct sockaddr* to typed pointer.
 * These are FreeBSD helpers; macOS does not define them in <netinet/in.h>. */
#ifndef satosin
#define satosin(sa)   ((struct sockaddr_in  *)(sa))
#endif
#ifndef satosin6
#define satosin6(sa)  ((struct sockaddr_in6 *)(sa))
#endif
