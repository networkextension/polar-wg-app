/* FreeBSD arpa/inet.h -> Windows stub via Winsock2 (inet_pton/inet_ntop
 * live in ws2tcpip.h on Windows). */
#pragma once
#define WIN32_LEAN_AND_MEAN
#ifndef _WINSOCKAPI_
#include <winsock2.h>
#endif
#include <ws2tcpip.h>
