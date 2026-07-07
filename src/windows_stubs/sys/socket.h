/* FreeBSD sys/socket.h -> Windows stub via Winsock2 */
#pragma once
#define WIN32_LEAN_AND_MEAN
#ifndef _WINSOCKAPI_
#include <winsock2.h>
#endif
#include <ws2tcpip.h>
