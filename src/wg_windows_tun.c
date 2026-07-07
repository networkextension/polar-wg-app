/* SPDX-License-Identifier: MIT
 *
 * wg_windows_tun: Windows CLI tunnel host, driving wg_session.c's I/O-free
 * API over a Wintun adapter — the Windows counterpart to
 * NetworkExtension/Sources/PacketTunnelProvider.swift (macOS) and
 * WireGuardAndroid's wg_jni.c (Android). Unlike wg_core.c (the POSIX
 * utun+select() reference client), this does NOT touch the noise_ /
 * cookie_ primitives directly — all state-machine work goes through
 * wg_session.c, exactly like the other two hosts.
 *
 * Usage: wg_windows_tun.exe <wg-quick-style-config-file>
 *
 * Requires wintun.dll (from wintun.net) next to the exe at runtime, and
 * admin elevation to create the adapter. Neither is needed to build this.
 */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wg_session.h"
#include "windows_stubs/wintun.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

/* ── Wintun: dynamically-loaded function table ─────────────────────────── */

/* The official wintun.h typedefs these as function TYPES (e.g.
 * `typedef T (WINAPI WINTUN_CREATE_ADAPTER_FUNC)(...)`), not pointer
 * types — so the variables holding the resolved GetProcAddress results
 * need an explicit `*`, matching Wintun's own example.c. */
static WINTUN_CREATE_ADAPTER_FUNC             *WintunCreateAdapter;
static WINTUN_OPEN_ADAPTER_FUNC               *WintunOpenAdapter;
static WINTUN_CLOSE_ADAPTER_FUNC              *WintunCloseAdapter;
static WINTUN_DELETE_DRIVER_FUNC              *WintunDeleteDriver;
static WINTUN_GET_ADAPTER_LUID_FUNC           *WintunGetAdapterLUID;
static WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC *WintunGetRunningDriverVersion;
static WINTUN_SET_LOGGER_FUNC                 *WintunSetLogger;
static WINTUN_START_SESSION_FUNC              *WintunStartSession;
static WINTUN_END_SESSION_FUNC                *WintunEndSession;
static WINTUN_GET_READ_WAIT_EVENT_FUNC        *WintunGetReadWaitEvent;
static WINTUN_RECEIVE_PACKET_FUNC             *WintunReceivePacket;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC     *WintunReleaseReceivePacket;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC       *WintunAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC                *WintunSendPacket;

static HMODULE g_wintun_dll;

#define WG_RESOLVE(name, type) \
    do { \
        name = (type)GetProcAddress(g_wintun_dll, #name); \
        if (!name) { \
            fprintf(stderr, "wintun.dll: missing export %s\n", #name); \
            return -1; \
        } \
    } while (0)

static int
wintun_load(void)
{
    g_wintun_dll = LoadLibraryExW(L"wintun.dll", NULL,
        LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!g_wintun_dll) {
        fprintf(stderr,
            "Could not load wintun.dll (error %lu). Download it from "
            "https://www.wintun.net and place it next to this exe.\n",
            (unsigned long)GetLastError());
        return -1;
    }

    WG_RESOLVE(WintunCreateAdapter, WINTUN_CREATE_ADAPTER_FUNC *);
    WG_RESOLVE(WintunOpenAdapter, WINTUN_OPEN_ADAPTER_FUNC *);
    WG_RESOLVE(WintunCloseAdapter, WINTUN_CLOSE_ADAPTER_FUNC *);
    WG_RESOLVE(WintunDeleteDriver, WINTUN_DELETE_DRIVER_FUNC *);
    WG_RESOLVE(WintunGetAdapterLUID, WINTUN_GET_ADAPTER_LUID_FUNC *);
    WG_RESOLVE(WintunGetRunningDriverVersion, WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC *);
    WG_RESOLVE(WintunSetLogger, WINTUN_SET_LOGGER_FUNC *);
    WG_RESOLVE(WintunStartSession, WINTUN_START_SESSION_FUNC *);
    WG_RESOLVE(WintunEndSession, WINTUN_END_SESSION_FUNC *);
    WG_RESOLVE(WintunGetReadWaitEvent, WINTUN_GET_READ_WAIT_EVENT_FUNC *);
    WG_RESOLVE(WintunReceivePacket, WINTUN_RECEIVE_PACKET_FUNC *);
    WG_RESOLVE(WintunReleaseReceivePacket, WINTUN_RELEASE_RECEIVE_PACKET_FUNC *);
    WG_RESOLVE(WintunAllocateSendPacket, WINTUN_ALLOCATE_SEND_PACKET_FUNC *);
    WG_RESOLVE(WintunSendPacket, WINTUN_SEND_PACKET_FUNC *);
    return 0;
}

/* ── Host context ────────────────────────────────────────────────────────── */

typedef struct {
    wg_session_t          *sess;
    WINTUN_ADAPTER_HANDLE   adapter;
    WINTUN_SESSION_HANDLE   tun_session;
    SOCKET                  udp_sock;
} wg_win_ctx;

static HANDLE g_quit_event;

static BOOL WINAPI
console_ctrl_handler(DWORD ctrl_type)
{
    (void)ctrl_type;
    SetEvent(g_quit_event);
    return TRUE;
}

/* ── wg_session callbacks ────────────────────────────────────────────────── */

static void
cb_send_udp(void *user_ctx, const uint8_t *bytes, size_t len,
            const struct sockaddr *to, socklen_t to_len)
{
    wg_win_ctx *ctx = (wg_win_ctx *)user_ctx;
    int rc;

    if (to->sa_family == AF_INET) {
        /* ctx->udp_sock is a dual-stack AF_INET6 socket (see
         * open_udp_socket) — Windows' sendto() rejects a raw
         * sockaddr_in on an AF_INET6 socket (WSAEAFNOSUPPORT), so an
         * IPv4 peer endpoint must be sent as an IPv4-mapped ::ffff:a.b.c.d
         * IPv6 address instead. Without this, every send silently fails
         * and the handshake retransmits forever with no response. */
        const struct sockaddr_in *in4 = (const struct sockaddr_in *)to;
        struct sockaddr_in6 mapped;
        memset(&mapped, 0, sizeof(mapped));
        mapped.sin6_family = AF_INET6;
        mapped.sin6_port = in4->sin_port;
        mapped.sin6_addr.u.Word[5] = 0xFFFF;
        memcpy(&mapped.sin6_addr.u.Byte[12], &in4->sin_addr, 4);
        rc = sendto(ctx->udp_sock, (const char *)bytes, (int)len, 0,
                    (struct sockaddr *)&mapped, sizeof(mapped));
    } else {
        rc = sendto(ctx->udp_sock, (const char *)bytes, (int)len, 0, to, to_len);
    }

    if (rc == SOCKET_ERROR) {
        fprintf(stderr, "sendto() failed: %d\n", WSAGetLastError());
    }
}

static void
cb_deliver_ip(void *user_ctx, const uint8_t *bytes, size_t len)
{
    wg_win_ctx *ctx = (wg_win_ctx *)user_ctx;
    BYTE *pkt = WintunAllocateSendPacket(ctx->tun_session, (DWORD)len);
    if (!pkt) {
        /* Ring full (ERROR_BUFFER_OVERFLOW) — drop, same backpressure
         * handling as the official Wintun example. */
        return;
    }
    memcpy(pkt, bytes, len);
    WintunSendPacket(ctx->tun_session, pkt);
}

static void
cb_log(void *user_ctx, const char *msg)
{
    (void)user_ctx;
    fprintf(stderr, "%s\n", msg);
}

/* ── Interface IP/MTU configuration via IP Helper API ───────────────────── */

static int
configure_interface(wg_win_ctx *ctx)
{
    NET_LUID luid;
    WintunGetAdapterLUID(ctx->adapter, &luid);

    int n = wg_session_iface_addr_count(ctx->sess);
    int have_v4 = 0, have_v6 = 0;

    for (int i = 0; i < n; i++) {
        char addr[64];
        int prefix, family;
        if (wg_session_iface_addr_get(ctx->sess, i, addr, &prefix, &family) != 0)
            continue;

        MIB_UNICASTIPADDRESS_ROW row;
        InitializeUnicastIpAddressEntry(&row);
        row.InterfaceLuid = luid;
        row.OnLinkPrefixLength = (UINT8)prefix;
        row.DadState = IpDadStatePreferred;

        if (family == AF_INET) {
            row.Address.Ipv4.sin_family = AF_INET;
            if (inet_pton(AF_INET, addr, &row.Address.Ipv4.sin_addr) != 1)
                continue;
            have_v4 = 1;
        } else if (family == AF_INET6) {
            row.Address.Ipv6.sin6_family = AF_INET6;
            if (inet_pton(AF_INET6, addr, &row.Address.Ipv6.sin6_addr) != 1)
                continue;
            have_v6 = 1;
        } else {
            continue;
        }

        DWORD err = CreateUnicastIpAddressEntry(&row);
        if (err != NO_ERROR && err != ERROR_OBJECT_ALREADY_EXISTS) {
            fprintf(stderr, "CreateUnicastIpAddressEntry(%s/%d) failed: %lu\n",
                addr, prefix, (unsigned long)err);
        }
    }

    /* MTU: match wg_core.c's utun_apply_inet4() default of 1420. */
    if (have_v4) {
        MIB_IPINTERFACE_ROW row;
        InitializeIpInterfaceEntry(&row);
        row.Family = AF_INET;
        row.InterfaceLuid = luid;
        if (GetIpInterfaceEntry(&row) == NO_ERROR) {
            row.NlMtu = 1420;
            row.SitePrefixLength = 0;
            SetIpInterfaceEntry(&row);
        }
    }
    if (have_v6) {
        MIB_IPINTERFACE_ROW row;
        InitializeIpInterfaceEntry(&row);
        row.Family = AF_INET6;
        row.InterfaceLuid = luid;
        if (GetIpInterfaceEntry(&row) == NO_ERROR) {
            row.NlMtu = 1420;
            row.SitePrefixLength = 0;
            SetIpInterfaceEntry(&row);
        }
    }

    /* Routes: a unicast address alone implies NO subnet route on Windows
     * (unlike ifconfig+route on macOS/Linux, which wg_core.c's
     * utun_apply_peer_routes() relies on) — every peer's AllowedIPs CIDR
     * needs an explicit route pointed at this adapter, or nothing beyond
     * the interface's own /32 host address is reachable. */
    int peer_count = wg_session_peer_count(ctx->sess);
    for (int i = 0; i < peer_count; i++) {
        int allowed_count = wg_session_peer_allowed_count(ctx->sess, i);
        for (int j = 0; j < allowed_count; j++) {
            char addr[64];
            int prefix, family;
            if (wg_session_peer_allowed_get(ctx->sess, i, j, addr, &prefix, &family) != 0)
                continue;

            MIB_IPFORWARD_ROW2 route;
            InitializeIpForwardEntry(&route);
            route.InterfaceLuid = luid;
            route.DestinationPrefix.PrefixLength = (UINT8)prefix;
            route.Metric = 0;

            if (family == AF_INET) {
                route.DestinationPrefix.Prefix.si_family = AF_INET;
                if (inet_pton(AF_INET, addr, &route.DestinationPrefix.Prefix.Ipv4.sin_addr) != 1)
                    continue;
                route.NextHop.si_family = AF_INET; /* on-link: no next hop */
            } else if (family == AF_INET6) {
                route.DestinationPrefix.Prefix.si_family = AF_INET6;
                if (inet_pton(AF_INET6, addr, &route.DestinationPrefix.Prefix.Ipv6.sin6_addr) != 1)
                    continue;
                route.NextHop.si_family = AF_INET6;
            } else {
                continue;
            }

            DWORD err = CreateIpForwardEntry2(&route);
            if (err != NO_ERROR && err != ERROR_OBJECT_ALREADY_EXISTS) {
                fprintf(stderr, "CreateIpForwardEntry2(%s/%d) failed: %lu\n",
                    addr, prefix, (unsigned long)err);
            }
        }
    }

    return 0;
}

/* ── UDP socket setup ────────────────────────────────────────────────────── */

static SOCKET
open_udp_socket(uint16_t listen_port, WSAEVENT udp_event)
{
    SOCKET s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) {
        fprintf(stderr, "socket() failed: %d\n", WSAGetLastError());
        return INVALID_SOCKET;
    }

    /* Dual-stack: accept both v4 (mapped) and v6 peers on one socket, same
     * as wg_core.c's udp_open_unconnected() when no address family is
     * pinned by the config. */
    DWORD v6only = 0;
    setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&v6only, sizeof(v6only));

    struct sockaddr_in6 sin6;
    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_addr = in6addr_any;
    sin6.sin6_port = htons(listen_port);

    if (bind(s, (struct sockaddr *)&sin6, sizeof(sin6)) != 0) {
        fprintf(stderr, "bind() failed: %d\n", WSAGetLastError());
        closesocket(s);
        return INVALID_SOCKET;
    }

    /* WSAEventSelect also switches the socket to non-blocking mode, which
     * is what lets the recv-until-WSAEWOULDBLOCK drain loop below work. */
    if (WSAEventSelect(s, udp_event, FD_READ) != 0) {
        fprintf(stderr, "WSAEventSelect() failed: %d\n", WSAGetLastError());
        closesocket(s);
        return INVALID_SOCKET;
    }

    return s;
}

/* ── Event loop ──────────────────────────────────────────────────────────── */

static void
drain_tun(wg_win_ctx *ctx)
{
    for (;;) {
        DWORD pkt_size;
        BYTE *pkt = WintunReceivePacket(ctx->tun_session, &pkt_size);
        if (!pkt) {
            DWORD err = GetLastError();
            if (err != ERROR_NO_MORE_ITEMS)
                fprintf(stderr, "WintunReceivePacket error: %lu\n", (unsigned long)err);
            return;
        }
        wg_session_handle_tun(ctx->sess, pkt, pkt_size);
        WintunReleaseReceivePacket(ctx->tun_session, pkt);
    }
}

static void
drain_udp(wg_win_ctx *ctx)
{
    uint8_t buf[2048];
    for (;;) {
        struct sockaddr_storage from;
        int from_len = sizeof(from);
        int n = recvfrom(ctx->udp_sock, (char *)buf, sizeof(buf), 0,
                          (struct sockaddr *)&from, &from_len);
        if (n < 0) {
            int err = WSAGetLastError();
            if (err != WSAEWOULDBLOCK)
                fprintf(stderr, "recvfrom() error: %d\n", err);
            return;
        }
        wg_session_handle_udp(ctx->sess, buf, (size_t)n,
                              (struct sockaddr *)&from, from_len);
    }
}

static void
run_event_loop(wg_win_ctx *ctx, HANDLE tun_read_event, HANDLE udp_event)
{
    HANDLE events[3] = { tun_read_event, udp_event, g_quit_event };

    wg_session_kick(ctx->sess);

    for (;;) {
        DWORD rc = WaitForMultipleObjects(3, events, FALSE, 1000);
        switch (rc) {
        case WAIT_OBJECT_0:
            drain_tun(ctx);
            break;
        case WAIT_OBJECT_0 + 1:
            drain_udp(ctx);
            break;
        case WAIT_OBJECT_0 + 2:
            fprintf(stderr, "shutting down\n");
            return;
        case WAIT_TIMEOUT:
            wg_session_tick(ctx->sess);
            break;
        default:
            fprintf(stderr, "WaitForMultipleObjects failed: %lu\n",
                (unsigned long)GetLastError());
            return;
        }
    }
}

/* ── main ─────────────────────────────────────────────────────────────────── */

static char *
read_file(const char *path, size_t *len_out)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = (char *)malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    *len_out = n;
    return buf;
}

int
main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <wg-quick-config-file>\n", argv[0]);
        return 1;
    }

    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    if (wintun_load() != 0)
        return 1;

    size_t config_len;
    char *config_text = read_file(argv[1], &config_len);
    if (!config_text) {
        fprintf(stderr, "could not read config file: %s\n", argv[1]);
        return 1;
    }

    wg_win_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    wg_session_callbacks cb;
    cb.send_udp   = cb_send_udp;
    cb.deliver_ip = cb_deliver_ip;
    cb.log_line   = cb_log;
    cb.user_ctx   = &ctx;

    ctx.sess = wg_session_create(config_text, config_len, cb);
    free(config_text);
    if (!ctx.sess) {
        fprintf(stderr, "wg_session_create failed (bad config?)\n");
        return 1;
    }

    ctx.adapter = WintunCreateAdapter(L"wgwin0", L"WireGuard", NULL);
    if (!ctx.adapter) {
        fprintf(stderr, "WintunCreateAdapter failed: %lu "
            "(are you running elevated?)\n", (unsigned long)GetLastError());
        wg_session_destroy(ctx.sess);
        return 1;
    }

    ctx.tun_session = WintunStartSession(ctx.adapter, 0x400000 /* 4 MiB ring */);
    if (!ctx.tun_session) {
        fprintf(stderr, "WintunStartSession failed: %lu\n",
            (unsigned long)GetLastError());
        WintunCloseAdapter(ctx.adapter);
        wg_session_destroy(ctx.sess);
        return 1;
    }

    configure_interface(&ctx);

    g_quit_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

    WSAEVENT udp_event = WSACreateEvent();
    ctx.udp_sock = open_udp_socket(wg_session_listen_port(ctx.sess), udp_event);
    if (ctx.udp_sock == INVALID_SOCKET) {
        WintunEndSession(ctx.tun_session);
        WintunCloseAdapter(ctx.adapter);
        wg_session_destroy(ctx.sess);
        return 1;
    }

    HANDLE tun_read_event = WintunGetReadWaitEvent(ctx.tun_session);

    fprintf(stderr, "wg_windows_tun: tunnel up, entering event loop\n");
    run_event_loop(&ctx, tun_read_event, (HANDLE)udp_event);

    closesocket(ctx.udp_sock);
    WSACloseEvent(udp_event);
    WintunEndSession(ctx.tun_session);
    WintunCloseAdapter(ctx.adapter);
    wg_session_destroy(ctx.sess);
    WSACleanup();
    return 0;
}
