/* SPDX-License-Identifier: MIT
 *
 * wg_session: I/O-agnostic WireGuard session library.
 *
 * This header is the public C API that the Swift PacketTunnelProvider
 * talks to. The design constraint is that the NetworkExtension process
 * owns all I/O (NEPacketTunnelFlow for the tunnel interface, NWUDPSession
 * for outer UDP, Dispatch timers for rekey), so this library must not
 * open sockets, must not read utun, must not call select, and must not
 * touch the clock except via the explicit tick() entry point.
 *
 * Everything the session wants to "do" goes through callbacks:
 *
 *   .send_udp  — here are outer UDP bytes, please write them to the peer
 *   .deliver_ip — here is a freshly decrypted inner IP packet, please
 *                 hand it to packetFlow.writePackets
 *   .log_line  — text log line, please emit to os_log
 *
 * Everything the session wants to "know" comes in through explicit calls:
 *
 *   wg_session_handle_udp(bytes, from)  — called when Swift reads from NWUDPSession
 *   wg_session_handle_tun(bytes)         — called when Swift reads from packetFlow
 *   wg_session_tick()                    — called ~1/sec from a Dispatch timer
 *
 * The header is pure C with fixed-layout types so clang -fmodules can
 * emit a clean Swift module from it. Do not add C++-only constructs,
 * designated initializers for the callback struct (we want POD), or
 * variadic types here.
 */
#ifndef _WG_SESSION_H
#define _WG_SESSION_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handle. Lifetime is owned by the Swift caller. */
struct wg_session;
typedef struct wg_session wg_session_t;

/* Callback function types. All callbacks are synchronous — the session
 * invokes them from inside a wg_session_handle_* or wg_session_tick call
 * and expects them to complete before returning. Swift implementations
 * should keep them cheap; if they block, the session loop stalls. */
typedef void (*wg_send_udp_fn)(
    void *user_ctx,
    const uint8_t *bytes, size_t len,
    const struct sockaddr *to, socklen_t to_len);

typedef void (*wg_deliver_ip_fn)(
    void *user_ctx,
    const uint8_t *bytes, size_t len);

typedef void (*wg_log_fn)(
    void *user_ctx,
    const char *msg);

typedef struct {
    wg_send_udp_fn   send_udp;
    wg_deliver_ip_fn deliver_ip;
    wg_log_fn        log_line;   /* nullable; NULL → stderr fallback */
    void            *user_ctx;   /* passed back to every callback */
} wg_session_callbacks;

/* ─────────────────────────────────────────────────────────────────────────
 * Lifecycle
 * ───────────────────────────────────────────────────────────────────────── */

/* Parse an INI-style wg-quick config and construct a new session with
 * the given callbacks installed. Returns NULL on config error or OOM.
 * The config text does not need to be NUL-terminated if config_len > 0.
 * Passing config_len = 0 means "config_text is a C string". */
wg_session_t *wg_session_create(const char *config_text, size_t config_len,
                                wg_session_callbacks cb);

void wg_session_destroy(wg_session_t *s);

/* ─────────────────────────────────────────────────────────────────────────
 * Inbound data plane
 * ───────────────────────────────────────────────────────────────────────── */

/* An outer UDP datagram has arrived (from NWUDPSession). Dispatches by
 * WireGuard message type: data → decrypt + deliver_ip callback; handshake
 * init/response/cookie → noise state machine. Zero-copy where possible.
 *
 * Returns 0 if the packet was understood (even if intentionally dropped,
 * e.g. anti-spoofing), -1 if it was malformed enough to log at error level. */
int wg_session_handle_udp(wg_session_t *s,
                          const uint8_t *bytes, size_t len,
                          const struct sockaddr *from, socklen_t from_len);

/* An inner IP packet has arrived from packetFlow.readPackets (or any
 * other L3 source on the Swift side). The session looks up the
 * destination in its allowedips trie to pick a peer, encrypts, and
 * invokes send_udp with the resulting outer datagram.
 *
 * Returns 0 on success (send_udp was called), -1 if no peer owns the
 * destination or the current keypair is not usable. */
int wg_session_handle_tun(wg_session_t *s,
                          const uint8_t *bytes, size_t len);

/* ─────────────────────────────────────────────────────────────────────────
 * Timers
 * ───────────────────────────────────────────────────────────────────────── */

/* Drive the handshake-retransmit, proactive-rekey, and persistent-
 * keepalive timers. Swift should call this every ~1 s from a Dispatch
 * source. The session will call send_udp synchronously from here for
 * any initiation / keepalive that needs to go out. */
void wg_session_tick(wg_session_t *s);

/* Force a handshake initiation to the first peer with an endpoint.
 * Useful on tunnel startup so the caller doesn't have to wait for the
 * first tick. Returns 0 if an initiation was sent, -1 otherwise. */
int wg_session_kick(wg_session_t *s);

/* ─────────────────────────────────────────────────────────────────────────
 * Introspection (for Swift to set up NEPacketTunnelNetworkSettings)
 * ───────────────────────────────────────────────────────────────────────── */

/* Number of [Interface] Address entries parsed from the config. */
int wg_session_iface_addr_count(const wg_session_t *s);

/* Fill *addr_out with the i'th Interface Address. Family is AF_INET or
 * AF_INET6. addr_out must have room for at least 64 chars including NUL.
 * Returns 0 on success, -1 if i is out of range. */
int wg_session_iface_addr_get(const wg_session_t *s, int i,
                              char *addr_out,
                              int *prefix_out,
                              int *family_out);

/* Number of peers. */
int wg_session_peer_count(const wg_session_t *s);

/* Fill *pubkey_out (must be 32 bytes) with the i'th peer's static
 * public key. Returns 0 on success, -1 if out of range. */
int wg_session_peer_pubkey(const wg_session_t *s, int i,
                           uint8_t *pubkey_out);

/* Number of AllowedIPs CIDRs on peer i. */
int wg_session_peer_allowed_count(const wg_session_t *s, int i);

/* Fill *addr_out (at least 64 bytes) and *prefix_out with the j'th
 * AllowedIPs CIDR of peer i. Returns 0 on success. */
int wg_session_peer_allowed_get(const wg_session_t *s, int i, int j,
                                char *addr_out,
                                int *prefix_out,
                                int *family_out);

/* Format a multi-line wg(8)-style status string into buf. Returns the
 * number of bytes that would be written (may exceed buf_len if the
 * buffer was too small, like snprintf). */
int wg_session_status(const wg_session_t *s, char *buf, size_t buf_len);

#ifdef __cplusplus
}
#endif

#endif /* _WG_SESSION_H */
