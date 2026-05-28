# Hub Status — client status upload

> Design doc. **Client-side is implemented** (macOS `wgctl-agent`, the native
> Linux/FreeBSD `wg-agent`, and — reduced — the mobile apps). The server-side
> storage + admin UI sketch here is for the Polar repo
> (`/Users/apple/github/Polar-`) and is **not** part of this repo's scope.

## Problem

Today `POST /v1/heartbeat` only carries enough to drive the admin "last seen"
column:

```json
{ "lan_addrs": [...], "wg_endpoint": "203.0.113.7:1632",
  "stats": { "rx_bytes": 0, "tx_bytes": 0, "last_handshake_sec": 0 } }
```

That tells you a device *checked in*, not whether its tunnel is actually
passing traffic, nor — for a multi-spoke mesh — which spokes the hub can
really see. The `/32`-routing class of bug (handshake fine, no traffic) is
invisible from the control plane.

## Goal

1. Every node uploads a richer **`status`** block on its existing 60 s
   heartbeat — no new endpoint, no new cadence.
2. The **hub's** `status.peers[]` is the authoritative mesh roster: the hub's
   kernel handshake table is ground truth for "who is online", because a
   sleeping/NATed spoke can stop self-reporting while the hub still knows its
   last-handshake age.
3. Backward/forward compatible: old servers ignore `status`; old clients send
   none and still drive `last_seen`.

## Wire format (heartbeat v2)

Reuse `POST /v1/heartbeat` (auth unchanged: `Authorization: Bearer <device-token>`
+ `X-Device-Id`). The legacy fields stay **verbatim**; `status` is additive.

```json
{
  "lan_addrs":   [{ "iface": "en0", "cidr": "192.168.1.5/24" }],
  "wg_endpoint": "203.0.113.7:1632",
  "stats":       { "rx_bytes": 90000, "tx_bytes": 80000, "last_handshake_sec": 11 },

  "status": {
    "schema":       1,
    "role":         "device",            // "device" | "hub"
    "os":           "darwin",            // darwin | linux | freebsd | ios | android
    "arch":         "arm64",
    "agent_ver":    "20260526-routes",
    "iface":        "wgc0",
    "iface_up":     true,
    "uptime_sec":   484212,              // host uptime, null if unknown
    "wg_listen":    1632,
    "peer_count":   3,
    "peers_online": 2,
    "peers": [
      { "pubkey":   "abc…=",
        "wg_ip":    "10.88.0.1",
        "endpoint": "198.51.100.9:1632",
        "last_handshake_sec": 11,        // null = never handshook
        "rx_bytes": 9000,
        "tx_bytes": 8000,
        "online":   true }
    ]
  }
}
```

`stats` is now the aggregate (sum of `rx_bytes`/`tx_bytes`, *min* handshake age
across peers) so the existing admin column keeps working for hubs too.

### Online definition

```
online := last_handshake_sec != null && last_handshake_sec < 180
```

180 s = ~7× the 25 s `PersistentKeepalive`; a healthy peer handshakes well
inside that window.

## Hub status = the hub's view

A **hub** is the one device whose `[Peer]` table is the whole mesh (it polls
`/v1/hub/peers`, role `hub`). So its `status.peers[]` *is* the mesh roster as
the central node actually sees it. The server keys those entries by `pubkey`
and joins to `wg_devices` to produce the **Hub Status** view:

| Column | Source |
|---|---|
| device / hostname | `wg_devices` (by pubkey) |
| online (hub view) | hub's `status.peers[].online` |
| last handshake (hub view) | hub's `status.peers[].last_handshake_sec` |
| throughput (hub view) | hub's `status.peers[].rx/tx_bytes` |
| last self-heartbeat | that device's own `last_status_at` |

The two columns disagreeing (self says up, hub says stale) is exactly the
signal you want — a spoke that thinks it's connected but the hub can't reach.

## Server side (Polar repo — design only)

- **Storage**: add `wg_devices.last_status_json` (JSON/JSONB) + `last_status_at`
  timestamp, written by the existing heartbeat handler. Latest-wins; no history
  table needed for v1.
- **Handler**: `internal/app/dock/wg_handlers.go` heartbeat handler — if
  `status` present, persist it; if absent, behave exactly as today. Reject
  nothing on shape (forward-compat).
- **Admin UI** (`/wg-tokens.html`): per-row online dot driven by the bound
  hub's view; a "Hub Status" panel that renders the hub device's
  `status.peers[]`. Optional read API: `GET /api/admin/wg-hubs/:id/status`
  returning the cached roster.
- **No new public endpoint.** Heartbeat is the carrier.

## Cost & limits

`peers[]` is bounded by mesh size; piggybacks the 60 s tick, so no extra
requests. For large meshes a future rev/etag can let the hub send only changed
peers — out of scope for v1.

## Client coverage

| Client | Builds `status` from | Notes |
|---|---|---|
| macOS `wgctl-agent` | `wgctl show <iface>` | full per-peer roster, uptime via `kern.boottime` |
| Linux/FreeBSD `wg-agent` | `wg show <iface> dump` | full per-peer roster, uptime via `/proc/uptime` / `kern.boottime` |
| iOS / Android app | extension stats | reduced (single peer, no host uptime) — optional |

See `scripts/wgctl-agent.sh` and the skill's `scripts/wg-agent.sh` for the two
daemon implementations.
