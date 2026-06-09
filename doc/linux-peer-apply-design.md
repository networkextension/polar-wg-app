# Design — applying peer public keys on a Linux WireGuard node

Status: design / 2026-06-09
Scope: how a **Linux** mesh member (hub or spoke) gets peer public keys
into its kernel WireGuard interface, and keeps them current as the roster
changes. macOS already solves this with `wgctl-agent.sh` + the wg-mac NE;
this doc picks the Linux equivalent.

## Problem

A Linux box registers via `POST /v1/register` and gets back a peer list
(`{pubkey, endpoint, wg_ip, allowed_extra}[]`). Those public keys have to
land in the kernel (`wg set` / a `.conf` + `wg-quick`), and — because the
mesh roster changes as devices join/leave/rotate — they have to be
**refreshed** on a cadence, not just once at join.

Today the macOS path does this with a launchd-driven reconciler
(`wgctl-agent.sh`): heartbeat → `GET /v1/peers` (or `/v1/hub/peers` for a
hub) → re-render conf → reload. **There is no shipped Linux equivalent that
is hub-aware**, which is why a Linux *hub* never learns its spokes' keys.

## What already exists (and the one bug)

`scripts/join-linux.sh` already implements most of "option 2":

- generates a keypair, `POST /v1/register`, writes `/etc/wgctl/<iface>.json`
  (incl. `role`) + an initial `/etc/wireguard/<iface>.conf`;
- `systemctl enable --now wg-quick@<iface>` to bring the link up;
- lays down two helpers and a timer:
  - `/usr/local/sbin/wgctl-render-linux <iface>` — render conf from a
    `/register|/peers` JSON body (writes every `[Peer] PublicKey`);
  - `/usr/local/sbin/wgctl-refresh-linux <iface>` — poll peers, re-render,
    and **`wg syncconf <iface> <(wg-quick strip <iface>)`** → hot-apply the
    new/removed pubkeys with **no interface flap**;
  - `wgctl-refresh@<iface>.timer` (systemd) fires it every `refresh_sec`.

`wg syncconf` IS the incremental "add/remove peer pubkey" primitive on
Linux — equivalent to what the macOS NE does on conf change.

**Bug (blocks Linux hubs):** `wgctl-refresh-linux` hardcodes
`"$SERVER/v1/peers"`. A hub must call `"$SERVER/v1/hub/peers"`. The `role`
is already persisted in the state file (`join-linux.sh` writes
`"role": resp.get("role","device")`), so the fix is a 3-line branch — the
same one `wgctl-agent.sh` already has on macOS:

```bash
case "$(read_field role)" in
  hub) PEER_URL="$SERVER/v1/hub/peers" ;;
  *)   PEER_URL="$SERVER/v1/peers" ;;
esac
```

The initial-join conf is fine (it renders from the `/register` response,
which already contains the right peer set for the role). Only the *refresh*
loop polls the wrong endpoint, so a hub comes up correct, then on the first
refresh tick re-renders from a device-scoped `/v1/peers` and loses the mesh.

> Note: the `join-linux2.sh` run on the VM is **not** this script — it's a
> hand-rolled variant. Step 0 of any rollout is to replace it with the
> repo's `join-linux.sh` (+ the hub fix) so the refresh timer actually
> exists.

## The three options

### Option 1 — 人肉 (manual peer entry)

Platform already shows every device's `pubkey / wg_ip / endpoint` (admin
`/wg-tokens.html` Hubs/Devices). Operator hand-writes `[Peer]` blocks into
the hub's `/etc/wireguard/wgc0.conf` and `wg syncconf` (or `wg set wgc0
peer <pub> allowed-ips <ip>/32 endpoint <ep>`).

- **Pros:** zero new code; unblocks the one stuck hub *today*; full control.
- **Cons:** O(n²) human work; no auto-add on new join; no auto-remove on
  revoke; drifts the moment anything rotates. A stopgap, not a system.
- **Use when:** you need the 124.221.22.9 hub talking to ≤3 known peers in
  the next 10 minutes.

### Option 2 — wg-agent like mac (systemd refresh agent) ★ recommended

Ship the repo's `join-linux.sh` path + the hub-role fix. Each Linux node
runs a `wgctl-refresh@<iface>.timer` that polls the right endpoint and
`wg syncconf`s the kernel — self-contained, no dock dependency, mirrors the
proven macOS design 1:1.

- **Pros:** ~90% already written + tested in this repo; kernel WireGuard
  (fast, no userspace `wg_core`); hub + spoke from one script; self-evict on
  401; hot reload (no flap); same control-plane protocol as macOS/iOS.
- **Cons:** bespoke systemd units live outside the polar-agent fleet view
  (separate "is it alive" signal); pubkey churn bounded by `refresh_sec`
  latency (fine — default 300s, tunable).
- **Work:**
  1. fix `wgctl-refresh-linux` role branch (`/v1/hub/peers` for hubs);
  2. make `wgctl-agent.sh`'s peer-status heartbeat reusable on Linux **or**
     add a tiny `POST /v1/heartbeat` to the refresh helper so the hub shows
     "online" + per-peer roster in admin (today only macOS heartbeats);
  3. fold `join-linux.sh` into the served bundle / a `/v1/install-linux`
     so operators get it the same way as macOS;
  4. doc + a 2-hub live smoke (hub learns spoke pubkey via syncconf).

### Option 3 — polar-agent with sudo (unified fleet agent)

Install `polar-agent` on the Linux box (it already dials dock over WS, has
a WireGuard skill, and reports `wg_pubkey` on hello). Add a new **mesh mode**
to the skill: instead of an operator-pushed static conf, the agent polls the
wg control plane (`/v1/hub/peers`) and `wg syncconf`s — i.e. move option 2's
loop *into* polar-agent.

- **Pros:** one agent for the whole host (WG + shell + VNC + telemetry +
  host-info crosslink, all already there); dock already manages its
  lifecycle, online state, and `host_id↔wg_pubkey` link; operator installs
  one thing; revoke/rotate can ride the existing WS control channel
  (push, not poll).
- **Cons:** most code to write (new skill mode + a dock/wg bridge so the
  agent can reach `/v1/hub/peers` with a wg device token, or a new
  dock→wg internal proxy); couples WG uptime to polar-agent uptime; needs
  `sudoers` for `wg`/`wg-quick` (the skill's `wireguard_priv.go` already
  detects + surfaces this). Today the skill is operator-conf-driven and
  does **not** poll the control plane — that's the gap to close.
- **Use when:** WG management should become part of fleet management (many
  hosts, central revoke/rotate, one pane of glass). This is the strategic
  end-state, not the fast fix.

## Recommendation

Sequence them — they're not mutually exclusive:

1. **Now (unblock):** Option 1 on the 124.221.22.9 hub — hand-add the known
   spoke pubkey(s) so the mesh forms today.
2. **This week (the system):** Option 2 — fix the hub-role branch, ship
   `join-linux.sh` as the official Linux installer, add the hub heartbeat,
   live-smoke a 2-hub mesh. This is the right amount of engineering for a
   handful of hubs and reuses proven code.
3. **Later (when fleet scale demands it):** Option 3 — fold the peer-refresh
   loop into polar-agent so WG joins the unified host fleet (central
   revoke/rotate over WS, one agent, one online signal). Revisit once
   there are enough Linux nodes that bespoke systemd timers are a burden.

Option 2 is the recommended primary because the code already exists, it's
hub+spoke symmetric, and it keeps WG self-contained (a WG node staying up
must not depend on the host-management agent being healthy). Option 3 is a
deliberate later consolidation, not a prerequisite.

## Cross-refs
- `scripts/wgctl-agent.sh` — macOS reconciler (the role-branch reference).
- `scripts/join-linux.sh` — the Linux join + refresh helper (option 2 base).
- polar-agent `cmd/polar-agent/skills/wireguard.go` — the conf-driven skill
  (option 3 base) + `wireguard_priv.go` (sudo/root detection).
- `doc/JOIN_PROTOCOL.md` — `/v1/register|peers|hub/peers|heartbeat|leave`.
- Known issue: hub→spoke NAT hairpin (separate from key-apply) — peers can
  be *configured* yet still unreachable behind NAT; see the WG NAT memo.
