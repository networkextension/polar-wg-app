---
name: wg-mac-install
description: Join the Polar WireGuard mesh on macOS, Linux, or FreeBSD from a polar_wg_ token (auto-registers — no manual server steps), or repair a tunnel that "can't reach the remote / hub". Use whenever the user wants to "install wg-mac", "join the mesh", "连入 mesh", onboard a Mac / Linux box / FreeBSD host to the Polar VPN, or fix a wg tunnel showing no handshake, no peers, or 100% ping loss. Knows the control plane is at https://wg.4950.store:2443 (NOT :443), the WireGuard listen port is 1632, the interface Address must use the /24 mesh prefix (a /32 silently breaks routing even with a healthy handshake), that macOS uses the bundled wg_core+launchd while Linux/FreeBSD use native kernel WireGuard via wg-quick (systemd timer or cron), that tskey- tokens belong to stock Tailscale (not wg-mac), and the classic port-collision / wrong-port / competing-instance failures. Pick this skill for any wg-mac onboarding or "my mesh tunnel won't connect" request.
---

# wg-mac — Install / Join Mesh

End-to-end: take a Polar join token, install the WireGuard data plane, register
with the control plane, bring the tunnel up, schedule the reconciler, and prove
it reaches the hub. Plus a diagnose-and-repair path for tunnels that are up but
not passing traffic.

**`scripts/join.sh` auto-detects the OS** and picks the right data plane:

| OS | Data plane | Brought up by | Reconciler |
|---|---|---|---|
| macOS | bundled `wg_core` + `wgctl` (pulled from `/v1/bundle`) | launchd | `wgctl-agent` (StartInterval 60) |
| Linux | native kernel WireGuard + `wg-quick` (auto-installs `wireguard-tools`) | `systemctl wg-quick@<iface>` (or `wg-quick up`) | `wg-agent` via systemd timer or cron |
| FreeBSD | native `if_wg` + `wg-quick` (auto-installs `wireguard-tools`) | `wg-quick up` + `rc.conf` | `wg-agent` via cron |

Registration is automatic on every platform — the operator only supplies the
`polar_wg_` token. The two scripts each emit a single JSON object on stdout
(progress on stderr), so you can capture and branch on the result.

## Decision flow

```
classify token (polar_wg_ vs tskey-)
        ↓ polar_wg_
scripts/join.sh      → JSON { status, iface, hub, ... }
        ↓ if status != ok
scripts/diagnose.sh  → JSON { handshake_age_s, address_prefix, mesh_route, ping_hub, ... }
        ↓
references/troubleshooting.md  (map the JSON to a fix)
```

## Step 0: Classify the token — do this first

- Starts with **`tskey-`** → this is a *Tailscale* PreAuthKey, **not** wg-mac. Do
  not run join.sh. Tell the user to use stock Tailscale:
  ```bash
  brew install --cask tailscale
  sudo tailscale up --login-server=https://wg.4950.store:2443 --authkey=<tskey-…>
  ```
  Then stop.
- Starts with **`polar_wg_`** → continue to Step 1.
- Anything else → warn, but you may proceed; the server is the final arbiter.

## Step 1: Install + join

```bash
sudo bash scripts/join.sh --token=polar_wg_<…> [--server=https://wg.4950.store:2443] [--iface=wgc0]
```

Same command on every OS — `join.sh` detects macOS / Linux / FreeBSD and does
the right thing (bundle+launchd on mac; auto-install `wireguard-tools` +
`wg-quick` + systemd-timer/cron on Linux/FreeBSD). On Linux/FreeBSD the script
auto-installs missing deps (`wireguard-tools`, `python3`, `curl`) via the host's
package manager (`apt`/`dnf`/`yum`/`pacman`/`apk`/`zypper`/`pkg`).

Reads the JSON result. `status` is one of:

- `ok` — joined and the hub is reachable. Done.
- `control_plane_unreachable` — the server/port is wrong. It MUST be `:2443`
  (plain `https://wg.4950.store` → 443 → times out).
- `token_already_bound` (409) — this device is already registered; either it's
  already joined, or pass `--reinstall` to re-render from the current peer list.
- `invalid_token` (401) — token bad/expired/revoked (native path surfaces this
  explicitly; re-mint in `/wg-tokens.html`).
- `pubkey_taken` (409) — this pubkey is bound to a different token.
- `wrong_token_kind` — a `tskey-` slipped through; go to Step 0.
- `requires_unmet` — not root, or `wireguard-tools` couldn't be installed
  (install it manually, then re-run).
- `unsupported_os` — not Darwin/Linux/FreeBSD.
- `joined_unverified` — registered, but handshake/route/ping didn't all pass →
  Step 2.
- `join_failed` / `server_error` — read stderr; for a 500, re-run the register
  `curl` **without `-f`** to see `{"error":"register failed: …"}` (server-side).

## Step 2: Diagnose (when not `ok`)

```bash
sudo bash scripts/diagnose.sh [--iface=wgc0]
```

JSON fields and what they mean:

- `handshake_age_s` — seconds since last handshake. `null` = never handshook →
  the hub's UDP path is unreachable (wrong port, carrier/NAT blocks UDP, or the
  port is taken — see `listen_port_owner`).
- `address_prefix` — **must be `24`**. If `32`, `wg_core` installs *no* mesh
  route, so the hub is unroutable even with a perfect handshake. Fix: set the
  conf `Address` to `…/24` and restart.
- `mesh_route` — `true` when `10.88.0.0/24 → utun` exists.
- `listen_port_owner` — how many processes hold UDP 1632. `>1` (or a stray
  `wg0`/dead `wgc0`) = competing instances; clean-reset.
- `ping_hub` — `ok` means fully working.

## Step 3: Fix

Map the diagnose JSON to a remedy using **`references/troubleshooting.md`**
(symptom → root cause → exact commands). The common three:

1. handshake fine + `address_prefix=32` → switch conf to `/24`, `wgctl down/up`.
2. `bind: Address already in use` / multiple instances → bootout the daemon,
   `pkill -f wg_core`, free 1632, bring up exactly one.
3. handshake `never` + `N sent / 0 received` → hub UDP path blocked; off the
   hotspot onto real wifi, or use the Tailscale/DERP path.

## Common pitfalls

- **Port, not host.** The control plane moved to `wg.4950.store:2443`. The
  served `/v1/install` template renders `SERVER` *without* `:2443`, so the bare
  `curl …/v1/install | sudo bash` one-liner fails at bundle download — always
  pass `--server=https://wg.4950.store:2443` (join.sh does this).
- **`/32` is a silent killer.** Handshake succeeds, `transfer 0/0`, ping 100%
  loss. It's routing, not connectivity. Address must be `/24`.
- **Roaming is automatic.** If the host's network changes, the hub rebinds the
  endpoint on the next authenticated packet (keepalive 25 s). The mesh IP
  (`10.88.0.2`) is bound to the pubkey and never changes.
- **Two NAT'd spokes can't reach each other directly** over raw WireGuard — only
  via the hub. Always test against the hub `10.88.0.1` first.
- **Platform data plane differs.** macOS runs the bundled userspace `wg_core`
  (utun) under launchd. Linux/FreeBSD run *native kernel* WireGuard via
  `wg-quick`, so `wg`/`wg show`/`wg-quick` are the tools — `wgctl`/`wg_core`
  don't exist there. On Linux/FreeBSD `wg-quick`'s `Table=auto` installs the
  AllowedIPs routes for you (the `/32` bug is a macOS-only failure mode), but
  the conf still uses the `/24` Address. FreeBSD confs live in
  `/usr/local/etc/wireguard/`, Linux/macOS in `/etc/wireguard/`.
- **Reconciler keeps the mesh fresh + reports status.** macOS `wgctl-agent`
  (launchd) and Linux/FreeBSD `wg-agent` (systemd timer / cron) both heartbeat
  every 60 s with the v2 `status` block (per-peer roster — see
  `doc/hub-status.md`) and re-render the conf when the peer list changes.

## Worked example

```bash
# user pasted: polar_wg_48154507ff61a15f3feec6c30bb938e8
sudo bash scripts/join.sh --token=polar_wg_48154507ff61a15f3feec6c30bb938e8
# → {"status":"ok","iface":"wgc0","hub":"10.88.0.1","detail":"joined wgc0, hub 10.88.0.1 reachable"}

# if instead it returned joined_unverified:
sudo bash scripts/diagnose.sh
# → {"handshake_age_s":4,"address_prefix":32,"mesh_route":false,"ping_hub":"fail",...}
# address_prefix=32 + no route → the /32 bug. Fix per references/troubleshooting.md.
```
