# wg-mac troubleshooting — symptom → root cause → fix

Map the JSON from `scripts/diagnose.sh` (and register errors from
`scripts/join.sh`) to a remedy. All commands run as root.

## Quick map from diagnose.sh JSON

| JSON signal | Root cause | Fix |
|---|---|---|
| `address_prefix: 32` (handshake fine, `mesh_route:false`, `ping_hub:fail`) | `/32` Interface address → `wg_core` installs no mesh route (`utun_apply_inet4` only routes when `prefix < 32`) | set conf `Address` to `…/24`, restart (below) |
| `handshake_age_s: null` + register was ok | hub UDP path unreachable: wrong port, carrier/NAT blocks UDP, or port taken | check `listen_port_owner`; off hotspot → real wifi; verify hub UDP 1632 |
| `listen_port_owner: >1` or stray `wg_core_procs` | competing instances (churn from repeated up/down) — route points at one utun, socket on another | clean-reset (below) |
| `mesh_route: false` but `address_prefix: 24` | route not (re)installed | `wgctl down $IFACE && wgctl up $IFACE` |
| `ping_hub: fail` but `handshake_age_s` small + `mesh_route: true` | hub drops ICMP, or you're pinging a NAT'd spoke not the hub | ping the **hub** `10.88.0.1`, not another spoke |

## Register errors from join.sh

| status | meaning | fix |
|---|---|---|
| `control_plane_unreachable` | hit `:443` not `:2443`, or server down | use `--server=https://wg.4950.store:2443` |
| `token_already_bound` (409) | device already registered (DB intact) | already joined, or add `--reinstall` |
| `pubkey_taken` (409) | same host re-joining with a new key | `wgctl down $IFACE`, then retry |
| `server_error` (500) | server-side error | re-run register **without `-f`**: `curl -sS -X POST "$SERVER/v1/register" -d "$REGISTER_BODY"` → read `{"error":"register failed: …"}`; fix on the dock |
| `wrong_token_kind` | `tskey-` token | stock Tailscale path, not wg-mac |

## Fix recipes

### A. `/32` → `/24` (the silent killer)

```bash
sudo sed -i '' -E 's#^([[:space:]]*Address[[:space:]]*=[[:space:]]*[0-9.]+)/32#\1/24#' /etc/wireguard/wgc0.conf
sudo wgctl down wgc0; sudo wgctl up wgc0
netstat -rn | grep 10.88            # expect 10.88.0.0/24 -> utun
ping -c3 10.88.0.1
```

### B. Clean-reset competing instances

```bash
sudo launchctl bootout system/com.wireguard.wgctl-agent      2>/dev/null
sudo launchctl bootout system/com.wireguard.wg-mac.wgc0      2>/dev/null
sudo wgctl down wgc0 2>/dev/null
sudo pkill -f wg_core; sleep 1; sudo pkill -9 -f wg_core; sleep 1
sudo rm -f /var/run/wireguard/wgc0.*
for i in 1 2 3; do sudo route -q -n delete -net 10.88.0.0/24 >/dev/null 2>&1; done
sudo launchctl bootstrap system /Library/LaunchDaemons/com.wireguard.wg-mac.wgc0.plist
sudo launchctl kickstart -k system/com.wireguard.wg-mac.wgc0
sleep 8; sudo wgctl show wgc0 | grep -E 'handshake|transfer'
sudo launchctl bootstrap system /Library/LaunchDaemons/com.wireguard.wgctl-agent.plist
```

### C. Free a port squatted by a stale tunnel

```bash
sudo lsof -nP -iUDP:1632
sudo launchctl bootout system/com.wireguard.wg-mac.wg0 2>/dev/null
sudo wgctl down wg0 2>/dev/null
```

## Notes

- The hub WireGuard endpoint may still be advertised as `zen.4950.store:1632`;
  that's fine — it resolves to the same IP as `wg.4950.store`. Only the HTTPS
  *control plane* requires `:2443`.
- WireGuard has no relay; two devices both behind NAT reach each other only via
  the hub. For direct/relayed connectivity use the Tailscale path
  (`tailscale up --login-server=…`).
