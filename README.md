# PasarGuard Route & Zero-Downtime WARP Manager

Automatically manages Xray user routing rules from PasarGuard user notes **and** keeps Cloudflare WARP outbounds (`warp1`, `warp2`, `warp3`, `warp4`, ...) stable with **zero-downtime live refreshes** — running **100% on the Main PasarGuard Panel VPS** with **zero scripts on remote nodes** and **zero central proxy servers**.

---

## Key Features

- **100% Panel-Side Only**: Installs only on the Main PasarGuard Panel VPS. Remote nodes stay vanilla `PasarGuard/node` and exit directly to local Cloudflare WARP Anycast edges.
- **Zero-Downtime Live WARP Refresh & Auto-Healing**: Refreshes wedged `wireguard` or `masque` WARP outbounds **without restarting Xray** and **without disconnecting other active users** (`direct`, `warp1`, `warp3`, `warp4`, etc.).
- **Instant Sub-Second Failover (`pg-ha-*` & `warp-pool`)**: Configures Xray `Observatory` + per-slot High-Availability balancers so if `warp2` stalls mid-poll, Xray fails over new streams to a healthy sibling WARP tunnel automatically before the daemon even polls.
- **Generation Reuse**: Before spawning a new outbound, checks if a previously retired tunnel has recovered on Cloudflare's edge and switches back via `ReplaceRouting` with zero new outbounds added.
- **Note-Based User Routing**: Add `node:sg out:warp1` or `node:sg out:warp-pool` to any user's note in PasarGuard Panel; rules merge automatically and clean up when users are deleted.

---

## How Zero-Downtime WARP Refresh Works

Editing or deleting an existing `wireguard` or `masque` outbound in Xray forces `PasarGuard/node` to restart the entire Xray process (dropping all active users). However, `PasarGuard/node`'s live-diff planner (`planLiveUpdate`) applies **appended outbounds** (`AddOutbound`) and **updated routing rules/balancers** (`ReplaceRouting`) **100% live over gRPC (`ApplyConfigLive`) with zero Xray restart**:

1. **Telemetry via Panel API**: Polls `GET /api/node/{id}/outbounds_latency` on the Panel to read Xray `Observatory` health across every connected node.
2. **Tunnel Hardening**: Sets `mtu: 1280`, `keepAlive: 20`, and diversifies Cloudflare Anycast IPv4:port endpoints (`162.159.192.x`–`188.114.99.x` across ports `2408`, `500`, `1701`, `4500`) so a single throttled Cloudflare edge never takes down all `warp*` slots at once.
3. **Live Generation Swap (`warp2` -> `warp2__r0001`)**: When `warp2` fails `fail_threshold` checks (or when you run `pg-route-manager --refresh warp2`), the manager clones `warp2` into `warp2__r0001` with a fresh Cloudflare Anycast endpoint, appends it to `outbounds`, and repoints `pg-ha-warp2` and `warp-pool` via `PUT /api/core/{id}?restart_nodes=true`.
4. **Live Safety Validator**: Mirrors PasarGuard's `only_live_parts_changed` and `planLiveUpdate` checks locally before every push — mathematically guaranteeing live updates never trigger an Xray restart.

---

## Installation

Run on your **Main PasarGuard Panel VPS**:

```bash
git clone https://github.com/Lordgrim77/PG-ADDON.git
cd PG-ADDON
chmod +x install.sh
sudo ./install.sh
```

### One-Time WARP HA & Observatory Optimization

After installation, run `--optimize-warp` once (during a brief maintenance moment) to inject `ObservatoryService`, configure static-prefix concurrent `observatory` probing, harden `mtu=1280` / `keepAlive=20`, diversify Cloudflare Anycast endpoints, and create `pg-ha-*` + `warp-pool` balancers:

```bash
# 1. Preview changes without applying
sudo pg-route-manager --optimize-warp --dry-run

# 2. Apply one-time optimization
sudo pg-route-manager --optimize-warp
```

After this one-time setup, **all future automatic heals and manual `--refresh` operations happen 100% live via gRPC with zero Xray restarts**.

---

## User Note Directives

In the PasarGuard Panel user **Note** field:

```text
# Pin user to warp1 (automatically protected by pg-ha-warp1 failover)
node:sg out:warp1

# Load-balance user across all healthy warp* tunnels by lowest ping
node:sg out:warp-pool

# Route across multiple nodes
node:sg out:warp1 | node:us out:direct
```

---

## CLI Usage

```bash
# View live WARP outbound health, endpoints, and latencies across all nodes
sudo pg-route-manager --status

# Zero-downtime live refresh of a specific WARP slot (0 user disconnects!)
sudo pg-route-manager --refresh warp2

# Zero-downtime live refresh of all WARP slots
sudo pg-route-manager --refresh all

# Force spawning a brand-new Anycast endpoint even if an older generation recovered
sudo pg-route-manager --refresh warp2 --force-spawn

# Preview a sync or refresh without touching the Panel
sudo pg-route-manager --refresh warp2 --dry-run

# Maintenance cleanup: collapse retired *__rNNNN outbounds back into clean warp1..N tags
# (Note: removing wireguard/masque outbounds triggers a brief Xray reload; run during off-peak)
sudo pg-route-manager --compact
```

---

## Configuration Reference (`/etc/pasarguard-route-manager/config.json`)

| Key | Default | Description |
| :--- | :--- | :--- |
| `panel_url` | `""` | PasarGuard Panel URL (e.g. `https://panel.example.com:8000`, no `/dashboard`) |
| `username` | `""` | Panel admin username |
| `password` | `""` | Panel admin password |
| `poll_interval` | `60` | Seconds between daemon sync & WARP health checks |
| `verify_ssl` | `true` | Verify Panel TLS certificate (`false` for self-signed / IP URLs) |
| `warp_prefix` | `"warp"` | Prefix matching managed WARP outbounds (`warp1`, `warp2`, ...) |
| `auto_heal_warp` | `true` | Automatically live-refresh wedged WARP slots when Observatory reports failure |
| `fail_threshold` | `2` | Consecutive failed poll cycles before triggering a live WARP rotation |
| `refresh_cooldown` | `180` | Minimum seconds between live rotations of the same WARP slot |
| `max_latency_ms` | `0` | Optional latency ceiling in ms (`0` = disabled; e.g. `2500` rotates severely stalled tunnels) |
| `use_ha_balancers` | `true` | Route `out:warpN` through `pg-ha-warpN` with instant sibling failover + `warp-pool` |
| `fallback_mode` | `"warp"` | Failover target when a slot dies: `"warp"` (healthy sibling WARP) or `"direct"` |
| `max_live_generations` | `12` | Cap on retired `*__rNNNN` outbounds per slot between `--compact` runs |
| `compact_window` | `""` | Optional daily off-peak compaction window `"HH:MM-HH:MM"` (`""` = manual `--compact` only) |

Reload configuration without restarting the service:

```bash
sudo systemctl reload pasarguard-route-manager
```

---

## License

MIT
