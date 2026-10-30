#!/usr/bin/env python3
"""
PasarGuard Route & WARP Health Manager
======================================
Automatically manages Xray routing rules based on user note directives AND
keeps WARP outbounds (warp1, warp2, warp3, warp4, ...) stable with zero-downtime
live refreshes — 100% from the Main PasarGuard Panel VPS (zero node scripts).

Note Format (in PasarGuard user notes):
    node:sg out:warp1
    node:sg out:warp-pool
    node:sg out:warp1 | node:us out:direct

How it works:
    1. Polls PasarGuard API for all users, nodes, cores, and outbound latencies
    2. Parses notes for routing directives (node:<name> out:<tag>)
    3. Monitors Xray Observatory health via /api/node/{id}/outbounds_latency
    4. Auto-heals or manually refreshes wedged WARP outbounds WITHOUT restarting
       Xray by appending a fresh generation (e.g. warp2__r0001) with a rotated
       Cloudflare Anycast endpoint and live-swapping routing/balancers via
       PasarGuard's ApplyConfigLive (AddOutbound + ReplaceRouting) gRPC path
    5. Reuses previously spawned generations if they recover, avoiding unbounded
       outbound growth; supports manual (--compact) or quiet-window cleanup
    6. Cleans up rules for deleted users or cleared notes

Security:
    - Config file permissions restricted to 600 (owner-only read/write)
    - API token is never logged
    - All inputs are validated and sanitized
    - No shell execution or eval()

Usage:
    python3 route_manager.py                        # Run sync + health check once
    python3 route_manager.py --dry-run              # Preview changes without applying
    python3 route_manager.py --daemon               # Run as daemon, poll on interval
    python3 route_manager.py --interval 30          # Poll every 30 seconds (with --daemon)
    python3 route_manager.py --status               # Show WARP outbound health across nodes
    python3 route_manager.py --refresh warp2        # Zero-downtime live refresh of warp2
    python3 route_manager.py --refresh all          # Zero-downtime live refresh of all warp*
    python3 route_manager.py --optimize-warp        # One-time setup: Observatory + MTU/KeepAlive + HA
    python3 route_manager.py --compact              # Prune retired *__rNNNN outbounds (maintenance)
    python3 route_manager.py --setup                # Interactive first-time setup
"""

import argparse
import copy
import datetime as dt
import getpass
import hashlib
import ipaddress
import json
import logging
import os
import re
import signal
import sys
import time
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
try:
    import httpx
except ImportError:
    print("ERROR: 'httpx' is required. Install it with: pip install httpx")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CONFIG_DIR = Path("/etc/pasarguard-route-manager")
CONFIG_FILE = CONFIG_DIR / "config.json"
STATE_FILE = CONFIG_DIR / "state.json"
LOG_FILE = Path("/var/log/pasarguard-route-manager.log")

# Regex to validate note directives
# Allows spaces around colons and hyphens/underscores in names
DIRECTIVE_PATTERN = re.compile(
    r"node\s*:\s*([a-zA-Z0-9_\-]+)\s+out\s*:\s*([a-zA-Z0-9_\-]+)",
    re.IGNORECASE,
)

# Generation suffix for zero-restart live WARP outbound spawns: <base>__r0001
GEN_TAG_PATTERN = re.compile(r"^([a-zA-Z0-9_\-]+?)__r(\d{4})$")

# Auto-managed balancer naming
HA_BALANCER_PREFIX = "pg-ha-"
WARP_POOL_TAG = "warp-pool"

# Outbound protocols PasarGuard Node (backend/xray/live_plan.go) can remove live
# without restarting Xray. Protocols NOT in this set (wireguard, masque) must
# never be edited in-place or removed during a zero-downtime live update.
SAFE_REMOVABLE_PROTOCOLS = frozenset({
    "freedom",
    "direct",
    "blackhole",
    "block",
    "loopback",
    "dns",
    "http",
    "socks",
    "shadowsocks",
    "vless",
    "vmess",
    "trojan",
    "hysteria",
})

# Diversified Cloudflare WARP WireGuard Anycast IPv4 endpoints across multiple
# /24 blocks and official WARP UDP ports to avoid single-edge throttling/stalls.
WARP_WG_ENDPOINTS: tuple[str, ...] = (
    "162.159.192.1:2408",
    "188.114.96.1:500",
    "162.159.193.1:1701",
    "188.114.97.1:4500",
    "162.159.195.1:2408",
    "188.114.98.1:500",
    "162.159.192.7:1701",
    "188.114.99.1:4500",
    "162.159.193.5:2408",
    "188.114.96.7:1701",
    "162.159.195.6:500",
    "188.114.97.9:2408",
    "162.159.192.15:4500",
    "188.114.98.11:1701",
    "162.159.193.12:500",
    "188.114.99.14:2408",
)

# Official Cloudflare MASQUE edge ports that return the pinned MASQUE cert
WARP_MASQUE_PORTS: tuple[int, ...] = (443, 8443, 4443, 4500, 1701, 500, 8095)

DEFAULT_OBSERVATORY_PROBE_URL = "https://cloudflare.com/cdn-cgi/trace"
DEFAULT_OBSERVATORY_INTERVAL = "20s"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("route-manager")


def setup_logging(verbose: bool = False, log_file: Optional[Path] = None):
    """Configure logging with both console and optional file output."""
    if logger.handlers:
        return
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(errors="replace")
        except Exception:
            pass
    level = logging.DEBUG if verbose else logging.INFO
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    console.setLevel(level)
    logger.addHandler(console)

    # File handler (if log file is writable)
    if log_file:
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(str(log_file), encoding="utf-8")
            fh.setFormatter(fmt)
            fh.setLevel(level)
            logger.addHandler(fh)
        except OSError:
            pass  # Skip file logging if no permission or non-Linux path

    logger.setLevel(level)


def _safe_chmod_600(path: Path):
    """Restrict permissions to 0600 where supported by the OS."""
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
class Config:
    """Manages the script's configuration file."""

    def __init__(self, path: Path = CONFIG_FILE):
        self.path = path
        self.panel_url: str = ""
        self.username: str = ""
        self.password: str = ""
        self.poll_interval: int = 60
        self.verify_ssl: bool = True

        # Zero-downtime WARP health & HA settings
        self.warp_prefix: str = "warp"
        self.auto_heal_warp: bool = True
        self.fail_threshold: int = 2
        self.refresh_cooldown: int = 180
        self.max_latency_ms: int = 0
        self.use_ha_balancers: bool = True
        self.fallback_mode: str = "warp"  # "warp" (sibling WARP) or "direct"
        self.max_live_generations: int = 12
        self.compact_window: str = ""  # "" = manual-only (--compact), or "HH:MM-HH:MM"

    def load(self) -> bool:
        """Load config from file. Returns True if successful."""
        if not self.path.exists():
            return False
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.panel_url = str(data.get("panel_url", "")).rstrip("/")
            self.username = str(data.get("username", ""))
            self.password = str(data.get("password", ""))
            self.poll_interval = int(data.get("poll_interval", 60))
            self.verify_ssl = bool(data.get("verify_ssl", True))

            self.warp_prefix = str(data.get("warp_prefix", "warp")).strip() or "warp"
            self.auto_heal_warp = bool(data.get("auto_heal_warp", True))
            self.fail_threshold = max(1, int(data.get("fail_threshold", 2)))
            self.refresh_cooldown = max(30, int(data.get("refresh_cooldown", 180)))
            self.max_latency_ms = max(0, int(data.get("max_latency_ms", 0)))
            self.use_ha_balancers = bool(data.get("use_ha_balancers", True))
            fb = str(data.get("fallback_mode", "warp")).strip().lower()
            self.fallback_mode = fb if fb in ("warp", "direct") else "warp"
            self.max_live_generations = max(1, int(data.get("max_live_generations", 12)))
            self.compact_window = str(data.get("compact_window", "")).strip()
            return bool(self.panel_url and self.username and self.password)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
            logger.error(f"Failed to parse config: {e}")
            return False

    def save(self):
        """Save config to file with restricted permissions."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "panel_url": self.panel_url,
            "username": self.username,
            "password": self.password,
            "poll_interval": self.poll_interval,
            "verify_ssl": self.verify_ssl,
            "warp_prefix": self.warp_prefix,
            "auto_heal_warp": self.auto_heal_warp,
            "fail_threshold": self.fail_threshold,
            "refresh_cooldown": self.refresh_cooldown,
            "max_latency_ms": self.max_latency_ms,
            "use_ha_balancers": self.use_ha_balancers,
            "fallback_mode": self.fallback_mode,
            "max_live_generations": self.max_live_generations,
            "compact_window": self.compact_window,
        }
        self.path.write_text(
            json.dumps(data, indent=2),
            encoding="utf-8",
        )
        _safe_chmod_600(self.path)
        logger.info(f"Config saved to {self.path} (permissions: 600)")

    @staticmethod
    def interactive_setup(path: Path = CONFIG_FILE) -> "Config":
        """Run interactive first-time setup."""
        cfg = Config(path=path)
        print("\n=== PasarGuard Route & WARP Health Manager Setup ===\n")
        cfg.panel_url = input("Panel URL (e.g. https://panel.example.com): ").strip().rstrip("/")
        cfg.username = input("Admin Username: ").strip()
        cfg.password = getpass.getpass("Admin Password: ").strip()

        interval_str = input("Poll interval in seconds [60]: ").strip()
        cfg.poll_interval = int(interval_str) if interval_str else 60

        verify_str = input("Verify SSL? [y/N]: ").strip().lower()
        cfg.verify_ssl = verify_str in ("y", "yes")

        prefix_str = input("WARP outbound tag prefix [warp]: ").strip()
        cfg.warp_prefix = prefix_str if prefix_str else "warp"

        heal_str = input("Enable automatic zero-downtime WARP healing? [Y/n]: ").strip().lower()
        cfg.auto_heal_warp = heal_str not in ("n", "no")

        fb_str = input("Failover target when a WARP tunnel stalls [warp/direct] (default: warp): ").strip().lower()
        cfg.fallback_mode = "direct" if fb_str == "direct" else "warp"

        cfg.save()
        print("\n✓ Configuration saved successfully.")
        print("  Tip: Run with '--optimize-warp --dry-run' next to preview one-time WARP HA setup.\n")
        return cfg


# ---------------------------------------------------------------------------
# State Management (change detection + WARP generation & health state)
# ---------------------------------------------------------------------------
class StateManager:
    """Tracks applied routing hashes, active WARP generations, and failure counters."""

    def __init__(self, path: Path = STATE_FILE):
        self.path = path
        self._hashes: dict[str, str] = {}
        # core_id -> {base_tag -> active_outbound_tag}
        self.active_generations: dict[str, dict[str, str]] = {}
        # "core_id:outbound_tag" -> consecutive failure count
        self.fail_counts: dict[str, int] = {}
        # "core_id:base_tag" -> unix timestamp of last live refresh
        self.last_refresh_ts: dict[str, float] = {}
        self.endpoint_cursor: int = 0
        # core_id -> "YYYY-MM-DD" of last quiet-window compaction
        self.last_compact_date: dict[str, str] = {}

    def load(self):
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                return
            # Backwards-compatible migration from v1 flat {core_id: sha256_str}
            if raw and all(isinstance(v, str) for v in raw.values()):
                self._hashes = dict(raw)
                return

            self._hashes = dict(raw.get("hashes", {}))
            self.active_generations = {
                str(k): dict(v)
                for k, v in raw.get("active_generations", {}).items()
                if isinstance(v, dict)
            }
            self.fail_counts = {
                str(k): int(v) for k, v in raw.get("fail_counts", {}).items()
            }
            self.last_refresh_ts = {
                str(k): float(v) for k, v in raw.get("last_refresh_ts", {}).items()
            }
            self.endpoint_cursor = int(raw.get("endpoint_cursor", 0))
            self.last_compact_date = {
                str(k): str(v) for k, v in raw.get("last_compact_date", {}).items()
            }
        except (json.JSONDecodeError, ValueError, TypeError):
            self._hashes = {}

    def save(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "hashes": self._hashes,
                "active_generations": self.active_generations,
                "fail_counts": self.fail_counts,
                "last_refresh_ts": self.last_refresh_ts,
                "endpoint_cursor": self.endpoint_cursor,
                "last_compact_date": self.last_compact_date,
            }
            self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            _safe_chmod_600(self.path)
        except OSError as e:
            logger.debug(f"Skipping state save ({self.path}): {e}")

    @staticmethod
    def compute_live_hash(
        rules: list[dict],
        balancers: Optional[list[dict]] = None,
        outbound_tags: Optional[list[str]] = None,
    ) -> str:
        """Compute a deterministic SHA-256 hash of routing rules, balancers, and outbound tags."""
        normalized_rules = []
        for rule in rules:
            r = copy.deepcopy(rule)
            if isinstance(r.get("user"), list):
                r["user"] = sorted(r["user"])
            normalized_rules.append(r)

        normalized_balancers = []
        for bal in balancers or []:
            b = copy.deepcopy(bal)
            if isinstance(b.get("selector"), list):
                b["selector"] = list(b["selector"])
            normalized_balancers.append(b)
        normalized_balancers.sort(key=lambda b: b.get("tag", ""))

        doc = {
            "rules": normalized_rules,
            "balancers": normalized_balancers,
            "outbounds": list(outbound_tags or []),
        }
        return hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest()

    def has_changed(self, core_id: int, rules: list[dict]) -> bool:
        """Backwards-compatible rule hash check (commits hash immediately)."""
        current_hash = self.compute_live_hash(rules)
        key = str(core_id)
        if self._hashes.get(key) == current_hash:
            return False
        self._hashes[key] = current_hash
        return True

    def mark_applied(
        self,
        core_id: int,
        rules: list[dict],
        balancers: Optional[list[dict]] = None,
        outbound_tags: Optional[list[str]] = None,
    ):
        """Record the applied live configuration hash after a successful API push."""
        self._hashes[str(core_id)] = self.compute_live_hash(rules, balancers, outbound_tags)

    def get_active_tag(self, core_id: int, base_tag: str) -> Optional[str]:
        return self.active_generations.get(str(core_id), {}).get(base_tag)

    def set_active_tag(self, core_id: int, base_tag: str, active_tag: str):
        self.active_generations.setdefault(str(core_id), {})[base_tag] = active_tag

    def clear_core_generations(self, core_id: int):
        self.active_generations.pop(str(core_id), None)
        prefix = f"{core_id}:"
        for k in [k for k in self.fail_counts if k.startswith(prefix)]:
            del self.fail_counts[k]

    def snapshot(self) -> dict[str, Any]:
        """Return a deep copy of in-memory state for dry-run or error rollback."""
        return copy.deepcopy({
            "hashes": self._hashes,
            "active_generations": self.active_generations,
            "fail_counts": self.fail_counts,
            "last_refresh_ts": self.last_refresh_ts,
            "endpoint_cursor": self.endpoint_cursor,
            "last_compact_date": self.last_compact_date,
        })

    def restore(self, snap: dict[str, Any]):
        """Restore in-memory state from a snapshot."""
        cp = copy.deepcopy(snap)
        self._hashes = cp["hashes"]
        self.active_generations = cp["active_generations"]
        self.fail_counts = cp["fail_counts"]
        self.last_refresh_ts = cp["last_refresh_ts"]
        self.endpoint_cursor = cp["endpoint_cursor"]
        self.last_compact_date = cp["last_compact_date"]

    def next_wg_endpoint(self, exclude_endpoints: set[str]) -> str:
        """Select the next Cloudflare WARP WireGuard endpoint not in exclude_endpoints."""
        total = len(WARP_WG_ENDPOINTS)
        for offset in range(total):
            idx = (self.endpoint_cursor + offset) % total
            candidate = WARP_WG_ENDPOINTS[idx]
            if candidate not in exclude_endpoints:
                self.endpoint_cursor = (idx + 1) % total
                return candidate
        # If all 16 are already in use, advance round-robin anyway
        candidate = WARP_WG_ENDPOINTS[self.endpoint_cursor % total]
        self.endpoint_cursor = (self.endpoint_cursor + 1) % total
        return candidate


# ---------------------------------------------------------------------------
# PasarGuard API Client
# ---------------------------------------------------------------------------
class PanelClient:
    """HTTP client for PasarGuard Panel API."""

    def __init__(self, config: Config):
        self.base_url = config.panel_url
        self.username = config.username
        self.password = config.password
        self.verify_ssl = config.verify_ssl
        self._token = None
        self._observatory_warned_nodes: set[int] = set()
        self._client = httpx.Client(
            base_url=self.base_url,
            verify=self.verify_ssl,
            timeout=30.0,
            follow_redirects=True,
        )

    def _authenticate(self):
        """Obtain OAuth2 Bearer token."""
        logger.debug("Authenticating with panel...")
        resp = self._client.post(
            "/api/admin/token",
            data={
                "username": self.username,
                "password": self.password,
                "grant_type": "password",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        token_data = resp.json()
        self._token = token_data.get("access_token")
        if not self._token:
            raise RuntimeError("Authentication failed: no access_token in response")
        logger.debug("Authentication successful")

    def _headers(self) -> dict:
        if not self._token:
            self._authenticate()
        return {"Authorization": f"Bearer {self._token}"}

    def _request(self, method: str, path: str, quiet_errors: bool = False, **kwargs) -> Any:
        """Make an authenticated request with auto-retry on 401."""
        try:
            resp = self._client.request(method, path, headers=self._headers(), **kwargs)
            if resp.status_code == 401:
                # Token expired, re-authenticate
                self._token = None
                resp = self._client.request(method, path, headers=self._headers(), **kwargs)
            resp.raise_for_status()
            if resp.status_code == 204 or not resp.content:
                return {}
            return resp.json()
        except httpx.HTTPStatusError as e:
            if not quiet_errors:
                logger.error(f"API error {e.response.status_code} on {path}: {e.response.text[:200]}")
            raise

    def get_users(self, offset: int = 0, limit: int = 500) -> list[dict]:
        """Fetch all users from the panel, handling pagination."""
        all_users = []
        while True:
            data = self._request("GET", "/api/users", params={"offset": offset, "limit": limit})
            users = data.get("users", [])
            all_users.extend(users)
            total = data.get("total", 0)
            offset += limit
            if offset >= total or not users:
                break
        return all_users

    def get_nodes(self) -> list[dict]:
        """Fetch all nodes."""
        data = self._request("GET", "/api/nodes")
        return data.get("nodes", [])

    def get_core(self, core_id: int) -> dict:
        """Fetch a specific core config."""
        return self._request("GET", f"/api/core/{core_id}")

    def get_cores(self) -> list[dict]:
        """Fetch all core configs."""
        data = self._request("GET", "/api/cores")
        return data.get("cores", [])

    def update_core(self, core_id: int, core_data: dict, restart_nodes: bool = True):
        """
        Update a core config.
        Note: In PasarGuard, when only outbounds (additions or removable edits) and
        routing.{rules, balancers} changed, restart_nodes=True triggers ApplyConfigLive
        (stop_first=False) on nodes — updating Xray via gRPC with ZERO process restart!
        """
        return self._request(
            "PUT",
            f"/api/core/{core_id}",
            params={"restart_nodes": restart_nodes},
            json=core_data,
        )

    def get_node_outbounds_latency(
        self, node_id: int, node_name: str = "", timeout: Optional[int] = None
    ) -> Optional[list[dict]]:
        """
        Query Xray Observatory outbound status for a remote node via Panel API.
        Returns list of latency dicts, or None if Observatory is not enabled/reachable.
        """
        params: dict[str, Any] = {}
        if timeout is not None:
            params["timeout"] = timeout
        try:
            data = self._request(
                "GET",
                f"/api/node/{node_id}/outbounds_latency",
                quiet_errors=True,
                params=params,
            )
            if isinstance(data, dict):
                return data.get("latencies", [])
            return None
        except Exception as e:
            if node_id not in self._observatory_warned_nodes:
                label = f"'{node_name}' (id={node_id})" if node_name else f"id={node_id}"
                logger.debug(
                    f"Node {label}: outbound latency unavailable ({e}). "
                    f"Run with '--optimize-warp' once to enable Xray Observatory."
                )
                self._observatory_warned_nodes.add(node_id)
            return None

    def get_nodes_realtime_stats(self) -> dict[str, Optional[dict]]:
        """Fetch real-time bandwidth & CPU/mem stats for all nodes."""
        try:
            data = self._request("GET", "/api/nodes/realtime_stats", quiet_errors=True)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def close(self):
        self._client.close()


# ---------------------------------------------------------------------------
# Note Parser & WARP Tag Helpers
# ---------------------------------------------------------------------------
def parse_routing_directives(note: str | None) -> list[dict]:
    """
    Parse routing directives from a user's note field.

    Format: "node:<name> out:<tag>" separated by "|" for multiple assignments.

    Returns a list of dicts: [{"node": "sg", "outbound": "warp1"}, ...]
    Returns empty list if no valid directives found.
    """
    if not note:
        return []

    directives = []
    # Split by | for multiple assignments
    segments = note.split("|")

    for segment in segments:
        segment = segment.strip()
        match = DIRECTIVE_PATTERN.search(segment)
        if match:
            node_name = match.group(1).strip()
            outbound_tag = match.group(2).strip()
            directives.append({
                "node": node_name,
                "outbound": outbound_tag,
            })

    return directives


def split_generation_tag(tag: str) -> tuple[str, int]:
    """
    Split an outbound tag into (base_tag, generation_number).
    Examples:
        "warp1"         -> ("warp1", 0)
        "warp1__r0001"  -> ("warp1", 1)
    """
    m = GEN_TAG_PATTERN.match(tag)
    if m:
        return m.group(1), int(m.group(2))
    return tag, 0


def format_generation_tag(base_tag: str, generation: int) -> str:
    """Format a 4-digit zero-padded generation tag so prefix selectors never collide."""
    if generation <= 0:
        return base_tag
    return f"{base_tag}__r{generation:04d}"


def is_warp_tag(tag: str, warp_prefix: str = "warp") -> bool:
    """Return True if tag (or its base tag) belongs to the managed WARP prefix."""
    base, _ = split_generation_tag(tag)
    return base.lower().startswith(warp_prefix.lower())


def is_managed_balancer_tag(tag: str) -> bool:
    """Return True if a balancer tag is managed automatically by PG-ADDON."""
    return tag.startswith(HA_BALANCER_PREFIX) or tag == WARP_POOL_TAG


def has_observatory_configured(core_config: dict) -> bool:
    """Return True if Xray Observatory or BurstObservatory is explicitly configured."""
    obs = core_config.get("observatory")
    burst = core_config.get("burstObservatory")
    return bool((isinstance(obs, dict) and obs) or (isinstance(burst, dict) and burst))


def has_prefix_collision(tag: str, all_tags: set[str]) -> bool:
    """
    Return True if another outbound tag starts with `tag` (Xray balancer `selector`
    is a prefix match, so `selector: ["warp1"]` would also match `"warp10"` or `"warp1__r0001"`).
    """
    return any(other != tag and other.startswith(tag) for other in all_tags)


# ---------------------------------------------------------------------------
# Live-Update Safety Validator (Mirrors PasarGuard Node `planLiveUpdate`)
# ---------------------------------------------------------------------------
class LiveSafetyValidator:
    """
    Verifies that a Core Config update satisfies PasarGuard Panel (`only_live_parts_changed`)
    and PasarGuard Node (`backend/xray/live_plan.go:planLiveUpdate`) so Xray is updated
    live via gRPC (AddOutbound + ReplaceRouting) and NEVER restarted!
    """

    @staticmethod
    def _without_live_parts(config: dict) -> dict:
        stripped = copy.deepcopy(config)
        stripped.pop("outbounds", None)
        routing = stripped.get("routing")
        if isinstance(routing, dict):
            routing.pop("rules", None)
            routing.pop("balancers", None)
            if not routing:
                stripped.pop("routing", None)
        return stripped

    @staticmethod
    def _is_outbound_safe_to_remove(ob: dict) -> bool:
        protocol = str(ob.get("protocol", "")).strip().lower()
        if protocol not in SAFE_REMOVABLE_PROTOCOLS:
            return False
        if protocol == "vless":
            settings_json = json.dumps(ob.get("settings", {}))
            if '"reverse"' in settings_json or '"testpre"' in settings_json:
                return False
        return True

    @classmethod
    def check(cls, before_config: dict, after_config: dict) -> tuple[bool, str]:
        """
        Return (True, "") if `after_config` is guaranteed to apply live on PasarGuard
        nodes without restarting Xray; otherwise (False, reason).
        """
        if cls._without_live_parts(before_config) != cls._without_live_parts(after_config):
            return False, "config changed outside outbounds and routing.{rules, balancers}"

        old_out = before_config.get("outbounds", [])
        new_out = after_config.get("outbounds", [])
        if not isinstance(old_out, list) or not isinstance(new_out, list) or not old_out or not new_out:
            return False, "outbounds list is missing or empty"

        old_by_tag: dict[str, dict] = {}
        for ob in old_out:
            if not isinstance(ob, dict) or not ob.get("tag"):
                return False, "existing outbound missing tag"
            old_by_tag[ob["tag"]] = ob

        new_by_tag: dict[str, dict] = {}
        for ob in new_out:
            if not isinstance(ob, dict) or not ob.get("tag"):
                return False, "new outbound missing tag"
            tag = ob["tag"]
            if tag in new_by_tag:
                return False, f"duplicate outbound tag '{tag}'"
            new_by_tag[tag] = ob

        # Default outbound (index 0) cannot move if old[0] or new[0] is non-removable
        old_default = old_out[0]["tag"]
        new_default = new_out[0]["tag"]
        if old_default != new_default:
            if not cls._is_outbound_safe_to_remove(old_by_tag[old_default]):
                return False, f"default outbound '{old_default}' moved and is not live-removable"
            if new_default in old_by_tag and not cls._is_outbound_safe_to_remove(old_by_tag[new_default]):
                return False, f"new default outbound '{new_default}' existed and is not live-removable"

        # Every non-removable outbound (wireguard, masque, etc.) in old_out MUST still
        # exist in new_out with exact identical JSON contents.
        for tag, old_ob in old_by_tag.items():
            if tag not in new_by_tag:
                if not cls._is_outbound_safe_to_remove(old_ob):
                    return False, f"non-removable outbound '{tag}' ({old_ob.get('protocol')}) was deleted"
                continue
            new_ob = new_by_tag[tag]
            if old_ob != new_ob and not cls._is_outbound_safe_to_remove(old_ob):
                return False, f"non-removable outbound '{tag}' ({old_ob.get('protocol')}) was modified in-place"

        return True, ""


# ---------------------------------------------------------------------------
# WARP Outbound Health & Live Rotation Engine
# ---------------------------------------------------------------------------
class WarpHealthManager:
    """
    Manages WARP slots (warp1, warp2, ...), monitors node Observatory telemetry,
    performs zero-restart live refreshes (spawning warpN__r0001 or reusing recovered
    generations), builds HA balancers, and handles one-time --optimize-warp / --compact.
    """

    def __init__(self, config: Config, state: StateManager):
        self.config = config
        self.state = state

    def collect_slots(self, outbounds: list[dict]) -> dict[str, dict[int, dict]]:
        """
        Group WARP outbounds by base slot tag -> {generation_int: outbound_dict}.
        Preserves base slot discovery order.
        """
        slots: dict[str, dict[int, dict]] = {}
        for ob in outbounds:
            if not isinstance(ob, dict):
                continue
            tag = str(ob.get("tag", "")).strip()
            if not tag or not is_warp_tag(tag, self.config.warp_prefix):
                continue
            base, gen = split_generation_tag(tag)
            slots.setdefault(base, {})[gen] = ob
        return slots

    def resolve_active_tags(self, core_id: int, core_config: dict) -> dict[str, str]:
        """
        Determine the currently active outbound tag for each WARP base slot.
        Checks persisted state first, then existing pg-ha-<slot> balancers, then
        highest generation number in outbounds.
        """
        outbounds = core_config.get("outbounds", [])
        slots = self.collect_slots(outbounds)
        if not slots:
            return {}

        # Extract any selector hints from existing pg-ha-* balancers
        balancer_hints: dict[str, str] = {}
        for bal in core_config.get("routing", {}).get("balancers", []) or []:
            if not isinstance(bal, dict):
                continue
            btag = str(bal.get("tag", ""))
            sels = bal.get("selector") or []
            if btag.startswith(HA_BALANCER_PREFIX) and len(sels) == 1 and isinstance(sels[0], str):
                base = btag[len(HA_BALANCER_PREFIX):]
                balancer_hints[base] = sels[0]

        active_map: dict[str, str] = {}
        for base, gens in slots.items():
            valid_tags = {ob["tag"] for ob in gens.values()}
            persisted = self.state.get_active_tag(core_id, base)
            hint = balancer_hints.get(base)

            if persisted and persisted in valid_tags:
                chosen = persisted
            elif hint and hint in valid_tags:
                chosen = hint
            else:
                highest_gen = max(gens.keys())
                chosen = gens[highest_gen]["tag"]

            active_map[base] = chosen
            self.state.set_active_tag(core_id, base, chosen)

        return active_map

    @staticmethod
    def get_outbound_endpoint(ob: dict) -> str:
        """Extract human-readable endpoint ip:port from a wireguard or masque outbound."""
        proto = str(ob.get("protocol", "")).lower()
        settings = ob.get("settings", {}) or {}
        if proto == "wireguard":
            peers = settings.get("peers") or []
            if peers and isinstance(peers[0], dict):
                return str(peers[0].get("endpoint", ""))
        elif proto == "masque":
            addr = settings.get("address", "")
            port = settings.get("port", "")
            if addr:
                return f"{addr}:{port}" if port else str(addr)
        elif proto in ("socks", "http"):
            servers = settings.get("servers") or []
            if servers and isinstance(servers[0], dict):
                return f"{servers[0].get('address', '')}:{servers[0].get('port', '')}"
        return ""

    @staticmethod
    def _collect_used_endpoints(outbounds: list[dict]) -> set[str]:
        used = set()
        for ob in outbounds:
            if isinstance(ob, dict):
                ep = WarpHealthManager.get_outbound_endpoint(ob)
                if ep:
                    used.add(ep)
        return used

    def spawn_rotated_outbound(
        self,
        base_tag: str,
        gens: dict[int, dict],
        all_outbounds: list[dict],
    ) -> tuple[dict, str]:
        """
        Clone the latest outbound of `base_tag` into a new `base_tag__rNNNN` outbound
        with a fresh Cloudflare Anycast endpoint and hardened WireGuard/MASQUE settings.
        Returns (new_outbound_dict, new_endpoint_str).
        """
        latest_gen = max(gens.keys())
        next_gen = latest_gen + 1
        new_tag = format_generation_tag(base_tag, next_gen)
        template = copy.deepcopy(gens[latest_gen])
        template["tag"] = new_tag

        proto = str(template.get("protocol", "")).lower()
        settings = template.setdefault("settings", {})
        used_endpoints = self._collect_used_endpoints(all_outbounds)
        chosen_endpoint = ""

        if proto == "wireguard":
            # Harden MTU & KeepAlive on newly spawned tunnel
            mtu = settings.get("mtu", 0)
            if not isinstance(mtu, int) or mtu <= 0 or mtu > 1280:
                settings["mtu"] = 1280
            peers = settings.get("peers") or []
            if peers and isinstance(peers[0], dict):
                chosen_endpoint = self.state.next_wg_endpoint(used_endpoints)
                peers[0]["endpoint"] = chosen_endpoint
                if not peers[0].get("keepAlive"):
                    peers[0]["keepAlive"] = 20

        elif proto == "masque":
            # Keep the same MASQUE edge IP (preserves publicKey cert pin) and rotate port
            cur_addr = str(settings.get("address", "162.159.198.2"))
            cur_port = int(settings.get("port", 443) or 443)
            chosen_port = cur_port
            for candidate_port in WARP_MASQUE_PORTS:
                ep = f"{cur_addr}:{candidate_port}"
                if candidate_port != cur_port and ep not in used_endpoints:
                    chosen_port = candidate_port
                    break
            else:
                idx = (WARP_MASQUE_PORTS.index(cur_port) + 1) % len(WARP_MASQUE_PORTS) if cur_port in WARP_MASQUE_PORTS else 0
                chosen_port = WARP_MASQUE_PORTS[idx]
            settings["port"] = chosen_port
            chosen_endpoint = f"{cur_addr}:{chosen_port}"

            # Ensure xmux periodic auto-refresh is active
            stream = template.setdefault("streamSettings", {})
            masque_settings = stream.setdefault("masqueSettings", {})
            xmux = masque_settings.get("xmux")
            if not isinstance(xmux, dict) or not xmux.get("hMaxReusableSecs"):
                masque_settings["xmux"] = {"hMaxReusableSecs": "900-1800"}

        else:
            chosen_endpoint = self.get_outbound_endpoint(template)

        return template, chosen_endpoint

    def poll_core_observatory(
        self, client: PanelClient, core_id: int, nodes: list[dict]
    ) -> dict[str, list[dict]]:
        """
        Poll /outbounds_latency across all connected nodes assigned to `core_id`.
        Returns {outbound_tag: [{"node": name, "node_id": id, "alive": bool, "delay": int, "probed": bool}, ...]}.
        """
        core_nodes = [
            n for n in nodes
            if (n.get("core_config_id") or 1) == core_id
            and str(n.get("status", "")).lower() == "connected"
        ]
        by_tag: dict[str, list[dict]] = {}
        for node in core_nodes:
            nid = node["id"]
            nname = node.get("name", f"node-{nid}")
            latencies = client.get_node_outbounds_latency(nid, node_name=nname)
            if latencies is None:
                continue
            for entry in latencies:
                tag = entry.get("name", "")
                if not tag:
                    continue
                last_try = int(entry.get("last_try_time", 0) or 0)
                alive = bool(entry.get("alive", False))
                delay = int(entry.get("delay", 0) or 0)
                by_tag.setdefault(tag, []).append({
                    "node": nname,
                    "node_id": nid,
                    "alive": alive,
                    "delay": delay,
                    "probed": last_try > 0,
                })
        return by_tag

    def is_tag_degraded(self, observations: list[dict]) -> tuple[bool, str]:
        """Return (is_degraded, reason) from node Observatory reports for a single outbound tag."""
        probed = [o for o in observations if o.get("probed")]
        if not probed:
            return False, "pending initial probe"

        dead_nodes = [o["node"] for o in probed if not o["alive"]]
        if dead_nodes:
            return True, f"dead on node(s): {', '.join(dead_nodes)}"

        if self.config.max_latency_ms > 0:
            slow = [
                f"{o['node']} ({o['delay']}ms)"
                for o in probed
                if o["delay"] > self.config.max_latency_ms
            ]
            if slow:
                return True, f"latency > {self.config.max_latency_ms}ms on {', '.join(slow)}"

        return False, "healthy"

    def is_tag_confirmed_healthy(self, observations: list[dict]) -> bool:
        """Return True if at least one node probed the tag and ALL probed nodes report it healthy."""
        probed = [o for o in observations if o.get("probed")]
        if not probed:
            return False
        degraded, _ = self.is_tag_degraded(probed)
        return not degraded

    def heal_or_refresh_core(
        self,
        core_id: int,
        core_name: str,
        core_config: dict,
        telemetry: dict[str, list[dict]],
        manual_refresh_targets: Optional[set[str]] = None,
        force_spawn: bool = False,
    ) -> tuple[list[dict], dict[str, str], bool]:
        """
        Evaluate WARP health (or execute manual --refresh targets) for a core.
        Returns (updated_outbounds, active_map, changed).
        Guarantees existing wireguard/masque outbounds are NEVER modified or removed!
        """
        outbounds = copy.deepcopy(core_config.get("outbounds", []))
        slots = self.collect_slots(outbounds)
        active_map = self.resolve_active_tags(core_id, core_config)
        if not slots:
            return outbounds, active_map, False

        changed = False
        now = time.time()

        for base_tag, gens in slots.items():
            cur_active = active_map[base_tag]
            is_manual = bool(
                manual_refresh_targets
                and ("all" in manual_refresh_targets or base_tag.lower() in manual_refresh_targets)
            )

            should_rotate = False
            trigger_reason = ""

            if is_manual:
                should_rotate = True
                trigger_reason = "manual --refresh request"
            elif self.config.auto_heal_warp and telemetry:
                obs = telemetry.get(cur_active, [])
                degraded, reason = self.is_tag_degraded(obs)
                fail_key = f"{core_id}:{cur_active}"
                if degraded:
                    count = self.state.fail_counts.get(fail_key, 0) + 1
                    self.state.fail_counts[fail_key] = count
                    logger.warning(
                        f"Core '{core_name}': WARP '{base_tag}' (active='{cur_active}') "
                        f"unhealthy [{count}/{self.config.fail_threshold}] — {reason}"
                    )
                    if count >= self.config.fail_threshold:
                        cd_key = f"{core_id}:{base_tag}"
                        elapsed = now - self.state.last_refresh_ts.get(cd_key, 0.0)
                        if elapsed >= self.config.refresh_cooldown:
                            should_rotate = True
                            trigger_reason = f"{count} consecutive failed checks ({reason})"
                        else:
                            rem = int(self.config.refresh_cooldown - elapsed)
                            logger.info(
                                f"Core '{core_name}': WARP '{base_tag}' refresh in cooldown ({rem}s remaining); "
                                f"HA balancer fallback active"
                            )
                else:
                    if self.state.fail_counts.get(fail_key, 0) > 0:
                        logger.info(
                            f"Core '{core_name}': WARP '{base_tag}' ('{cur_active}') recovered before threshold"
                        )
                    self.state.fail_counts[fail_key] = 0

            if not should_rotate:
                continue

            # Step 1: Before spawning a new outbound, check if an ALREADY-EXISTING
            # generation of `base_tag` is confirmed healthy across probed nodes!
            reused_tag: Optional[str] = None
            if not force_spawn and telemetry:
                for gen_num, cand_ob in sorted(gens.items(), reverse=True):
                    cand_tag = cand_ob["tag"]
                    if cand_tag == cur_active:
                        continue
                    if self.is_tag_confirmed_healthy(telemetry.get(cand_tag, [])):
                        reused_tag = cand_tag
                        break

            if reused_tag:
                active_map[base_tag] = reused_tag
                self.state.set_active_tag(core_id, base_tag, reused_tag)
                self.state.fail_counts[f"{core_id}:{cur_active}"] = 0
                self.state.fail_counts[f"{core_id}:{reused_tag}"] = 0
                self.state.last_refresh_ts[f"{core_id}:{base_tag}"] = now
                ep = self.get_outbound_endpoint(
                    next(ob for ob in gens.values() if ob["tag"] == reused_tag)
                )
                logger.info(
                    f"Core '{core_name}': Live-switched '{base_tag}' from '{cur_active}' → "
                    f"recovered '{reused_tag}' ({ep}) [0 new outbounds, 0 restarts] ({trigger_reason})"
                )
                changed = True
                continue

            # Step 2: Spawn a brand-new generation outbound (liveAddOutbound)
            retired_count = len(gens) - 1
            if not is_manual and retired_count >= self.config.max_live_generations:
                logger.warning(
                    f"Core '{core_name}': '{base_tag}' reached max_live_generations "
                    f"({self.config.max_live_generations}). Relying on HA fallback until '--compact' runs."
                )
                continue

            new_ob, new_ep = self.spawn_rotated_outbound(base_tag, gens, outbounds)
            new_tag = new_ob["tag"]
            outbounds.append(new_ob)
            _, new_gen_num = split_generation_tag(new_tag)
            gens[new_gen_num] = new_ob

            active_map[base_tag] = new_tag
            self.state.set_active_tag(core_id, base_tag, new_tag)
            self.state.fail_counts[f"{core_id}:{cur_active}"] = 0
            self.state.fail_counts[f"{core_id}:{new_tag}"] = 0
            self.state.last_refresh_ts[f"{core_id}:{base_tag}"] = now

            logger.info(
                f"Core '{core_name}': Live-spawned fresh WARP outbound '{new_tag}' "
                f"(endpoint={new_ep}, replaces '{cur_active}') [0 node restarts] ({trigger_reason})"
            )
            changed = True

        return outbounds, active_map, changed

    @staticmethod
    def find_direct_outbound_tag(outbounds: list[dict]) -> Optional[str]:
        """Find the tag of the first freedom/direct outbound in Core Config."""
        for ob in outbounds:
            if isinstance(ob, dict) and str(ob.get("protocol", "")).lower() in ("freedom", "direct"):
                return ob.get("tag")
        if outbounds and isinstance(outbounds[0], dict):
            return outbounds[0].get("tag")
        return None

    def build_managed_balancers(
        self,
        core_config: dict,
        outbounds: list[dict],
        active_map: dict[str, str],
        telemetry: Optional[dict[str, list[dict]]] = None,
    ) -> tuple[list[dict], dict[str, str]]:
        """
        Build Xray HA balancers (`pg-ha-<base_tag>` and `warp-pool`) when Observatory
        is configured and `use_ha_balancers` is enabled.

        Returns:
            (managed_balancers_list, slot_to_balancer_tag_map)
        """
        if not self.config.use_ha_balancers or not active_map or not has_observatory_configured(core_config):
            return [], {}

        all_outbound_tags = {
            ob["tag"] for ob in outbounds if isinstance(ob, dict) and ob.get("tag")
        }
        direct_tag = self.find_direct_outbound_tag(outbounds)
        ordered_bases = list(active_map.keys())

        # Determine which active tags are currently healthy (for smart sibling fallback)
        healthy_bases = [
            b for b in ordered_bases
            if not telemetry or not self.is_tag_degraded(telemetry.get(active_map[b], []))[0]
        ]

        managed_balancers: list[dict] = []
        slot_balancer_map: dict[str, str] = {}
        collision_free_pool_selectors: list[str] = []

        for idx, base_tag in enumerate(ordered_bases):
            act_tag = active_map[base_tag]
            if has_prefix_collision(act_tag, all_outbound_tags):
                # Cannot isolate `act_tag` alone with Xray's prefix selector (e.g. warp1 vs warp1__r0001
                # when warp1 is active, or warp1 vs warp10). Route directly via outboundTag!
                logger.debug(
                    f"Skipping HA balancer for '{base_tag}' (active='{act_tag}' is a prefix of another tag)"
                )
                continue

            collision_free_pool_selectors.append(act_tag)

            # Choose fallbackTag (MUST be an outboundTag in Xray-core, never a balancerTag!)
            fallback_tag: Optional[str] = None
            if self.config.fallback_mode == "warp" and len(ordered_bases) > 1:
                # Prefer a healthy sibling slot in ring order
                ring = ordered_bases[idx + 1:] + ordered_bases[:idx]
                for cand_base in ring:
                    if cand_base in healthy_bases:
                        fallback_tag = active_map[cand_base]
                        break
                if not fallback_tag:
                    fallback_tag = active_map[ring[0]]
            if not fallback_tag:
                fallback_tag = direct_tag

            bal_tag = f"{HA_BALANCER_PREFIX}{base_tag}"
            bal_obj: dict[str, Any] = {
                "tag": bal_tag,
                "selector": [act_tag],
                "strategy": {"type": "roundRobin"},
            }
            if fallback_tag and fallback_tag != act_tag:
                bal_obj["fallbackTag"] = fallback_tag

            managed_balancers.append(bal_obj)
            slot_balancer_map[base_tag] = bal_tag

        # Build shared `warp-pool` leastPing balancer across all collision-free active WARP tags
        if collision_free_pool_selectors:
            pool_bal: dict[str, Any] = {
                "tag": WARP_POOL_TAG,
                "selector": sorted(collision_free_pool_selectors),
                "strategy": {"type": "leastPing"},
            }
            if direct_tag:
                pool_bal["fallbackTag"] = direct_tag
            managed_balancers.append(pool_bal)

        return managed_balancers, slot_balancer_map

    def optimize_core_config(self, core_id: int, core_config: dict) -> tuple[dict, list[str]]:
        """
        One-time setup (`--optimize-warp`):
          1. Adds "ObservatoryService" to `api.services`
          2. Configures static `"observatory"` (`subjectSelector: [warp_prefix]`, `enableConcurrency: true`)
          3. Hardens existing WARP outbounds (`mtu: 1280`, `keepAlive: 20`, diversified Anycast IPs, MASQUE xmux)
          4. Collapses any retired `*__rNNNN` generations cleanly
          5. Configures initial HA balancers (`pg-ha-*` and `warp-pool`)

        Returns (updated_config, summary_notes).
        """
        cfg = copy.deepcopy(core_config)
        notes: list[str] = []

        # 1. Collapse retired *__rNNNN generations first if any exist
        cfg, compact_notes = self.compact_core_config(core_id, cfg)
        notes.extend(compact_notes)

        outbounds = cfg.get("outbounds", [])
        slots = self.collect_slots(outbounds)
        if not slots:
            return cfg, []

        # 2. Harden each base WARP outbound & diversify endpoints
        used_endpoints: set[str] = set()
        for ob in outbounds:
            if not isinstance(ob, dict):
                continue
            tag = str(ob.get("tag", ""))
            if not is_warp_tag(tag, self.config.warp_prefix):
                continue

            proto = str(ob.get("protocol", "")).lower()
            settings = ob.setdefault("settings", {})

            if proto == "wireguard":
                if settings.get("mtu") != 1280:
                    settings["mtu"] = 1280
                    notes.append(f"'{tag}': set WireGuard mtu=1280")

                peers = settings.get("peers") or []
                for p in peers:
                    if not isinstance(p, dict):
                        continue
                    if not p.get("keepAlive"):
                        p["keepAlive"] = 20
                        notes.append(f"'{tag}': set WireGuard keepAlive=20")

                    ep = str(p.get("endpoint", "")).strip()
                    host = ep.rsplit(":", 1)[0].strip("[]") if ":" in ep else ep
                    is_domain = False
                    if host:
                        try:
                            ipaddress.ip_address(host)
                        except ValueError:
                            is_domain = True

                    # Replace domain endpoint (e.g. engage.cloudflareclient.com) or duplicate IP:port
                    if is_domain or not ep or ep in used_endpoints:
                        new_ep = self.state.next_wg_endpoint(used_endpoints)
                        p["endpoint"] = new_ep
                        notes.append(f"'{tag}': diversified endpoint {ep or '(empty)'} → {new_ep}")
                        ep = new_ep
                    used_endpoints.add(ep)

            elif proto == "masque":
                stream = ob.setdefault("streamSettings", {})
                ms = stream.setdefault("masqueSettings", {})
                xmux = ms.get("xmux")
                if not isinstance(xmux, dict) or not xmux.get("hMaxReusableSecs"):
                    ms["xmux"] = {"hMaxReusableSecs": "900-1800"}
                    notes.append(f"'{tag}': enabled MASQUE xmux auto-refresh (900-1800s)")

        # 3. Ensure ObservatoryService in api.services
        api_cfg = cfg.get("api")
        if not isinstance(api_cfg, dict):
            api_cfg = {
                "tag": "API",
                "services": [
                    "HandlerService",
                    "LoggerService",
                    "StatsService",
                    "ObservatoryService",
                ],
            }
            cfg["api"] = api_cfg
            notes.append("api.services: initialized API with 'ObservatoryService'")
        else:
            services = list(api_cfg.get("services") or [])
            if not any(str(s).lower() == "observatoryservice" for s in services):
                services.append("ObservatoryService")
                api_cfg["services"] = services
                notes.append("api.services: enabled 'ObservatoryService'")

        # 4. Ensure static prefix `observatory` so future liveAddOutbound never alters non-live config
        prefix = self.config.warp_prefix
        if not has_observatory_configured(cfg):
            cfg["observatory"] = {
                "subjectSelector": [prefix],
                "probeURL": DEFAULT_OBSERVATORY_PROBE_URL,
                "probeInterval": DEFAULT_OBSERVATORY_INTERVAL,
                "enableConcurrency": True,
            }
            notes.append(
                f"observatory: configured concurrent probe ({DEFAULT_OBSERVATORY_INTERVAL}) for selector ['{prefix}']"
            )
        else:
            for key in ("observatory", "burstObservatory"):
                sec = cfg.get(key)
                if isinstance(sec, dict):
                    sels = list(sec.get("subjectSelector") or [])
                    if prefix not in sels:
                        # Replace individual warp1/warp2 tags with static prefix so live spawns match automatically
                        sels = [s for s in sels if not is_warp_tag(str(s), prefix)]
                        sels.append(prefix)
                        sec["subjectSelector"] = sels
                        notes.append(f"{key}.subjectSelector: normalized to static prefix '{prefix}'")
                    if key == "observatory" and not sec.get("enableConcurrency"):
                        sec["enableConcurrency"] = True
                        notes.append("observatory: enabled enableConcurrency=true")

        # 5. Build initial HA balancers
        active_map = self.resolve_active_tags(core_id, cfg)
        managed_bals, _ = self.build_managed_balancers(cfg, outbounds, active_map)
        if managed_bals:
            routing = cfg.setdefault("routing", {})
            existing_bals = routing.get("balancers") or []
            manual_bals = [
                b for b in existing_bals
                if isinstance(b, dict) and not is_managed_balancer_tag(str(b.get("tag", "")))
            ]
            Merged = manual_bals + managed_bals
            if Merged != existing_bals:
                routing["balancers"] = Merged
                notes.append(
                    f"routing.balancers: configured {len(managed_bals)} HA/pool balancer(s) "
                    f"({', '.join(b['tag'] for b in managed_bals)})"
                )

        return cfg, notes

    def compact_core_config(self, core_id: int, core_config: dict) -> tuple[dict, list[str]]:
        """
        Collapse retired `warpN__rXXXX` outbounds back into clean `warpN` outbounds,
        carrying over the currently active generation's working endpoint & settings.
        """
        cfg = copy.deepcopy(core_config)
        outbounds = cfg.get("outbounds", [])
        slots = self.collect_slots(outbounds)
        if not slots:
            return cfg, []

        active_map = self.resolve_active_tags(core_id, cfg)
        retired_tags: set[str] = set()
        replacements: dict[str, dict] = {}
        notes: list[str] = []

        for base_tag, gens in slots.items():
            if len(gens) <= 1 and 0 in gens:
                continue
            act_tag = active_map[base_tag]
            act_ob = next((ob for ob in gens.values() if ob["tag"] == act_tag), None)
            if act_ob is None:
                act_ob = gens[max(gens.keys())]

            clean_ob = copy.deepcopy(act_ob)
            clean_ob["tag"] = base_tag
            replacements[base_tag] = clean_ob

            for ob in gens.values():
                if ob["tag"] != base_tag:
                    retired_tags.add(ob["tag"])

            notes.append(
                f"'{base_tag}': compacted {len(gens)} generation(s) (active='{act_tag}', "
                f"endpoint={self.get_outbound_endpoint(clean_ob)}) → '{base_tag}'"
            )

        if not retired_tags and not replacements:
            return cfg, []

        new_outbounds: list[dict] = []
        placed_bases: set[str] = set()
        for ob in outbounds:
            if not isinstance(ob, dict):
                continue
            tag = str(ob.get("tag", ""))
            base, _ = split_generation_tag(tag)
            if base in replacements:
                if base not in placed_bases:
                    new_outbounds.append(replacements[base])
                    placed_bases.add(base)
                continue
            if tag in retired_tags:
                continue
            new_outbounds.append(ob)

        cfg["outbounds"] = new_outbounds
        self.state.clear_core_generations(core_id)

        # Rewrite any rules or managed balancers pointing to `__rNNNN` back to `base_tag`
        active_map = self.resolve_active_tags(core_id, cfg)
        managed_bals, slot_bal_map = self.build_managed_balancers(cfg, new_outbounds, active_map)
        routing = cfg.setdefault("routing", {})
        existing_bals = routing.get("balancers") or []
        manual_bals = [
            b for b in existing_bals
            if isinstance(b, dict) and not is_managed_balancer_tag(str(b.get("tag", "")))
        ]
        if manual_bals or managed_bals:
            routing["balancers"] = manual_bals + managed_bals
        else:
            routing.pop("balancers", None)

        if isinstance(routing.get("rules"), list):
            for rule in routing["rules"]:
                if not isinstance(rule, dict):
                    continue
                if rule.get("outboundTag"):
                    b, gen = split_generation_tag(str(rule["outboundTag"]))
                    if gen > 0 and b in active_map:
                        rule["outboundTag"] = b
                elif rule.get("balancerTag") and str(rule["balancerTag"]).startswith(HA_BALANCER_PREFIX):
                    b = str(rule["balancerTag"])[len(HA_BALANCER_PREFIX):]
                    if b in active_map and b not in slot_bal_map:
                        rule.pop("balancerTag", None)
                        rule["outboundTag"] = b

        return cfg, notes


# ---------------------------------------------------------------------------
# Routing Rule Engine
# ---------------------------------------------------------------------------
class RoutingEngine:
    """Builds and manages Xray routing rules based on user directives."""

    @staticmethod
    def build_rules(
        assignments: dict[str, list[str]],
        balancer_tags: Optional[set[str]] = None,
    ) -> list[dict]:
        """
        Build routing rules from target_tag→users mapping.
        Automatically emits `balancerTag` when `target_tag` is in `balancer_tags`,
        and `outboundTag` otherwise.

        Args:
            assignments: {"target_tag": ["user_email_1", "user_email_2"]}
            balancer_tags: Optional set of valid Xray balancer tags in this core.

        Returns:
            List of Xray routing rule dicts.
        """
        btags = balancer_tags or set()
        rules = []
        for target_tag, users in sorted(assignments.items()):
            if not users:
                continue
            rule: dict[str, Any] = {
                "type": "field",
                "user": sorted(set(users)),  # Deduplicate and sort
            }
            if target_tag in btags:
                rule["balancerTag"] = target_tag
            else:
                rule["outboundTag"] = target_tag
            rules.append(rule)
        return rules


# ---------------------------------------------------------------------------
# Main Sync & WARP Orchestration Logic
# ---------------------------------------------------------------------------
class RouteSync:
    """Orchestrates user note routing sync, live WARP healing, and maintenance."""

    def __init__(
        self,
        client: PanelClient,
        state: StateManager,
        config: Optional[Config] = None,
        dry_run: bool = False,
    ):
        self.client = client
        self.state = state
        self.config = config or Config()
        self.dry_run = dry_run
        self.engine = RoutingEngine()
        self.warp = WarpHealthManager(self.config, self.state)

    @staticmethod
    def _filter_cores(cores: list[dict], selector: Optional[str]) -> list[dict]:
        if not selector:
            return cores
        sel = selector.strip().lower()
        return [
            c for c in cores
            if str(c.get("id", "")).lower() == sel or str(c.get("name", "")).lower() == sel
        ]

    def _is_in_compact_window(self, core_id: int) -> bool:
        """Check if current local time falls in `compact_window` ("HH:MM-HH:MM") once per day."""
        win = self.config.compact_window
        if not win or "-" not in win:
            return False
        now = dt.datetime.now()
        today = now.strftime("%Y-%m-%d")
        if self.state.last_compact_date.get(str(core_id)) == today:
            return False
        try:
            start_s, end_s = [p.strip() for p in win.split("-", 1)]
            sh, sm = [int(x) for x in start_s.split(":", 1)]
            eh, em = [int(x) for x in end_s.split(":", 1)]
            cur_m = now.hour * 60 + now.minute
            start_m = sh * 60 + sm
            end_m = eh * 60 + em
            if start_m <= end_m:
                return start_m <= cur_m <= end_m
            return cur_m >= start_m or cur_m <= end_m
        except ValueError:
            logger.warning(f"Invalid compact_window format '{win}' (expected HH:MM-HH:MM)")
            return False

    def sync(
        self,
        manual_refresh_targets: Optional[set[str]] = None,
        core_selector: Optional[str] = None,
        force_spawn: bool = False,
    ) -> int:
        """
        Run a full user-routing sync + zero-downtime WARP health check cycle.

        Returns the number of cores that were updated.
        """
        dry_snap = self.state.snapshot() if self.dry_run else None
        try:
            return self._sync_impl(
                manual_refresh_targets=manual_refresh_targets,
                core_selector=core_selector,
                force_spawn=force_spawn,
            )
        finally:
            if dry_snap is not None:
                self.state.restore(dry_snap)

    def _sync_impl(
        self,
        manual_refresh_targets: Optional[set[str]] = None,
        core_selector: Optional[str] = None,
        force_spawn: bool = False,
    ) -> int:
        # 1. Fetch all data
        logger.info("Fetching users from panel...")
        users = self.client.get_users()
        logger.info(f"  → {len(users)} users fetched")

        logger.info("Fetching nodes from panel...")
        nodes = self.client.get_nodes()
        logger.info(f"  → {len(nodes)} nodes fetched")

        logger.info("Fetching core configs from panel...")
        all_cores = self.client.get_cores()
        cores = self._filter_cores(all_cores, core_selector)
        logger.info(f"  → {len(cores)} core(s) selected")

        # 2. Build lookup maps
        node_by_name: dict[str, dict] = {}
        node_to_core: dict[int, int] = {}
        for node in nodes:
            name = node.get("name", "").lower()
            if name:
                node_by_name[name] = node
            core_id = node.get("core_config_id")
            if core_id:
                node_to_core[node["id"]] = core_id

        core_by_id: dict[int, dict] = {c["id"]: c for c in cores}

        # 3. Poll Observatory health & prepare per-core WARP state (outbounds, active slots, balancers)
        prepared_cores: dict[int, dict[str, Any]] = {}
        for core in cores:
            if str(core.get("type", "xray")).lower() != "xray":
                continue
            cid = core["id"]
            cname = core.get("name", f"core-{cid}")
            ccfg = core.get("config", {})
            slots = self.warp.collect_slots(ccfg.get("outbounds", []))

            telemetry: dict[str, list[dict]] = {}
            if slots and (self.config.auto_heal_warp or manual_refresh_targets):
                telemetry = self.warp.poll_core_observatory(self.client, cid, nodes)

            pre_core_snap = self.state.snapshot()
            new_outbounds, active_map, warp_changed = self.warp.heal_or_refresh_core(
                core_id=cid,
                core_name=cname,
                core_config=ccfg,
                telemetry=telemetry,
                manual_refresh_targets=manual_refresh_targets,
                force_spawn=force_spawn,
            )

            managed_bals, slot_balancer_map = self.warp.build_managed_balancers(
                ccfg, new_outbounds, active_map, telemetry=telemetry
            )

            existing_bals = ccfg.get("routing", {}).get("balancers") or []
            manual_bals = [
                b for b in existing_bals
                if isinstance(b, dict) and not is_managed_balancer_tag(str(b.get("tag", "")))
            ]
            merged_balancers = manual_bals + managed_bals
            balancer_tags = {b["tag"] for b in merged_balancers if isinstance(b, dict) and b.get("tag")}
            outbound_tags = {ob["tag"] for ob in new_outbounds if isinstance(ob, dict) and ob.get("tag")}

            prepared_cores[cid] = {
                "outbounds": new_outbounds,
                "active_map": active_map,
                "slot_balancer_map": slot_balancer_map,
                "merged_balancers": merged_balancers,
                "balancer_tags": balancer_tags,
                "outbound_tags": outbound_tags,
                "warp_changed": warp_changed,
                "slots": slots,
                "pre_state_snap": pre_core_snap,
            }

        # 4. Parse all user directives and build per-core assignments
        #    core_id → {resolved_target_tag → [user_emails]}
        core_assignments: dict[int, dict[str, list[str]]] = {}

        for user in users:
            username = user.get("username", "")
            user_id = user.get("id")
            note = user.get("note", "")

            if not username or not user_id:
                continue

            directives = parse_routing_directives(note)
            if not directives:
                continue  # Manually managed, skip

            # The Xray email format in PasarGuard is just the user ID string
            xray_email = f"{user_id}"

            for directive in directives:
                target_node_name = directive["node"].lower()
                raw_target = directive["outbound"]

                node = node_by_name.get(target_node_name)
                if not node:
                    logger.warning(
                        f"User '{username}': node '{directive['node']}' not found, skipping"
                    )
                    continue

                core_id = node_to_core.get(node["id"])
                if not core_id or core_id not in prepared_cores:
                    if not core_selector:
                        logger.warning(
                            f"User '{username}': node '{node.get('name')}' has no active Xray core config, skipping"
                        )
                    continue

                prep = prepared_cores[core_id]
                resolved_target = self._resolve_directive_target(raw_target, prep)
                if not resolved_target:
                    logger.warning(
                        f"User '{username}': outbound/balancer '{raw_target}' not found in core config "
                        f"for node '{directive['node']}'. Skipping."
                    )
                    continue

                core_assignments.setdefault(core_id, {}).setdefault(resolved_target, []).append(xray_email)
                logger.debug(
                    f"  User '{username}' ({xray_email}) → "
                    f"node '{directive['node']}' (core {core_id}) → "
                    f"'{raw_target}' (resolved='{resolved_target}')"
                )

        # 5. Include cores that had existing user rules, WARP changes, or managed balancer updates
        for cid, prep in prepared_cores.items():
            ccfg = core_by_id[cid].get("config", {})
            existing_rules = ccfg.get("routing", {}).get("rules", [])
            has_user_rules = any(isinstance(r, dict) and "user" in r for r in existing_rules)
            existing_bals = ccfg.get("routing", {}).get("balancers") or []
            if (
                cid not in core_assignments
                and (has_user_rules or prep["warp_changed"] or prep["merged_balancers"] != existing_bals)
            ):
                core_assignments[cid] = {}

        # 6. Apply live updates per core
        updates = 0
        for core_id, assignments in core_assignments.items():
            core = core_by_id.get(core_id)
            prep = prepared_cores.get(core_id)
            if not core or not prep:
                continue

            if self._update_core_live(core, assignments, prep):
                updates += 1

            # Check optional off-peak quiet-window compaction
            slots = self.warp.collect_slots(prep["outbounds"])
            retired_total = sum(max(0, len(g) - 1) for g in slots.values())
            if (
                not self.dry_run
                and retired_total >= max(4, self.config.max_live_generations // 2)
                and self._is_in_compact_window(core_id)
            ):
                logger.info(
                    f"Core '{core.get('name')}' entered quiet compact_window "
                    f"({self.config.compact_window}) with {retired_total} retired WARP outbound(s); compacting..."
                )
                fresh_core = self.client.get_core(core_id)
                self._apply_maintenance_transform(fresh_core, mode="compact")
                self.state.last_compact_date[str(core_id)] = dt.datetime.now().strftime("%Y-%m-%d")
                self.state.save()

        if updates == 0:
            logger.info("No routing or WARP state changes detected.")
        else:
            logger.info(f"Updated {updates} core config(s) live (0 Xray restarts).")

        if not self.dry_run:
            self.state.save()

        return updates

    @staticmethod
    def _resolve_directive_target(raw_target: str, prep: dict[str, Any]) -> Optional[str]:
        """
        Resolve a user's `out:<tag>` directive against a core's WARP HA balancers,
        active WARP generations, custom balancers, and standard outbounds.
        Case-insensitive match against base WARP slot names for convenience.
        """
        slot_bal_map: dict[str, str] = prep["slot_balancer_map"]
        active_map: dict[str, str] = prep["active_map"]
        balancer_tags: set[str] = prep["balancer_tags"]
        outbound_tags: set[str] = prep["outbound_tags"]

        # 1. Exact or case-insensitive match on a WARP base slot (e.g. "warp1")
        for base_tag in active_map:
            if base_tag.lower() == raw_target.lower():
                if base_tag in slot_bal_map:
                    return slot_bal_map[base_tag]
                return active_map[base_tag]

        # 2. Balancer tag (e.g. "warp-pool" or custom balancer)
        for btag in balancer_tags:
            if btag.lower() == raw_target.lower():
                return btag

        # 3. Direct outbound tag (e.g. "direct", "block")
        for otag in outbound_tags:
            if otag.lower() == raw_target.lower():
                return otag

        return None

    def _update_core_live(
        self,
        core: dict,
        assignments: dict[str, list[str]],
        prep: dict[str, Any],
    ) -> bool:
        """
        Apply a strictly live-safe update (outbounds append + routing rules/balancers)
        to a single core config. Never restarts Xray!
        """
        core_id = core["id"]
        core_name = core.get("name", f"core-{core_id}")
        config = core.get("config", {})

        existing_routing = config.get("routing", {})
        existing_rules = existing_routing.get("rules", [])
        existing_balancers = existing_routing.get("balancers") or []
        existing_outbounds = config.get("outbounds", [])

        # Preserve manual system rules (rules that don't match by 'user')
        manual_rules = [r for r in existing_rules if isinstance(r, dict) and "user" not in r]
        new_user_rules = self.engine.build_rules(assignments, balancer_tags=prep["balancer_tags"])
        merged_rules = manual_rules + new_user_rules
        merged_balancers = prep["merged_balancers"]
        updated_outbounds = prep["outbounds"]

        # Compare directly against what the Panel currently runs!
        rules_same = merged_rules == existing_rules
        bals_same = merged_balancers == existing_balancers
        outbounds_same = updated_outbounds == existing_outbounds

        if rules_same and bals_same and outbounds_same:
            logger.debug(f"Core '{core_name}' (id={core_id}): already in sync")
            self.state.mark_applied(
                core_id,
                merged_rules,
                merged_balancers,
                [ob["tag"] for ob in updated_outbounds if isinstance(ob, dict) and ob.get("tag")],
            )
            return False

        # Build candidate updated config
        updated_config = copy.deepcopy(config)
        updated_config["outbounds"] = updated_outbounds
        routing_obj = updated_config.setdefault("routing", {})
        routing_obj["rules"] = merged_rules
        if merged_balancers or "balancers" in routing_obj:
            if merged_balancers:
                routing_obj["balancers"] = merged_balancers
            else:
                routing_obj.pop("balancers", None)

        # Enforce strict live-update safety invariant before touching Panel!
        is_safe, unsafe_reason = LiveSafetyValidator.check(config, updated_config)
        if not is_safe:
            if "pre_state_snap" in prep:
                self.state.restore(prep["pre_state_snap"])
            logger.error(
                f"Core '{core_name}' (id={core_id}): Refusing update because it would "
                f"restart Xray ({unsafe_reason})"
            )
            return False

        old_user_count = sum(len(r.get("user", [])) for r in existing_rules if isinstance(r, dict) and "user" in r)
        new_user_count = sum(len(r.get("user", [])) for r in new_user_rules)
        logger.info(
            f"Core '{core_name}' (id={core_id}) [LIVE gRPC]: "
            f"outbounds {len(existing_outbounds)} → {len(updated_outbounds)}, "
            f"balancers {len(existing_balancers)} → {len(merged_balancers)}, "
            f"rules {len(existing_rules)} → {len(merged_rules)}, "
            f"routed users {old_user_count} → {new_user_count}"
        )

        for rule in new_user_rules:
            target = rule.get("balancerTag") or rule.get("outboundTag", "?")
            kind = "balancer" if "balancerTag" in rule else "outbound"
            logger.info(f"  → {kind} '{target}': {rule.get('user', [])}")

        if self.dry_run:
            logger.info(f"  [DRY RUN] Would live-update core '{core_name}' — skipping")
            return False

        update_payload = {
            "name": core.get("name"),
            "config": updated_config,
            "type": core.get("type"),
            "exclude_inbound_tags": list(core.get("exclude_inbound_tags", [])),
            "fallbacks_inbound_tags": list(core.get("fallbacks_inbound_tags", [])),
        }

        try:
            # Note: restart_nodes=True tells PasarGuard Panel to push the edit to nodes;
            # Panel's `only_live_parts_changed` sets stop_first=False, so PasarGuard Node
            # runs ApplyConfigLive (AddOutbound + ReplaceRouting) with ZERO Xray restart!
            self.client.update_core(core_id, update_payload, restart_nodes=True)
            logger.info(f"  ✓ Core '{core_name}' updated live via gRPC (0 connections dropped)")
            self.state.mark_applied(
                core_id,
                merged_rules,
                merged_balancers,
                [ob["tag"] for ob in updated_outbounds if isinstance(ob, dict) and ob.get("tag")],
            )
            self.state.save()
            return True
        except Exception as e:
            if "pre_state_snap" in prep:
                self.state.restore(prep["pre_state_snap"])
            logger.error(f"  ✗ Failed to update core '{core_name}': {e}")
            return False

    def _apply_maintenance_transform(self, core: dict, mode: str) -> bool:
        """Execute one-time `--optimize-warp` or maintenance `--compact` on a core."""
        core_id = core["id"]
        core_name = core.get("name", f"core-{core_id}")
        old_cfg = core.get("config", {})
        snap = self.state.snapshot()

        if mode == "optimize":
            new_cfg, notes = self.warp.optimize_core_config(core_id, old_cfg)
        elif mode == "compact":
            new_cfg, notes = self.warp.compact_core_config(core_id, old_cfg)
        else:
            raise ValueError(f"Unknown mode: {mode}")

        if not notes or new_cfg == old_cfg:
            logger.info(f"Core '{core_name}' (id={core_id}): nothing to {mode}.")
            return False

        logger.info(f"Core '{core_name}' (id={core_id}) [{mode.upper()}]:")
        for n in notes:
            logger.info(f"  • {n}")

        if self.dry_run:
            self.state.restore(snap)
            logger.info(f"  [DRY RUN] Would apply {mode} to core '{core_name}' — skipping")
            return False

        payload = {
            "name": core.get("name"),
            "config": new_cfg,
            "type": core.get("type"),
            "exclude_inbound_tags": list(core.get("exclude_inbound_tags", [])),
            "fallbacks_inbound_tags": list(core.get("fallbacks_inbound_tags", [])),
        }
        try:
            self.client.update_core(core_id, payload, restart_nodes=True)
        except Exception:
            self.state.restore(snap)
            raise
        self.state.save()
        logger.info(f"  ✓ Core '{core_name}' {mode} complete.")
        return True

    def optimize_warp(self, core_selector: Optional[str] = None) -> int:
        """Run one-time WARP HA + Observatory + MTU/KeepAlive optimization."""
        cores = self._filter_cores(self.client.get_cores(), core_selector)
        count = 0
        for core in cores:
            if str(core.get("type", "xray")).lower() != "xray":
                continue
            if self._apply_maintenance_transform(core, mode="optimize"):
                count += 1
        # Follow up with a live routing sync so user rules bind to the new HA balancers
        if count > 0 and not self.dry_run:
            self.sync(core_selector=core_selector)
        return count

    def compact_warp(self, core_selector: Optional[str] = None) -> int:
        """Collapse retired `*__rNNNN` outbounds back to base WARP tags."""
        cores = self._filter_cores(self.client.get_cores(), core_selector)
        count = 0
        for core in cores:
            if str(core.get("type", "xray")).lower() != "xray":
                continue
            if self._apply_maintenance_transform(core, mode="compact"):
                count += 1
        if count > 0 and not self.dry_run:
            self.sync(core_selector=core_selector)
        return count

    def print_status(self, core_selector: Optional[str] = None):
        """Print a human-readable health dashboard of all WARP slots across cores & nodes."""
        nodes = self.client.get_nodes()
        cores = self._filter_cores(self.client.get_cores(), core_selector)

        print("\n=== PasarGuard WARP Outbound Status ===")
        for core in cores:
            if str(core.get("type", "xray")).lower() != "xray":
                continue
            cid = core["id"]
            cname = core.get("name", f"core-{cid}")
            ccfg = core.get("config", {})
            slots = self.warp.collect_slots(ccfg.get("outbounds", []))
            if not slots:
                continue

            active_map = self.warp.resolve_active_tags(cid, ccfg)
            obs_enabled = has_observatory_configured(ccfg)
            telemetry = self.warp.poll_core_observatory(self.client, cid, nodes)
            retired_total = sum(max(0, len(g) - 1) for g in slots.values())

            print(
                f"\nCore: {cname} (id={cid}) | Observatory: {'ENABLED' if obs_enabled else 'NOT SET (run --optimize-warp)'} "
                f"| Retired Outbounds: {retired_total}"
            )
            print("-" * 86)
            print(f"{'Slot':<12} {'Active Tag':<18} {'Protocol':<10} {'Endpoint':<23} {'Node Health'}")
            print("-" * 86)

            for base_tag, gens in slots.items():
                act_tag = active_map[base_tag]
                act_ob = next((ob for ob in gens.values() if ob["tag"] == act_tag), gens[max(gens.keys())])
                proto = str(act_ob.get("protocol", "?"))
                ep = self.warp.get_outbound_endpoint(act_ob) or "-"
                obs_list = telemetry.get(act_tag, [])
                if not obs_list:
                    health_str = "no node telemetry yet"
                else:
                    parts = []
                    for o in obs_list:
                        if not o["probed"]:
                            parts.append(f"{o['node']}:pending")
                        elif o["alive"]:
                            parts.append(f"{o['node']}:OK({o['delay']}ms)")
                        else:
                            parts.append(f"{o['node']}:DEAD")
                    health_str = ", ".join(parts)

                print(f"{base_tag:<12} {act_tag:<18} {proto:<10} {ep:<23} {health_str}")
        print("")


# ---------------------------------------------------------------------------
# Daemon Mode
# ---------------------------------------------------------------------------
class Daemon:
    """Runs the sync & WARP health loop as a daemon process."""

    def __init__(self, syncer: RouteSync, interval: int):
        self.syncer = syncer
        self.interval = max(10, interval)  # Minimum 10s to be safe
        self._running = True
        self._reload_requested = False

        signal.signal(signal.SIGTERM, self._handle_stop)
        signal.signal(signal.SIGINT, self._handle_stop)
        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, self._handle_reload)

    def _handle_stop(self, signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        self._running = False

    def _handle_reload(self, signum, frame):
        logger.info("Received SIGHUP, reloading config and triggering immediate sync...")
        self._reload_requested = True

    def run(self):
        logger.info(
            f"Daemon started, polling every {self.interval}s "
            f"(auto_heal_warp={self.syncer.config.auto_heal_warp})"
        )
        while self._running:
            if self._reload_requested:
                self._reload_requested = False
                self.syncer.config.load()

            try:
                self.syncer.sync()
            except Exception as e:
                logger.error(f"Sync cycle failed: {e}")

            # Sleep in small intervals so we respond immediately to signals
            for _ in range(self.interval):
                if not self._running or self._reload_requested:
                    break
                time.sleep(1)

        logger.info("Daemon stopped")


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="PasarGuard Route & Zero-Downtime WARP Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Note format (in PasarGuard user notes):
  node:sg out:warp1                     Route user through 'warp1' (with automatic HA failover)
  node:sg out:warp-pool                 Load-balance user across all healthy warp* outbounds
  node:sg out:warp1 | node:us out:direct   Multiple node assignments

Zero-Downtime WARP Commands (run on Main Panel VPS):
  %(prog)s --optimize-warp              One-time setup: enable Observatory, MTU=1280, KeepAlive=20 & HA balancers
  %(prog)s --status                     View live WARP outbound latency & health across all nodes
  %(prog)s --refresh warp2              Live-refresh 'warp2' with a new Anycast IP:port (0 user drops!)
  %(prog)s --refresh all                Live-refresh every 'warp*' slot with zero Xray restarts
  %(prog)s --compact                    Maintenance: prune retired *__rNNNN outbounds back to base tags

Daemon & Sync Examples:
  %(prog)s                              Run routing sync + WARP health check once
  %(prog)s --dry-run                    Preview changes without applying
  %(prog)s --daemon                     Run background service with auto-polling & auto-healing
  %(prog)s --setup                      Interactive first-time setup
        """,
    )
    parser.add_argument("--dry-run", action="store_true", help="Preview changes without applying")
    parser.add_argument("--daemon", action="store_true", help="Run as daemon with periodic polling")
    parser.add_argument("--interval", type=int, default=None, help="Poll interval in seconds (default: from config)")
    parser.add_argument("--setup", action="store_true", help="Run interactive first-time setup")
    parser.add_argument("--status", action="store_true", help="Show live WARP health across cores and nodes")
    parser.add_argument(
        "--refresh",
        type=str,
        default=None,
        metavar="TAG",
        help="Zero-downtime live refresh of a WARP slot (e.g. 'warp2', 'warp1,warp2', or 'all')",
    )
    parser.add_argument(
        "--force-spawn",
        action="store_true",
        help="With --refresh, always spawn a fresh *__rNNNN endpoint instead of reusing a recovered one",
    )
    parser.add_argument(
        "--optimize-warp",
        action="store_true",
        help="One-time setup: configure Xray Observatory, WireGuard MTU/KeepAlive, Anycast IPs, and HA balancers",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Maintenance: collapse retired *__rNNNN outbounds back into clean base WARP tags",
    )
    parser.add_argument(
        "--core",
        type=str,
        default=None,
        help="Optional core ID or core name filter (for --refresh, --optimize-warp, --compact, --status)",
    )
    parser.add_argument("--config", type=str, default=None, help=f"Config file path (default: {CONFIG_FILE})")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    # Setup logging
    setup_logging(verbose=args.verbose, log_file=LOG_FILE)

    # Config file path
    config_path = Path(args.config) if args.config else CONFIG_FILE

    # Interactive setup mode
    if args.setup:
        Config.interactive_setup(path=config_path)
        return

    # Load config
    config = Config(path=config_path)
    if not config.load():
        logger.error(f"Config not found or invalid at {config_path}")
        logger.error("Run with --setup to create a config, or specify --config <path>")
        sys.exit(1)

    # Initialize components
    state = StateManager()
    state.load()

    client = PanelClient(config)
    syncer = RouteSync(client, state, config=config, dry_run=args.dry_run)

    try:
        if args.status:
            syncer.print_status(core_selector=args.core)
        elif args.optimize_warp:
            syncer.optimize_warp(core_selector=args.core)
        elif args.compact:
            syncer.compact_warp(core_selector=args.core)
        elif args.refresh:
            targets = {t.strip().lower() for t in args.refresh.split(",") if t.strip()}
            syncer.sync(
                manual_refresh_targets=targets,
                core_selector=args.core,
                force_spawn=args.force_spawn,
            )
        elif args.daemon:
            interval = args.interval or config.poll_interval
            daemon = Daemon(syncer, interval)
            daemon.run()
        else:
            syncer.sync(core_selector=args.core)
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)
    finally:
        client.close()
        if not args.dry_run:
            state.save()


if __name__ == "__main__":
    main()
