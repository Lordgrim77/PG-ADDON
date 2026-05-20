#!/usr/bin/env python3
"""
PasarGuard Route Manager
========================
Automatically manages Xray routing rules based on user note directives.

Note Format (in PasarGuard user notes):
    node:sg out:warp
    node:sg out:warp | node:us out:direct

How it works:
    1. Polls PasarGuard API for all users
    2. Parses notes for routing directives (node:<name> out:<tag>)
    3. Reads core configs and builds proper Xray routing rules
    4. Pushes updated configs only when changes are detected
    5. Cleans up rules for deleted users or cleared notes
Security:
    - Config file permissions restricted to 600 (owner-only read/write)
    - API token is never logged
    - All inputs are validated and sanitized
    - No shell execution or eval()

Usage:
    python3 route_manager.py                    # Run sync once
    python3 route_manager.py --dry-run          # Preview changes without applying
    python3 route_manager.py --daemon           # Run as daemon, poll on interval
    python3 route_manager.py --interval 30      # Poll every 30 seconds (with --daemon)
    python3 route_manager.py --setup            # Interactive first-time setup
"""

import argparse
import copy
import getpass
import hashlib
import json
import logging
import os
import re
import signal
import sys
import time
from pathlib import Path
from typing import Optional

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

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("route-manager")


def setup_logging(verbose: bool = False, log_file: Optional[Path] = None):
    """Configure logging with both console and optional file output."""
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
        except PermissionError:
            pass  # Skip file logging if no permission

    logger.setLevel(level)


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

    def load(self) -> bool:
        """Load config from file. Returns True if successful."""
        if not self.path.exists():
            return False
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.panel_url = data.get("panel_url", "").rstrip("/")
            self.username = data.get("username", "")
            self.password = data.get("password", "")
            self.poll_interval = data.get("poll_interval", 60)
            self.verify_ssl = data.get("verify_ssl", True)
            return bool(self.panel_url and self.username and self.password)
        except (json.JSONDecodeError, KeyError) as e:
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
        }
        self.path.write_text(
            json.dumps(data, indent=2),
            encoding="utf-8",
        )
        # Restrict permissions: owner read/write only
        os.chmod(self.path, 0o600)
        logger.info(f"Config saved to {self.path} (permissions: 600)")

    @staticmethod
    def interactive_setup() -> "Config":
        """Run interactive first-time setup."""
        cfg = Config()
        print("\n=== PasarGuard Route Manager Setup ===\n")
        cfg.panel_url = input("Panel URL (e.g. https://panel.example.com): ").strip().rstrip("/")
        cfg.username = input("Admin Username: ").strip()
        cfg.password = getpass.getpass("Admin Password: ").strip()

        interval_str = input("Poll interval in seconds [60]: ").strip()
        cfg.poll_interval = int(interval_str) if interval_str else 60

        verify_str = input("Verify SSL? [y/N]: ").strip().lower()
        cfg.verify_ssl = verify_str in ("y", "yes")

        cfg.save()
        print("\n✓ Configuration saved successfully.\n")
        return cfg


# ---------------------------------------------------------------------------
# State Management (for change detection)
# ---------------------------------------------------------------------------
class StateManager:
    """Tracks the hash of the last applied routing state to avoid unnecessary updates."""

    def __init__(self, path: Path = STATE_FILE):
        self.path = path
        self._hashes: dict[str, str] = {}  # core_id -> hash of auto_rules

    def load(self):
        if self.path.exists():
            try:
                self._hashes = json.loads(self.path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, ValueError):
                self._hashes = {}

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._hashes, indent=2), encoding="utf-8")
        os.chmod(self.path, 0o600)

    def has_changed(self, core_id: int, rules: list[dict]) -> bool:
        """Check if the rules for this core have changed since last apply."""
        # Create a deterministic hash of the rules
        # Sort users within each rule for consistent comparison
        normalized = []
        for rule in rules:
            r = dict(rule)
            if "user" in r:
                r["user"] = sorted(r["user"])
            normalized.append(r)
        normalized.sort(key=lambda r: r.get("outboundTag", ""))

        current_hash = hashlib.sha256(
            json.dumps(normalized, sort_keys=True).encode()
        ).hexdigest()

        key = str(core_id)
        if self._hashes.get(key) == current_hash:
            return False

        self._hashes[key] = current_hash
        return True


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

    def _request(self, method: str, path: str, **kwargs) -> dict | list:
        """Make an authenticated request with auto-retry on 401."""
        try:
            resp = self._client.request(method, path, headers=self._headers(), **kwargs)
            if resp.status_code == 401:
                # Token expired, re-authenticate
                self._token = None
                resp = self._client.request(method, path, headers=self._headers(), **kwargs)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"API error {e.response.status_code}: {e.response.text[:200]}")
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
            if offset >= total:
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
        """Update a core config and optionally restart associated nodes."""
        return self._request(
            "PUT",
            f"/api/core/{core_id}",
            params={"restart_nodes": restart_nodes},
            json=core_data,
        )

    def close(self):
        self._client.close()


# ---------------------------------------------------------------------------
# Note Parser
# ---------------------------------------------------------------------------
def parse_routing_directives(note: str | None) -> list[dict]:
    """
    Parse routing directives from a user's note field.

    Format: "node:<name> out:<tag>" separated by "|" for multiple assignments.

    Returns a list of dicts: [{"node": "sg", "outbound": "warp"}, ...]
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


# ---------------------------------------------------------------------------
# Routing Rule Engine
# ---------------------------------------------------------------------------
class RoutingEngine:
    """Builds and manages Xray routing rules based on user directives."""

    @staticmethod
    def build_rules(assignments: dict[str, list[str]]) -> list[dict]:
        """
        Build routing rules from outbound→users mapping.

        Args:
            assignments: {"outbound_tag": ["user_email_1", "user_email_2"]}

        Returns:
            List of Xray routing rule dicts.
        """
        rules = []
        for outbound_tag, users in sorted(assignments.items()):
            if not users:
                continue
            rule = {
                "type": "field",
                "user": sorted(set(users)),  # Deduplicate and sort
                "outboundTag": outbound_tag,
            }
            rules.append(rule)
        return rules


# ---------------------------------------------------------------------------
# Main Sync Logic
# ---------------------------------------------------------------------------
class RouteSync:
    """Orchestrates the full sync cycle."""

    def __init__(self, client: PanelClient, state: StateManager, dry_run: bool = False):
        self.client = client
        self.state = state
        self.dry_run = dry_run
        self.engine = RoutingEngine()

    def sync(self) -> int:
        """
        Run a full sync cycle.

        Returns the number of cores that were updated.
        """
        # 1. Fetch all data
        logger.info("Fetching users from panel...")
        users = self.client.get_users()
        logger.info(f"  → {len(users)} users fetched")

        logger.info("Fetching nodes from panel...")
        nodes = self.client.get_nodes()
        logger.info(f"  → {len(nodes)} nodes fetched")

        logger.info("Fetching core configs from panel...")
        cores = self.client.get_cores()
        logger.info(f"  → {len(cores)} cores fetched")

        # 2. Build lookup maps
        # node_name (lowercase) → node dict
        node_by_name: dict[str, dict] = {}
        for node in nodes:
            name = node.get("name", "").lower()
            if name:
                node_by_name[name] = node

        # node_id → core_config_id
        node_to_core: dict[int, int] = {}
        for node in nodes:
            core_id = node.get("core_config_id")
            if core_id:
                node_to_core[node["id"]] = core_id

        # core_id → core dict
        core_by_id: dict[int, dict] = {c["id"]: c for c in cores}

        # Build valid outbounds per core_id
        valid_outbounds_by_core: dict[int, set[str]] = {}
        for core in cores:
            outbounds = set()
            for ob in core.get("config", {}).get("outbounds", []):
                if isinstance(ob, dict) and "tag" in ob:
                    outbounds.add(ob["tag"])
            valid_outbounds_by_core[core["id"]] = outbounds

        # 3. Parse all user directives and build per-core assignments
        #    core_id → {outbound_tag → [user_emails]}
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

            # The Xray email format is: "{id}.{username}"
            xray_email = f"{user_id}.{username}"

            for directive in directives:
                target_node_name = directive["node"].lower()
                target_outbound = directive["outbound"]

                # Find the node
                node = node_by_name.get(target_node_name)
                if not node:
                    logger.warning(
                        f"User '{username}': node '{directive['node']}' not found, skipping"
                    )
                    continue

                # Find the core for this node
                core_id = node_to_core.get(node["id"])
                if not core_id:
                    logger.warning(
                        f"User '{username}': node '{node.get('name')}' has no core config, skipping"
                    )
                    continue

                # Validate outboundTag exists in core config
                if target_outbound not in valid_outbounds_by_core.get(core_id, set()):
                    logger.warning(
                        f"User '{username}': outbound '{target_outbound}' not found in core config for node '{directive['node']}'. Skipping."
                    )
                    continue

                # Add to assignments
                if core_id not in core_assignments:
                    core_assignments[core_id] = {}
                if target_outbound not in core_assignments[core_id]:
                    core_assignments[core_id][target_outbound] = []

                core_assignments[core_id][target_outbound].append(xray_email)
                logger.debug(
                    f"  User '{username}' ({xray_email}) → "
                    f"node '{directive['node']}' (core {core_id}) → "
                    f"outbound '{target_outbound}'"
                )

        # 4. Handle cores that have existing routing rules but no directives assigned
        for core in cores:
            core_id = core["id"]
            config = core.get("config", {})
            existing_rules = config.get("routing", {}).get("rules", [])
            if existing_rules and core_id not in core_assignments:
                core_assignments[core_id] = {}  # Empty = remove all rules

        # 5. Apply changes per core
        updates = 0

        for core_id, assignments in core_assignments.items():
            core = core_by_id.get(core_id)
            if not core:
                logger.warning(f"Core {core_id} not found in cores list, skipping")
                continue

            updated = self._update_core_rules(core, assignments)
            if updated:
                updates += 1

        if updates == 0:
            logger.info("No routing changes detected.")
        else:
            logger.info(f"Updated {updates} core config(s).")

        return updates

    def _update_core_rules(self, core: dict, assignments: dict[str, list[str]]) -> bool:
        """
        Update routing rules for a single core config.

        Returns True if the core was updated.
        """
        core_id = core["id"]
        core_name = core.get("name", f"core-{core_id}")
        config = core.get("config", {})

        # Get existing routing rules
        routing = config.get("routing", {})
        existing_rules = routing.get("rules", [])

        # Preserve manual system rules (rules that don't match by 'user')
        manual_rules = [r for r in existing_rules if "user" not in r]

        # Build new rules
        new_rules = self.engine.build_rules(assignments)

        # Merge them (manual system rules first, then auto-generated user rules)
        merged_rules = manual_rules + new_rules

        # Check if anything changed
        if not self.state.has_changed(core_id, merged_rules):
            logger.debug(f"Core '{core_name}' (id={core_id}): no changes detected")
            return False

        # Log changes
        old_user_count = sum(len(r.get("user", [])) for r in existing_rules if "user" in r)
        new_user_count = sum(len(r.get("user", [])) for r in new_rules)
        logger.info(
            f"Core '{core_name}' (id={core_id}): "
            f"rules {len(existing_rules)} → {len(merged_rules)}, "
            f"users in rules {old_user_count} → {new_user_count} "
            f"(preserved {len(manual_rules)} manual rules)"
        )

        # Show detailed diff for user rules
        for rule in new_rules:
            users = rule.get("user", [])
            outbound = rule.get("outboundTag", "?")
            logger.info(f"  → outbound '{outbound}': {users}")

        if self.dry_run:
            logger.info(f"  [DRY RUN] Would update core '{core_name}' — skipping")
            return False

        # Build update payload
        updated_config = copy.deepcopy(config)
        if "routing" not in updated_config:
            updated_config["routing"] = {}
        updated_config["routing"]["rules"] = merged_rules

        # Prepare the core update payload matching CoreCreate schema
        update_payload = {
            "name": core.get("name"),
            "config": updated_config,
            "type": core.get("type"),
            "exclude_inbound_tags": list(core.get("exclude_inbound_tags", [])),
            "fallbacks_inbound_tags": list(core.get("fallbacks_inbound_tags", [])),
        }

        # Push to panel
        try:
            self.client.update_core(core_id, update_payload, restart_nodes=True)
            logger.info(f"  ✓ Core '{core_name}' updated and nodes restarted")
            self.state.save()
            return True
        except Exception as e:
            logger.error(f"  ✗ Failed to update core '{core_name}': {e}")
            return False


# ---------------------------------------------------------------------------
# Daemon Mode
# ---------------------------------------------------------------------------
class Daemon:
    """Runs the sync loop as a daemon process."""

    def __init__(self, syncer: RouteSync, interval: int):
        self.syncer = syncer
        self.interval = max(10, interval)  # Minimum 10s to be safe
        self._running = True

        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

    def _handle_signal(self, signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        self._running = False

    def run(self):
        logger.info(f"Daemon started, polling every {self.interval}s")
        while self._running:
            try:
                self.syncer.sync()
            except Exception as e:
                logger.error(f"Sync cycle failed: {e}")

            # Sleep in small intervals so we can respond to signals
            for _ in range(self.interval):
                if not self._running:
                    break
                time.sleep(1)

        logger.info("Daemon stopped")


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="PasarGuard Route Manager — Auto-manage Xray routing rules via user notes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Note format (in PasarGuard user notes):
  node:sg out:warp              Route user through 'warp' outbound on node 'sg'
  node:sg out:warp | node:us out:direct   Multiple node assignments

Examples:
  %(prog)s                      Run sync once
  %(prog)s --dry-run            Preview changes without applying
  %(prog)s --daemon             Run as daemon with auto-polling
  %(prog)s --daemon --interval 30   Poll every 30 seconds
  %(prog)s --setup              Interactive first-time setup
        """,
    )
    parser.add_argument("--dry-run", action="store_true", help="Preview changes without applying")
    parser.add_argument("--daemon", action="store_true", help="Run as daemon with periodic polling")
    parser.add_argument("--interval", type=int, default=None, help="Poll interval in seconds (default: from config)")
    parser.add_argument("--setup", action="store_true", help="Run interactive first-time setup")
    parser.add_argument("--config", type=str, default=None, help=f"Config file path (default: {CONFIG_FILE})")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    # Setup logging
    setup_logging(verbose=args.verbose, log_file=LOG_FILE)

    # Config file path
    config_path = Path(args.config) if args.config else CONFIG_FILE

    # Interactive setup mode
    if args.setup:
        Config.interactive_setup()
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
    syncer = RouteSync(client, state, dry_run=args.dry_run)

    try:
        if args.daemon:
            interval = args.interval or config.poll_interval
            daemon = Daemon(syncer, interval)
            daemon.run()
        else:
            syncer.sync()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)
    finally:
        client.close()
        state.save()


if __name__ == "__main__":
    main()
