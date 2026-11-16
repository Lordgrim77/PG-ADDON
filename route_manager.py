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
    python3 route_manager.py --diagnose             # Read-only audit: node versions, duplicate keys
    python3 route_manager.py --status               # Show WARP outbound health across nodes
    python3 route_manager.py --refresh warp2        # Zero-downtime live refresh of warp2
    python3 route_manager.py --refresh warp2 --new-identity --force-spawn  # Fresh Cloudflare identity
    python3 route_manager.py --migrate-masque warp15  # Live two-stage MASQUE migration (Xray>=26.10.21)
    python3 route_manager.py --optimize-warp        # One-time setup: Observatory + MTU/KeepAlive + HA
    python3 route_manager.py --compact              # Prune retired *__rNNNN outbounds (maintenance)
    python3 route_manager.py --setup                # Interactive first-time setup
"""

import argparse
import base64
import contextlib
import copy
import datetime as dt
import getpass
import hashlib
import ipaddress
import json
import logging
import os
import re
import secrets
import signal
import socket
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Optional

try:
    import fcntl
except ImportError:  # Windows
    fcntl = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
try:
    import httpx
except ImportError:
    print("ERROR: 'httpx' is required. Install it with: pip install httpx")
    sys.exit(1)

try:
    from cryptography.hazmat.primitives import serialization as _crypto_serialization
    from cryptography.hazmat.primitives.asymmetric import ec as _crypto_ec
    from cryptography.hazmat.primitives.asymmetric import x25519 as _crypto_x25519
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CONFIG_DIR = Path("/etc/pasarguard-route-manager")
CONFIG_FILE = CONFIG_DIR / "config.json"
STATE_FILE = CONFIG_DIR / "state.json"
WARP_DEVICES_FILE = CONFIG_DIR / "warp_devices.json"
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
    # Extended pool (used once the first 16 are taken or when a /24 is unreachable)
    "162.159.192.20:500",
    "188.114.96.20:4500",
    "162.159.195.20:1701",
    "188.114.97.20:2408",
    "162.159.192.33:4500",
    "188.114.98.33:2408",
    "162.159.195.33:500",
    "188.114.99.33:1701",
    "162.159.192.48:2408",
    "188.114.96.48:500",
    "162.159.195.48:4500",
    "188.114.97.48:1701",
    "162.159.192.66:1701",
    "188.114.98.66:4500",
    "162.159.195.66:2408",
    "188.114.99.66:500",
)

# Official Cloudflare MASQUE edge ports that return the pinned MASQUE cert
WARP_MASQUE_PORTS: tuple[int, ...] = (443, 8443, 4443, 4500, 1701, 500, 8095)

DEFAULT_OBSERVATORY_PROBE_URL = "https://cloudflare.com/cdn-cgi/trace"
DEFAULT_OBSERVATORY_INTERVAL = "20s"

# Minimum Xray-core version with MASQUE WARP support (PR #6878, released v26.10.21)
MIN_MASQUE_WARP_VERSION: tuple[int, int, int] = (26, 10, 21)

# Cloudflare WARP client registration endpoints (matching 3x-ui WarpService)
CF_WARP_WG_API_BASE = "https://api.cloudflareclient.com/v0a4005"
CF_WARP_WG_CLIENT_VER = "a-6.30-3596"
CF_WARP_MASQUE_API_BASE = "https://api.cloudflareclient.com/v0a4471"
CF_WARP_MASQUE_CLIENT_VER = "a-6.35-4471"
CF_WARP_MASQUE_SNI = "consumer-masque.cloudflareclient.com"
CF_WARP_USER_AGENT = "WARP for Android"

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


def _file_sig(path: Path) -> Optional[tuple[int, int]]:
    """Return (mtime_ns, size) if `path` exists, else None."""
    try:
        st = path.stat()
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return None


def _atomic_write_text(path: Path, text: str):
    """Atomically write UTF-8 text with 0600 permissions so readers never see partial JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f".{path.name}.{os.getpid()}.tmp"
    try:
        tmp.write_text(text, encoding="utf-8")
        _safe_chmod_600(tmp)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


@contextlib.contextmanager
def _interprocess_lock(lock_path: Path):
    """Advisory inter-process lock (POSIX flock) preventing CLI vs Daemon state races."""
    if fcntl is None:
        yield
        return
    f = None
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        f = lock_path.open("a+", encoding="utf-8")
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
    except OSError:
        # Fail open in restricted read-only test/non-root environments
        if f is not None:
            try:
                f.close()
            except OSError:
                pass
            f = None
    try:
        yield
    finally:
        if f is not None:
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                f.close()
            except OSError:
                pass


def endpoint_prefix24(endpoint: str) -> str:
    """Return the IPv4 /24 network of an `ip:port` endpoint (e.g. '162.159.193.0/24'), or '' if not IPv4."""
    host = endpoint.rsplit(":", 1)[0].strip("[]") if ":" in endpoint else endpoint
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return ""
    if addr.version != 4:
        return ""
    return str(ipaddress.ip_network(f"{host}/24", strict=False))


def parse_xray_version(version_str: Optional[str]) -> Optional[tuple[int, int, int]]:
    """Parse Xray version tags like '26.10.21', 'v26.11.9', or '26.10.21-rc1'."""
    if not version_str:
        return None
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", str(version_str).strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def node_supports_masque(node: dict) -> tuple[bool, str]:
    """Check whether a PasarGuard node runs Xray >= 26.10.21 (MASQUE WARP support)."""
    raw = node.get("xray_version")
    parsed = parse_xray_version(raw)
    if parsed is None:
        return False, f"unknown xray_version ({raw!r})"
    if parsed < MIN_MASQUE_WARP_VERSION:
        min_str = ".".join(map(str, MIN_MASQUE_WARP_VERSION))
        return False, f"xray_version {raw} < {min_str}"
    return True, str(raw)


def get_nodes_for_core(nodes: list[dict], core_id: int) -> list[dict]:
    """Return all nodes assigned to `core_id` (defaulting core_config_id=None to id=1)."""
    return [n for n in nodes if (n.get("core_config_id") or 1) == core_id]


def core_masque_readiness(nodes: list[dict], core_id: int) -> tuple[bool, list[str], list[dict]]:
    """
    Verify every node assigned to `core_id` runs Xray >= 26.10.21.
    Returns (all_ready, blocker_messages, assigned_nodes).
    """
    assigned = get_nodes_for_core(nodes, core_id)
    if not assigned:
        return False, [f"no nodes assigned to core id={core_id}"], []
    blockers: list[str] = []
    for n in assigned:
        ok, detail = node_supports_masque(n)
        if not ok:
            nname = n.get("name", f"node-{n.get('id', '?')}")
            blockers.append(f"{nname}: {detail}")
    return (len(blockers) == 0), blockers, assigned


def key_fingerprint(secret: str) -> str:
    """Return a non-reversible 12-char SHA-256 prefix for safe duplicate-key detection."""
    cleaned = str(secret or "").strip()
    if not cleaned:
        return ""
    return hashlib.sha256(cleaned.encode("utf-8")).hexdigest()[:12]


_X25519_P = (1 << 255) - 19
_X25519_A24 = 121665
_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")


def _x25519_scalar_mult(scalar_bytes: bytes, u_bytes: Optional[bytes] = None) -> bytes:
    """Pure-Python RFC 7748 X25519 Montgomery ladder (works without cryptography)."""
    if len(scalar_bytes) != 32:
        raise ValueError("X25519 scalar must be 32 bytes")
    k_buf = bytearray(scalar_bytes)
    k_buf[0] &= 248
    k_buf[31] &= 127
    k_buf[31] |= 64
    k = int.from_bytes(k_buf, "little")

    if u_bytes is None:
        u = 9
    else:
        u_arr = bytearray(u_bytes)
        u_arr[31] &= 127
        u = int.from_bytes(u_arr, "little") % _X25519_P

    x_1 = u
    x_2, z_2 = 1, 0
    x_3, z_3 = u, 1
    swap = 0
    p = _X25519_P

    for t in range(254, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        if swap:
            x_2, x_3 = x_3, x_2
            z_2, z_3 = z_3, z_2
        swap = k_t

        a = (x_2 + z_2) % p
        aa = (a * a) % p
        b = (x_2 - z_2) % p
        bb = (b * b) % p
        e = (aa - bb) % p
        c = (x_3 + z_3) % p
        d = (x_3 - z_3) % p
        da = (d * a) % p
        cb = (c * b) % p
        x_3 = pow(da + cb, 2, p)
        z_3 = (x_1 * pow(da - cb, 2, p)) % p
        x_2 = (aa * bb) % p
        z_2 = (e * (aa + _X25519_A24 * e)) % p

    if swap:
        x_2, x_3 = x_3, x_2
        z_2, z_3 = z_3, z_2

    res = (x_2 * pow(z_2, p - 2, p)) % p
    return res.to_bytes(32, "little")


def _p256_jdouble(pt: tuple[int, int, int]) -> tuple[int, int, int]:
    """Double a Jacobian point (X, Y, Z) on NIST P-256 (a = -3)."""
    x1, y1, z1 = pt
    if z1 == 0 or y1 == 0:
        return (0, 1, 0)
    p = _P256_P
    delta = (z1 * z1) % p
    gamma = (y1 * y1) % p
    beta = (x1 * gamma) % p
    alpha = (3 * (x1 - delta) * (x1 + delta)) % p
    x3 = (alpha * alpha - 8 * beta) % p
    z3 = ((y1 + z1) ** 2 - gamma - delta) % p
    y3 = (alpha * (4 * beta - x3) - 8 * gamma * gamma) % p
    return (x3, y3, z3)


def _p256_jadd(pt1: tuple[int, int, int], pt2: tuple[int, int, int]) -> tuple[int, int, int]:
    """Add two Jacobian points on NIST P-256."""
    x1, y1, z1 = pt1
    x2, y2, z2 = pt2
    if z1 == 0:
        return pt2
    if z2 == 0:
        return pt1
    p = _P256_P
    z1z1 = (z1 * z1) % p
    z2z2 = (z2 * z2) % p
    u1 = (x1 * z2z2) % p
    u2 = (x2 * z1z1) % p
    s1 = (y1 * z2 * z2z2) % p
    s2 = (y2 * z1 * z1z1) % p
    if u1 == u2:
        if s1 != s2:
            return (0, 1, 0)
        return _p256_jdouble(pt1)
    h = (u2 - u1) % p
    i = (4 * h * h) % p
    j = (h * i) % p
    r = (2 * (s2 - s1)) % p
    v = (u1 * i) % p
    x3 = (r * r - j - 2 * v) % p
    y3 = (r * (v - x3) - 2 * s1 * j) % p
    z3 = (((z1 + z2) ** 2 - z1z1 - z2z2) * h) % p
    return (x3, y3, z3)


def _p256_point_mul(k: int, x: int = _P256_GX, y: int = _P256_GY) -> tuple[int, int]:
    """Scalar multiplication k * (x, y) on NIST P-256 returning affine (x, y)."""
    res = (0, 1, 0)
    addend = (x % _P256_P, y % _P256_P, 1)
    n = k
    while n:
        if n & 1:
            res = _p256_jadd(res, addend)
        addend = _p256_jdouble(addend)
        n >>= 1
    rx, ry, rz = res
    if rz == 0:
        raise ValueError("Point at infinity")
    zinv = pow(rz, _P256_P - 2, _P256_P)
    zinv2 = (zinv * zinv) % _P256_P
    zinv3 = (zinv2 * zinv) % _P256_P
    return ((rx * zinv2) % _P256_P, (ry * zinv3) % _P256_P)


def generate_wireguard_keypair(prefer_cryptography: bool = True) -> tuple[str, str]:
    """Generate a WireGuard X25519 keypair, returning (private_b64, public_b64)."""
    if prefer_cryptography and _HAS_CRYPTOGRAPHY:
        priv = _crypto_x25519.X25519PrivateKey.generate()
        priv_raw = priv.private_bytes(
            _crypto_serialization.Encoding.Raw,
            _crypto_serialization.PrivateFormat.Raw,
            _crypto_serialization.NoEncryption(),
        )
        pub_raw = priv.public_key().public_bytes(
            _crypto_serialization.Encoding.Raw,
            _crypto_serialization.PublicFormat.Raw,
        )
        return base64.b64encode(priv_raw).decode("ascii"), base64.b64encode(pub_raw).decode("ascii")

    priv_buf = bytearray(secrets.token_bytes(32))
    priv_buf[0] &= 248
    priv_buf[31] &= 127
    priv_buf[31] |= 64
    priv_bytes = bytes(priv_buf)
    pub_bytes = _x25519_scalar_mult(priv_bytes)
    return base64.b64encode(priv_bytes).decode("ascii"), base64.b64encode(pub_bytes).decode("ascii")


def generate_ec_p256_keypair(prefer_cryptography: bool = True) -> tuple[str, str]:
    """Generate an ECDSA P-256 keypair, returning (pkcs8_pem, spki_b64)."""
    if prefer_cryptography and _HAS_CRYPTOGRAPHY:
        priv = _crypto_ec.generate_private_key(_crypto_ec.SECP256R1())
        pkcs8_pem = priv.private_bytes(
            _crypto_serialization.Encoding.PEM,
            _crypto_serialization.PrivateFormat.PKCS8,
            _crypto_serialization.NoEncryption(),
        ).decode("ascii")
        spki_der = priv.public_key().public_bytes(
            _crypto_serialization.Encoding.DER,
            _crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pkcs8_pem, base64.b64encode(spki_der).decode("ascii")

    d = secrets.randbelow(_P256_N - 1) + 1
    px, py = _p256_point_mul(d)
    d_bytes = d.to_bytes(32, "big")
    pub_point = b"\x04" + px.to_bytes(32, "big") + py.to_bytes(32, "big")
    spki_der = _P256_SPKI_PREFIX + pub_point

    ec_priv_body = (
        b"\x02\x01\x01"
        + b"\x04\x20" + d_bytes
        + b"\xa1\x44\x03\x42\x00" + pub_point
    )
    ec_priv_der = b"\x30\x6b" + ec_priv_body  # 3 + 34 + 70 = 107 = 0x6b
    pkcs8_body = (
        b"\x02\x01\x00"
        + bytes.fromhex("301306072a8648ce3d020106082a8648ce3d030107")
        + b"\x04\x6d" + ec_priv_der  # 2 + 109 = 111 = 0x6f? Wait 109 = 0x6d!
    )
    pkcs8_der = b"\x30\x81\x87" + pkcs8_body  # 3 + 21 + 111 = 135 = 0x87
    b64_pem = base64.b64encode(pkcs8_der).decode("ascii")
    pem_lines = [b64_pem[i:i + 64] for i in range(0, len(b64_pem), 64)]
    pkcs8_pem = "-----BEGIN PRIVATE KEY-----\n" + "\n".join(pem_lines) + "\n-----END PRIVATE KEY-----\n"
    return pkcs8_pem, base64.b64encode(spki_der).decode("ascii")


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
        self.max_live_generations: int = 4
        self.compact_window: str = ""  # "" = manual-only (--compact), or "HH:MM-HH:MM"
        # Protocol & fresh-identity enrollment settings
        self.prefer_protocol: str = "wireguard"  # "wireguard" or "masque"
        self.masque_alpn: list[str] = ["h3"]
        self.identity_escalate_window: int = 1800
        self.identity_max_age_hours: float = 0.0
        self.latency_degrade_factor: float = 3.0
        self.max_registrations_per_hour: int = 6
        self.warp_license: str = ""
        self.live_remove_supported: bool = False
        self._loaded_sig: Optional[tuple[int, int]] = None

    def reload_if_newer(self) -> bool:
        sig = _file_sig(self.path)
        if sig is not None and sig != self._loaded_sig:
            return self.load()
        return False

    @staticmethod
    def _parse_masque_alpn(raw: Any) -> list[str]:
        if isinstance(raw, str):
            items = [x.strip().lower() for x in raw.split(",") if x.strip()]
        elif isinstance(raw, list):
            items = [str(x).strip().lower() for x in raw if str(x).strip()]
        else:
            items = []
        valid = [x for x in items if x in ("h3", "h2")]
        seen: list[str] = []
        for x in valid:
            if x not in seen:
                seen.append(x)
        return seen or ["h3"]

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
            self.max_live_generations = max(1, int(data.get("max_live_generations", 4)))
            self.compact_window = str(data.get("compact_window", "")).strip()

            pref = str(data.get("prefer_protocol", "wireguard")).strip().lower()
            self.prefer_protocol = pref if pref in ("wireguard", "masque") else "wireguard"
            self.masque_alpn = self._parse_masque_alpn(data.get("masque_alpn", ["h3"]))
            self.identity_escalate_window = max(0, int(data.get("identity_escalate_window", 1800)))
            self.identity_max_age_hours = max(0.0, float(data.get("identity_max_age_hours", 0.0)))
            self.latency_degrade_factor = max(0.0, float(data.get("latency_degrade_factor", 3.0)))
            self.max_registrations_per_hour = max(1, int(data.get("max_registrations_per_hour", 6)))
            self.warp_license = str(data.get("warp_license", "")).strip()
            self.live_remove_supported = bool(data.get("live_remove_supported", False))
            self._loaded_sig = _file_sig(self.path)
            return bool(self.panel_url and self.username and self.password)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
            logger.error(f"Failed to parse config: {e}")
            return False

    def save(self):
        """Save config to file with restricted permissions."""
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
            "prefer_protocol": self.prefer_protocol,
            "masque_alpn": self.masque_alpn,
            "identity_escalate_window": self.identity_escalate_window,
            "identity_max_age_hours": self.identity_max_age_hours,
            "latency_degrade_factor": self.latency_degrade_factor,
            "max_registrations_per_hour": self.max_registrations_per_hour,
            "warp_license": self.warp_license,
            "live_remove_supported": self.live_remove_supported,
        }
        _atomic_write_text(self.path, json.dumps(data, indent=2))
        self._loaded_sig = _file_sig(self.path)
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
        # "core_id:base_tag" -> "endpoint" | "identity" | "masque"
        self.last_rotation_mode: dict[str, str] = {}
        # "core_id:base_tag" -> rolling list of healthy latency samples (ms)
        self.latency_history: dict[str, list[int]] = {}
        # "core_id:outbound_tag" -> unix timestamp when WARP identity was created
        self.identity_created_ts: dict[str, float] = {}
        # unix timestamps of Cloudflare WARP registrations (rolling 1-hour window)
        self.registration_timestamps: list[float] = []
        self._loaded_sig: Optional[tuple[int, int]] = None

    def reload_if_newer(self) -> bool:
        sig = _file_sig(self.path)
        if sig is not None and sig != self._loaded_sig:
            self.load()
            return True
        return False

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
            self.last_rotation_mode = {
                str(k): str(v) for k, v in raw.get("last_rotation_mode", {}).items()
            }
            self.latency_history = {
                str(k): [int(x) for x in v if isinstance(x, (int, float))][-20:]
                for k, v in raw.get("latency_history", {}).items()
                if isinstance(v, list)
            }
            self.identity_created_ts = {
                str(k): float(v) for k, v in raw.get("identity_created_ts", {}).items()
            }
            self.registration_timestamps = [
                float(x) for x in raw.get("registration_timestamps", [])
                if isinstance(x, (int, float))
            ]
            self._loaded_sig = _file_sig(self.path)
        except (json.JSONDecodeError, ValueError, TypeError):
            self._hashes = {}

    def save(self):
        try:
            payload = {
                "hashes": self._hashes,
                "active_generations": self.active_generations,
                "fail_counts": self.fail_counts,
                "last_refresh_ts": self.last_refresh_ts,
                "endpoint_cursor": self.endpoint_cursor,
                "last_compact_date": self.last_compact_date,
                "last_rotation_mode": self.last_rotation_mode,
                "latency_history": self.latency_history,
                "identity_created_ts": self.identity_created_ts,
                "registration_timestamps": self.prune_registrations(),
            }
            _atomic_write_text(self.path, json.dumps(payload, indent=2))
            self._loaded_sig = _file_sig(self.path)
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
            "last_rotation_mode": self.last_rotation_mode,
            "latency_history": self.latency_history,
            "identity_created_ts": self.identity_created_ts,
            "registration_timestamps": self.registration_timestamps,
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
        self.last_rotation_mode = cp.get("last_rotation_mode", {})
        self.latency_history = cp.get("latency_history", {})
        self.identity_created_ts = cp.get("identity_created_ts", {})
        self.registration_timestamps = cp.get("registration_timestamps", [])

    def record_latency_sample(self, core_id: int, base_tag: str, latency_ms: int, max_samples: int = 20):
        """Record a healthy latency sample for a WARP slot (rolling window)."""
        if latency_ms <= 0:
            return
        key = f"{core_id}:{base_tag}"
        hist = self.latency_history.setdefault(key, [])
        hist.append(int(latency_ms))
        if len(hist) > max_samples:
            del hist[:-max_samples]

    def get_latency_baseline(self, core_id: int, base_tag: str, min_samples: int = 3) -> Optional[float]:
        """Return the rolling median healthy latency (ms), or None if fewer than `min_samples`."""
        hist = self.latency_history.get(f"{core_id}:{base_tag}", [])
        if len(hist) < min_samples:
            return None
        return float(statistics.median(hist))

    def prune_registrations(self, now: Optional[float] = None) -> list[float]:
        """Keep registration timestamps within the last 3600 seconds."""
        t = time.time() if now is None else now
        cutoff = t - 3600.0
        self.registration_timestamps = [ts for ts in self.registration_timestamps if ts >= cutoff]
        return list(self.registration_timestamps)

    def can_register(self, max_per_hour: int, now: Optional[float] = None) -> tuple[bool, int]:
        """Check hourly Cloudflare registration budget; returns (allowed, wait_seconds)."""
        t = time.time() if now is None else now
        recent = self.prune_registrations(t)
        if len(recent) < max(1, max_per_hour):
            return True, 0
        oldest = min(recent)
        wait_sec = max(1, int(oldest + 3600.0 - t))
        return False, wait_sec

    def record_registration(self, now: Optional[float] = None):
        """Record a successful/attempted Cloudflare WARP registration timestamp."""
        t = time.time() if now is None else now
        self.prune_registrations(t)
        self.registration_timestamps.append(t)

    def next_wg_endpoint(
        self,
        exclude_endpoints: set[str],
        avoid_prefixes: Optional[set[str]] = None,
    ) -> str:
        """
        Select the next Cloudflare WARP WireGuard endpoint.
        Preference order:
          1. Not already used AND not in an unreachable /24 (`avoid_prefixes`)
          2. Not in an unreachable /24 (may share an edge with a healthy slot)
          3. Not already used
          4. Plain round-robin
        """
        avoid = avoid_prefixes or set()
        total = len(WARP_WG_ENDPOINTS)

        def pick(predicate) -> Optional[str]:
            for offset in range(total):
                idx = (self.endpoint_cursor + offset) % total
                candidate = WARP_WG_ENDPOINTS[idx]
                if predicate(candidate):
                    self.endpoint_cursor = (idx + 1) % total
                    return candidate
            return None

        for predicate in (
            lambda c: c not in exclude_endpoints and endpoint_prefix24(c) not in avoid,
            lambda c: endpoint_prefix24(c) not in avoid,
            lambda c: c not in exclude_endpoints,
        ):
            chosen = pick(predicate)
            if chosen:
                return chosen

        candidate = WARP_WG_ENDPOINTS[self.endpoint_cursor % total]
        self.endpoint_cursor = (self.endpoint_cursor + 1) % total
        return candidate


# ---------------------------------------------------------------------------
# Cloudflare WARP Device Store & Enrollment Client (3x-ui compatible)
# ---------------------------------------------------------------------------
class WarpRegistrationError(RuntimeError):
    """Raised when Cloudflare WARP device enrollment fails."""


class WarpRateLimitError(WarpRegistrationError):
    """Raised when Cloudflare API returns 429 Too Many Requests."""

    def __init__(self, retry_after_sec: int, message: str):
        super().__init__(message)
        self.retry_after_sec = retry_after_sec


class WarpDeviceStore:
    """
    Persists enrolled Cloudflare WARP device credentials per (core_id, slot)
    at /etc/pasarguard-route-manager/warp_devices.json with 0600 permissions.
    Credentials are never logged.
    """

    def __init__(self, path: Path = WARP_DEVICES_FILE):
        self.path = path
        self.devices: dict[str, dict[str, Any]] = {}
        self._loaded_sig: Optional[tuple[int, int]] = None

    @staticmethod
    def _slot_key(core_id: int, base_tag: str) -> str:
        return f"{core_id}:{base_tag}"

    def reload_if_newer(self) -> bool:
        sig = _file_sig(self.path)
        if sig is not None and sig != self._loaded_sig:
            self.load()
            return True
        return False

    def load(self):
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                devs = raw.get("devices", raw)
                if isinstance(devs, dict):
                    self.devices = {
                        str(k): dict(v)
                        for k, v in devs.items()
                        if isinstance(v, dict)
                    }
                    self._loaded_sig = _file_sig(self.path)
        except (json.JSONDecodeError, OSError, TypeError, ValueError) as e:
            logger.debug(f"Could not read WARP device store ({self.path}): {e}")

    def save(self):
        try:
            payload = {"devices": self.devices}
            _atomic_write_text(self.path, json.dumps(payload, indent=2))
            self._loaded_sig = _file_sig(self.path)
        except OSError as e:
            logger.debug(f"Skipping WARP device store save ({self.path}): {e}")

    def get(self, core_id: int, base_tag: str) -> Optional[dict[str, Any]]:
        rec = self.devices.get(self._slot_key(core_id, base_tag))
        return copy.deepcopy(rec) if isinstance(rec, dict) else None

    def put(self, core_id: int, base_tag: str, record: dict[str, Any]):
        self.devices[self._slot_key(core_id, base_tag)] = copy.deepcopy(record)

    def snapshot(self) -> dict[str, Any]:
        return copy.deepcopy(self.devices)

    def restore(self, snap: dict[str, Any]):
        self.devices = copy.deepcopy(snap)


class WarpRegistrar:
    """
    Zero-dependency Cloudflare WARP / WARP-over-MASQUE device registrar modeled
    directly after 3x-ui's WarpService (RegWarp + RegWarpMasque + SetWarpLicense).
    Runs 100% locally on the Panel host with zero central proxy or node SSH.
    """

    def __init__(self, http_client: Optional[httpx.Client] = None):
        self._external_client = http_client

    def _client_ctx(self):
        if self._external_client is not None:
            return _NullClientCtx(self._external_client)
        return httpx.Client(timeout=20.0, follow_redirects=False)

    @staticmethod
    def _headers(client_ver: str, bearer_token: str = "") -> dict[str, str]:
        hdrs = {
            "Content-Type": "application/json",
            "CF-Client-Version": client_ver,
            "User-Agent": CF_WARP_USER_AGENT,
        }
        if bearer_token:
            hdrs["Authorization"] = f"Bearer {bearer_token}"
        return hdrs

    @staticmethod
    def _request_json(
        client: httpx.Client,
        method: str,
        url: str,
        headers: dict[str, str],
        payload: Optional[dict] = None,
    ) -> dict[str, Any]:
        try:
            resp = client.request(method, url, headers=headers, json=payload)
        except httpx.RequestError as e:
            raise WarpRegistrationError(f"Cloudflare API network error: {type(e).__name__}") from e

        if resp.status_code == 429:
            retry_hdr = resp.headers.get("Retry-After", "60")
            try:
                retry_sec = max(1, int(float(retry_hdr)))
            except ValueError:
                retry_sec = 60
            raise WarpRateLimitError(
                retry_sec,
                f"Cloudflare API rate-limited (HTTP 429, Retry-After={retry_sec}s)",
            )
        if resp.status_code >= 400:
            raise WarpRegistrationError(f"Cloudflare API returned HTTP {resp.status_code}")

        try:
            data = resp.json()
        except ValueError as e:
            raise WarpRegistrationError("Cloudflare API returned invalid JSON") from e
        if not isinstance(data, dict):
            raise WarpRegistrationError("Cloudflare API returned unexpected payload type")
        return data

    @staticmethod
    def _extract_addresses(cfg: dict) -> list[str]:
        iface_addrs = (cfg.get("interface") or {}).get("addresses") or {}
        addrs: list[str] = []
        v4 = str(iface_addrs.get("v4", "")).strip()
        v6 = str(iface_addrs.get("v6", "")).strip()
        if v4:
            addrs.append(v4 if "/" in v4 else f"{v4}/32")
        if v6:
            addrs.append(v6 if "/" in v6 else f"{v6}/128")
        return addrs

    @staticmethod
    def _extract_peer(cfg: dict) -> tuple[str, str]:
        peers = cfg.get("peers") or []
        peer = peers[0] if peers and isinstance(peers[0], dict) else {}
        peer_pub = str(peer.get("public_key", "")).strip()
        ep_obj = peer.get("endpoint") or {}
        ep_v4 = str(ep_obj.get("v4") or ep_obj.get("host") or "").strip()
        return peer_pub, ep_v4

    @staticmethod
    def _extract_ip_host(endpoint: str, default_ip: str) -> str:
        raw = str(endpoint or "").strip()
        if not raw:
            return default_ip
        host = raw.rsplit(":", 1)[0].strip("[]") if ":" in raw else raw.strip("[]")
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            return default_ip

    @staticmethod
    def _decode_reserved(client_id: str) -> Optional[list[int]]:
        cleaned = str(client_id or "").strip()
        if not cleaned:
            return None
        try:
            padded = cleaned + "=" * (-len(cleaned) % 4)
            raw = base64.b64decode(padded)
            if len(raw) >= 3:
                return [int(raw[0]), int(raw[1]), int(raw[2])]
        except Exception:
            pass
        return None

    def _apply_license(
        self,
        client: httpx.Client,
        api_base: str,
        client_ver: str,
        account_id: str,
        token: str,
        license_key: str,
    ) -> Optional[dict[str, Any]]:
        key = str(license_key or "").strip()
        if not key:
            return None
        hdrs = self._headers(client_ver, token)
        self._request_json(
            client,
            "PUT",
            f"{api_base}/reg/{account_id}/account",
            headers=hdrs,
            payload={"license": key},
        )
        return self._request_json(
            client,
            "GET",
            f"{api_base}/reg/{account_id}",
            headers=hdrs,
        )

    def register_wireguard(self, license_key: str = "") -> dict[str, Any]:
        """Register a new Cloudflare WARP WireGuard device via v0a4005 API."""
        wg_priv, wg_pub = generate_wireguard_keypair()
        hostname = (socket.gethostname() or "pg-addon")[:32]
        tos = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        with self._client_ctx() as client:
            data = self._request_json(
                client,
                "POST",
                f"{CF_WARP_WG_API_BASE}/reg",
                headers=self._headers(CF_WARP_WG_CLIENT_VER),
                payload={
                    "key": wg_pub,
                    "tos": tos,
                    "type": "PC",
                    "model": "pg-addon",
                    "name": hostname,
                },
            )
            account_id = str(data.get("id", "")).strip()
            token = str(data.get("token", "")).strip()
            if not account_id or not token:
                raise WarpRegistrationError("Cloudflare WireGuard registration returned no id/token")

            if license_key:
                licensed = self._apply_license(
                    client, CF_WARP_WG_API_BASE, CF_WARP_WG_CLIENT_VER, account_id, token, license_key
                )
                if licensed:
                    data = licensed

        cfg = data.get("config") or {}
        addresses = self._extract_addresses(cfg)
        peer_pub, ep_v4 = self._extract_peer(cfg)
        if not addresses or not peer_pub:
            raise WarpRegistrationError("Cloudflare WireGuard registration missing addresses or peer key")

        ep_ip = self._extract_ip_host(ep_v4, "162.159.192.1")
        reserved = self._decode_reserved(str(cfg.get("client_id", "")))
        return {
            "protocol": "wireguard",
            "account_id": account_id,
            "access_token": token,
            "device_name": hostname,
            "license_key": license_key.strip(),
            "created_at": time.time(),
            "wg_private_key": wg_priv,
            "wg_public_key": wg_pub,
            "peer_public_key": peer_pub,
            "addresses": addresses,
            "reserved": reserved,
            "endpoint": f"{ep_ip}:2408",
        }

    def register_masque(self, license_key: str = "") -> dict[str, Any]:
        """Register & enroll a new Cloudflare WARP-over-MASQUE device (v0a4471 + secp256r1)."""
        wg_priv, wg_pub = generate_wireguard_keypair()
        p256_pem, p256_spki_b64 = generate_ec_p256_keypair()
        hostname = (socket.gethostname() or "pg-addon")[:32]
        tos = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        with self._client_ctx() as client:
            reg_data = self._request_json(
                client,
                "POST",
                f"{CF_WARP_MASQUE_API_BASE}/reg",
                headers=self._headers(CF_WARP_MASQUE_CLIENT_VER),
                payload={
                    "key": wg_pub,
                    "tos": tos,
                    "type": "PC",
                    "model": "pg-addon",
                    "name": hostname,
                },
            )
            account_id = str(reg_data.get("id", "")).strip()
            token = str(reg_data.get("token", "")).strip()
            if not account_id or not token:
                raise WarpRegistrationError("Cloudflare MASQUE registration returned no id/token")

            if license_key:
                self._apply_license(
                    client, CF_WARP_MASQUE_API_BASE, CF_WARP_MASQUE_CLIENT_VER, account_id, token, license_key
                )

            hdrs = self._headers(CF_WARP_MASQUE_CLIENT_VER, token)
            data = self._request_json(
                client,
                "PATCH",
                f"{CF_WARP_MASQUE_API_BASE}/reg/{account_id}",
                headers=hdrs,
                payload={
                    "key": p256_spki_b64,
                    "key_type": "secp256r1",
                    "tunnel_type": "masque",
                    "name": hostname,
                },
            )
            if data.get("warp_enabled") is False:
                data = self._request_json(
                    client,
                    "PATCH",
                    f"{CF_WARP_MASQUE_API_BASE}/reg/{account_id}",
                    headers=hdrs,
                    payload={"warp_enabled": True},
                )

        cfg = data.get("config") or {}
        addresses = self._extract_addresses(cfg)
        peer_pub, ep_v4 = self._extract_peer(cfg)
        if not addresses or not peer_pub:
            raise WarpRegistrationError("Cloudflare MASQUE enrollment missing addresses or peer key")

        ep_ip = self._extract_ip_host(ep_v4, "162.159.198.2")
        return {
            "protocol": "masque",
            "account_id": account_id,
            "access_token": token,
            "device_name": hostname,
            "license_key": license_key.strip(),
            "created_at": time.time(),
            "wg_private_key": wg_priv,
            "p256_private_pem": p256_pem,
            "peer_public_key": peer_pub,
            "addresses": addresses,
            "endpoint_ip": ep_ip,
            "endpoint": f"{ep_ip}:443",
        }

    @staticmethod
    def build_masque_outbound(
        tag: str,
        record: dict[str, Any],
        port: int = 443,
        alpn: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """
        Build an Xray >= 26.10.21 WARP-over-MASQUE outbound JSON matching 3x-ui / Xray spec.
        Omits `xmux` intentionally so Xray uses `defaultMasqueXmux()` (`maxConnections: 1`, 1800-3000s).
        """
        addr = str(
            record.get("endpoint_ip")
            or WarpRegistrar._extract_ip_host(str(record.get("endpoint", "")), "162.159.198.2")
        ).strip()
        return {
            "tag": tag,
            "protocol": "masque",
            "settings": {
                "address": addr,
                "port": int(port or 443),
            },
            "streamSettings": {
                "network": "masque",
                "security": "tls",
                "tlsSettings": {
                    "serverName": CF_WARP_MASQUE_SNI,
                    "alpn": list(alpn or ["h3"]),
                },
                "masqueSettings": {
                    "warp": {
                        "privateKey": str(record["p256_private_pem"]),
                        "publicKey": str(record["peer_public_key"]),
                        "address": list(record["addresses"]),
                    }
                },
            },
        }

    @staticmethod
    def build_wireguard_outbound(
        tag: str,
        record: dict[str, Any],
        endpoint: str,
        keepalive: int = 0,
    ) -> dict[str, Any]:
        """Build a userspace WireGuard outbound matching 3x-ui & Xray-core requirements."""
        peer: dict[str, Any] = {
            "endpoint": endpoint,
            "publicKey": str(record["peer_public_key"]),
        }
        if keepalive > 0:
            peer["keepAlive"] = int(keepalive)

        settings: dict[str, Any] = {
            "secretKey": str(record["wg_private_key"]),
            "address": list(record["addresses"]),
            "peers": [peer],
            "mtu": 1280,
            "noKernelTun": True,
            "targetStrategy": "ForceIPv4v6",
        }
        if record.get("reserved"):
            settings["reserved"] = list(record["reserved"])

        return {
            "tag": tag,
            "protocol": "wireguard",
            "settings": settings,
            "streamSettings": {
                "sockopt": {
                    "domainStrategy": "ForceIPv4v6",
                }
            },
        }


class _NullClientCtx:
    """Context manager wrapper for externally supplied httpx.Client."""

    def __init__(self, client: httpx.Client):
        self._client = client

    def __enter__(self) -> httpx.Client:
        return self._client

    def __exit__(self, *args):
        return False


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
    def check(
        cls,
        before_config: dict,
        after_config: dict,
        live_remove_supported: bool = False,
    ) -> tuple[bool, str]:
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

        def _removable(ob: dict) -> bool:
            if cls._is_outbound_safe_to_remove(ob):
                return True
            if live_remove_supported:
                return str(ob.get("protocol", "")).strip().lower() in ("wireguard", "masque")
            return False

        # Default outbound (index 0) cannot move if old[0] or new[0] is non-removable
        old_default = old_out[0]["tag"]
        new_default = new_out[0]["tag"]
        if old_default != new_default:
            if not _removable(old_by_tag[old_default]):
                return False, f"default outbound '{old_default}' moved and is not live-removable"
            if new_default in old_by_tag and not _removable(old_by_tag[new_default]):
                return False, f"new default outbound '{new_default}' existed and is not live-removable"

        # Every non-removable outbound (wireguard, masque, etc.) in old_out MUST still
        # exist in new_out with exact identical JSON contents unless live_remove_supported is enabled.
        for tag, old_ob in old_by_tag.items():
            if tag not in new_by_tag:
                if not _removable(old_ob):
                    return False, f"non-removable outbound '{tag}' ({old_ob.get('protocol')}) was deleted"
                continue
            new_ob = new_by_tag[tag]
            if old_ob != new_ob and not _removable(old_ob):
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
    def _clean_partial_masque_xmux(ob: dict) -> bool:
        """
        Remove partial `xmux` objects that set `hMaxReusableSecs` without `maxConnections`
        or `maxConcurrency`, which silently bypass Xray's `defaultMasqueXmux()`.
        Returns True if a partial `xmux` was stripped.
        """
        if str(ob.get("protocol", "")).lower() != "masque":
            return False
        stream = ob.get("streamSettings")
        if not isinstance(stream, dict):
            return False
        ms = stream.get("masqueSettings")
        if not isinstance(ms, dict):
            return False
        xmux = ms.get("xmux")
        if (
            isinstance(xmux, dict)
            and "hMaxReusableSecs" in xmux
            and not xmux.get("maxConnections")
            and not xmux.get("maxConcurrency")
        ):
            ms.pop("xmux", None)
            return True
        return False

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
        avoid_prefixes: Optional[set[str]] = None,
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
            # Harden MTU; omit keepAlive on spawned generations so retired stacks stop pinging once idle.
            # Active slots are kept warm by Xray Observatory pings every 20s.
            mtu = settings.get("mtu", 0)
            if not isinstance(mtu, int) or mtu <= 0 or mtu > 1280:
                settings["mtu"] = 1280
            peers = settings.get("peers") or []
            if peers and isinstance(peers[0], dict):
                chosen_endpoint = self.state.next_wg_endpoint(used_endpoints, avoid_prefixes)
                peers[0]["endpoint"] = chosen_endpoint
                peers[0].pop("keepAlive", None)

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

            # Remove any partial xmux override so Xray applies defaultMasqueXmux() (maxConnections=1, 1800-3000s)
            self._clean_partial_masque_xmux(template)

        else:
            chosen_endpoint = self.get_outbound_endpoint(template)

        return template, chosen_endpoint

    def poll_core_observatory(
        self,
        client: PanelClient,
        core_id: int,
        nodes: list[dict],
        core_config: Optional[dict] = None,
    ) -> dict[str, list[dict]]:
        """
        Poll /outbounds_latency across all connected nodes assigned to `core_id`.
        Returns {outbound_tag: [{"node": name, "node_id": id, "alive": bool, "delay": int, "probed": bool}, ...]}.

        Note: Xray's `burstObservatory` always reports `last_try_time == 0`
        (app/observatory/burst/burstobserver.go) but only creates an entry after a
        real ping result, so every entry from a burst-only core counts as probed.
        """
        burst_only = False
        if isinstance(core_config, dict):
            obs = core_config.get("observatory")
            burst = core_config.get("burstObservatory")
            burst_only = bool(isinstance(burst, dict) and burst and not (isinstance(obs, dict) and obs))

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
                probed = last_try > 0 or burst_only or (alive and delay > 0)
                by_tag.setdefault(tag, []).append({
                    "node": nname,
                    "node_id": nid,
                    "alive": alive,
                    "delay": delay,
                    "probed": probed,
                })
        return by_tag

    def is_tag_degraded(
        self,
        observations: list[dict],
        baseline_ms: Optional[float] = None,
    ) -> tuple[bool, str]:
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

        factor = self.config.latency_degrade_factor
        if factor > 0 and baseline_ms is not None and baseline_ms > 0:
            threshold = max(250.0, baseline_ms * factor)
            slow_rel = [
                f"{o['node']} ({o['delay']}ms)"
                for o in probed
                if o["delay"] > threshold
            ]
            if slow_rel:
                return (
                    True,
                    f"latency spike > {int(threshold)}ms ({factor:.1f}x baseline {int(baseline_ms)}ms) on {', '.join(slow_rel)}",
                )

        return False, "healthy"

    def is_tag_confirmed_healthy(
        self,
        observations: list[dict],
        baseline_ms: Optional[float] = None,
    ) -> bool:
        """Return True if at least one node probed the tag and ALL probed nodes report it healthy."""
        probed = [o for o in observations if o.get("probed")]
        if not probed:
            return False
        degraded, _ = self.is_tag_degraded(probed, baseline_ms=baseline_ms)
        return not degraded

    def find_unreachable_prefixes(
        self, outbounds: list[dict], telemetry: Optional[dict[str, list[dict]]]
    ) -> set[str]:
        """
        Return IPv4 /24 networks where every probed WARP outbound is degraded and
        none is healthy (e.g. a Cloudflare edge block unreachable from the node).
        """
        if not telemetry:
            return set()
        dead: dict[str, int] = {}
        healthy: dict[str, int] = {}
        for ob in outbounds:
            if not isinstance(ob, dict):
                continue
            tag = str(ob.get("tag", ""))
            if not is_warp_tag(tag, self.config.warp_prefix):
                continue
            prefix = endpoint_prefix24(self.get_outbound_endpoint(ob))
            if not prefix:
                continue
            obs = telemetry.get(tag, [])
            if not any(o.get("probed") for o in obs):
                continue
            if self.is_tag_degraded(obs)[0]:
                dead[prefix] = dead.get(prefix, 0) + 1
            else:
                healthy[prefix] = healthy.get(prefix, 0) + 1
        return {p for p in dead if healthy.get(p, 0) == 0}

    @staticmethod
    def _pick_masque_port(edge_ip: str, used_endpoints: set[str], preferred_port: int = 443) -> int:
        if f"{edge_ip}:{preferred_port}" not in used_endpoints:
            return preferred_port
        for cand_port in WARP_MASQUE_PORTS:
            if f"{edge_ip}:{cand_port}" not in used_endpoints:
                return cand_port
        return preferred_port

    def _spawn_fresh_identity_outbound(
        self,
        core_id: int,
        base_tag: str,
        gens: dict[int, dict],
        all_outbounds: list[dict],
        avoid_prefixes: set[str],
        registrar: WarpRegistrar,
        device_store: Optional[WarpDeviceStore],
        masque_ready: bool,
        license_key: str,
        now: float,
    ) -> tuple[dict, str, str]:
        """
        Register a brand-new Cloudflare WARP identity (WireGuard or MASQUE) and build
        the next `base_tag__rNNNN` outbound. Returns (outbound_dict, endpoint, used_mode).
        """
        allowed, wait_sec = self.state.can_register(self.config.max_registrations_per_hour, now)
        if not allowed:
            raise WarpRateLimitError(
                wait_sec,
                f"hourly Cloudflare registration limit ({self.config.max_registrations_per_hour}/hr) reached; retry in {wait_sec}s",
            )

        latest_gen = max(gens.keys())
        new_tag = format_generation_tag(base_tag, latest_gen + 1)
        cur_proto = str(gens[latest_gen].get("protocol", "wireguard")).lower()
        used_endpoints = self._collect_used_endpoints(all_outbounds)

        want_masque = False
        if self.config.prefer_protocol == "masque":
            if masque_ready:
                want_masque = True
            else:
                logger.warning(
                    f"Core id={core_id}: prefer_protocol='masque' requested for '{base_tag}', "
                    f"but assigned node(s) lack Xray >= 26.10.21; registering WireGuard identity instead"
                )
        elif cur_proto == "masque" and masque_ready:
            want_masque = True

        self.state.record_registration(now)
        eff_license = (license_key or self.config.warp_license or "").strip()

        if want_masque:
            rec = registrar.register_masque(license_key=eff_license)
            if device_store is not None:
                device_store.put(core_id, base_tag, rec)
            port = self._pick_masque_port(rec["endpoint_ip"], used_endpoints)
            new_ob = registrar.build_masque_outbound(
                new_tag, rec, port=port, alpn=self.config.masque_alpn
            )
            new_ep = f"{rec['endpoint_ip']}:{port}"
            mode = "masque"
        else:
            rec = registrar.register_wireguard(license_key=eff_license)
            if device_store is not None:
                device_store.put(core_id, base_tag, rec)
            new_ep = self.state.next_wg_endpoint(used_endpoints, avoid_prefixes)
            new_ob = registrar.build_wireguard_outbound(
                new_tag, rec, endpoint=new_ep, keepalive=0
            )
            mode = "identity"

        self.state.identity_created_ts[f"{core_id}:{new_tag}"] = now
        return new_ob, new_ep, mode

    def heal_or_refresh_core(
        self,
        core_id: int,
        core_name: str,
        core_config: dict,
        telemetry: dict[str, list[dict]],
        manual_refresh_targets: Optional[set[str]] = None,
        force_spawn: bool = False,
        force_new_identity: bool = False,
        registrar: Optional[WarpRegistrar] = None,
        device_store: Optional[WarpDeviceStore] = None,
        masque_ready: bool = False,
        license_key: str = "",
        dry_run: bool = False,
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
        avoid_prefixes = self.find_unreachable_prefixes(outbounds, telemetry)
        if avoid_prefixes:
            logger.warning(
                f"Core '{core_name}': avoiding unreachable Cloudflare block(s) for new endpoints: "
                f"{', '.join(sorted(avoid_prefixes))}"
            )

        for base_tag, gens in slots.items():
            cur_active = active_map[base_tag]
            cd_key = f"{core_id}:{base_tag}"
            cur_ts_key = f"{core_id}:{cur_active}"
            if self.config.identity_max_age_hours > 0 and cur_ts_key not in self.state.identity_created_ts:
                self.state.identity_created_ts[cur_ts_key] = now

            is_manual = bool(
                manual_refresh_targets
                and ("all" in manual_refresh_targets or base_tag.lower() in manual_refresh_targets)
            )

            should_rotate = False
            want_new_identity = bool(is_manual and force_new_identity)
            is_scheduled_age = False
            trigger_reason = ""

            if is_manual:
                should_rotate = True
                trigger_reason = (
                    "manual --refresh --new-identity request"
                    if want_new_identity
                    else "manual --refresh request"
                )
            elif self.config.auto_heal_warp and telemetry:
                obs = telemetry.get(cur_active, [])
                baseline_ms = self.state.get_latency_baseline(core_id, base_tag)
                degraded, reason = self.is_tag_degraded(obs, baseline_ms=baseline_ms)
                fail_key = f"{core_id}:{cur_active}"
                if degraded:
                    count = self.state.fail_counts.get(fail_key, 0) + 1
                    self.state.fail_counts[fail_key] = count
                    logger.warning(
                        f"Core '{core_name}': WARP '{base_tag}' (active='{cur_active}') "
                        f"unhealthy [{count}/{self.config.fail_threshold}] — {reason}"
                    )
                    if count >= self.config.fail_threshold:
                        elapsed = now - self.state.last_refresh_ts.get(cd_key, 0.0)
                        if elapsed >= self.config.refresh_cooldown:
                            should_rotate = True
                            trigger_reason = f"{count} consecutive failed checks ({reason})"
                            esc_win = self.config.identity_escalate_window
                            prev_mode = self.state.last_rotation_mode.get(cd_key, "")
                            if esc_win > 0 and prev_mode == "endpoint" and elapsed <= esc_win:
                                want_new_identity = True
                                trigger_reason += " → escalating to fresh identity"
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
                    healthy_delays = [
                        int(o["delay"]) for o in obs
                        if o.get("probed") and o.get("alive") and int(o.get("delay", 0)) > 0
                    ]
                    if healthy_delays:
                        self.state.record_latency_sample(
                            core_id, base_tag, int(sum(healthy_delays) / len(healthy_delays))
                        )

            if not should_rotate and self.config.identity_max_age_hours > 0:
                created = self.state.identity_created_ts.get(cur_ts_key, now)
                age_hours = (now - created) / 3600.0
                if age_hours >= self.config.identity_max_age_hours:
                    should_rotate = True
                    want_new_identity = True
                    is_scheduled_age = True
                    trigger_reason = (
                        f"scheduled identity refresh (age {age_hours:.1f}h >= {self.config.identity_max_age_hours:.1f}h)"
                    )

            if not should_rotate:
                continue

            # Step 1: Before spawning a new outbound, check if an ALREADY-EXISTING
            # generation of `base_tag` is confirmed healthy across probed nodes!
            reused_tag: Optional[str] = None
            if not force_spawn and not (is_manual and force_new_identity) and not is_scheduled_age and telemetry:
                cur_ob = next((ob for ob in gens.values() if ob["tag"] == cur_active), gens[max(gens.keys())])
                cur_proto = str(cur_ob.get("protocol", "")).lower()
                reuse_baseline = self.state.get_latency_baseline(core_id, base_tag)
                for gen_num, cand_ob in sorted(gens.items(), reverse=True):
                    cand_tag = cand_ob["tag"]
                    if cand_tag == cur_active:
                        continue
                    # Never silently downgrade an active MASQUE slot back to an old retired WireGuard generation
                    if cur_proto == "masque" and str(cand_ob.get("protocol", "")).lower() != "masque":
                        continue
                    if self.is_tag_confirmed_healthy(telemetry.get(cand_tag, []), baseline_ms=reuse_baseline):
                        reused_tag = cand_tag
                        break

            if reused_tag:
                active_map[base_tag] = reused_tag
                self.state.set_active_tag(core_id, base_tag, reused_tag)
                self.state.fail_counts[f"{core_id}:{cur_active}"] = 0
                self.state.fail_counts[f"{core_id}:{reused_tag}"] = 0
                self.state.last_refresh_ts[cd_key] = now
                self.state.last_rotation_mode[cd_key] = "reuse"
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

            new_ob: Optional[dict] = None
            new_ep = ""
            rot_mode = "endpoint"

            if want_new_identity:
                if dry_run:
                    new_ob, new_ep = self.spawn_rotated_outbound(base_tag, gens, outbounds, avoid_prefixes)
                    rot_mode = self.config.prefer_protocol if masque_ready else "identity"
                    logger.info(
                        f"  [DRY RUN] Would register fresh Cloudflare WARP ({rot_mode}) identity "
                        f"for '{base_tag}' → '{new_ob['tag']}'"
                    )
                elif registrar is None:
                    if is_manual and force_new_identity:
                        logger.error(f"Core '{core_name}': cannot register new identity for '{base_tag}' (no registrar)")
                        continue
                else:
                    try:
                        new_ob, new_ep, rot_mode = self._spawn_fresh_identity_outbound(
                            core_id=core_id,
                            base_tag=base_tag,
                            gens=gens,
                            all_outbounds=outbounds,
                            avoid_prefixes=avoid_prefixes,
                            registrar=registrar,
                            device_store=device_store,
                            masque_ready=masque_ready,
                            license_key=license_key,
                            now=now,
                        )
                    except WarpRegistrationError as e:
                        if is_manual and force_new_identity:
                            logger.error(
                                f"Core '{core_name}': fresh WARP identity registration failed for '{base_tag}': {e}"
                            )
                            continue
                        logger.warning(
                            f"Core '{core_name}': fresh identity registration unavailable for '{base_tag}' "
                            f"({e}); falling back to endpoint rotation"
                        )

            if new_ob is None:
                new_ob, new_ep = self.spawn_rotated_outbound(base_tag, gens, outbounds, avoid_prefixes)
                rot_mode = "endpoint"

            new_tag = new_ob["tag"]
            outbounds.append(new_ob)
            _, new_gen_num = split_generation_tag(new_tag)
            gens[new_gen_num] = new_ob

            active_map[base_tag] = new_tag
            self.state.set_active_tag(core_id, base_tag, new_tag)
            self.state.fail_counts[f"{core_id}:{cur_active}"] = 0
            self.state.fail_counts[f"{core_id}:{new_tag}"] = 0
            self.state.last_refresh_ts[cd_key] = now
            self.state.last_rotation_mode[cd_key] = rot_mode

            logger.info(
                f"Core '{core_name}': Live-spawned fresh WARP outbound '{new_tag}' "
                f"(mode={rot_mode}, endpoint={new_ep}, replaces '{cur_active}') [0 node restarts] ({trigger_reason})"
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
        core_id: Optional[int] = None,
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
        healthy_bases = []
        for b in ordered_bases:
            if not telemetry:
                healthy_bases.append(b)
                continue
            baseline = (
                self.state.get_latency_baseline(core_id, b)
                if core_id is not None
                else None
            )
            if not self.is_tag_degraded(telemetry.get(active_map[b], []), baseline_ms=baseline)[0]:
                healthy_bases.append(b)

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
                if self._clean_partial_masque_xmux(ob):
                    notes.append(
                        f"'{tag}': removed partial MASQUE xmux (restores Xray default maxConnections=1, 1800-3000s)"
                    )

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

        carried_identity_ts: dict[str, float] = {}
        for base_tag, gens in slots.items():
            if len(gens) <= 1 and 0 in gens:
                continue
            act_tag = active_map[base_tag]
            ts_val = self.state.identity_created_ts.get(f"{core_id}:{act_tag}")
            if ts_val:
                carried_identity_ts[f"{core_id}:{base_tag}"] = ts_val
            act_ob = next((ob for ob in gens.values() if ob["tag"] == act_tag), None)
            if act_ob is None:
                act_ob = gens[max(gens.keys())]

            clean_ob = copy.deepcopy(act_ob)
            clean_ob["tag"] = base_tag
            if str(clean_ob.get("protocol", "")).lower() == "wireguard":
                for p in (clean_ob.get("settings", {}) or {}).get("peers") or []:
                    if isinstance(p, dict) and not p.get("keepAlive"):
                        p["keepAlive"] = 20
            else:
                self._clean_partial_masque_xmux(clean_ob)
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
        for k, v in carried_identity_ts.items():
            self.state.identity_created_ts[k] = v

        # Rewrite any rules or managed balancers pointing to `__rNNNN` back to `base_tag`
        active_map = self.resolve_active_tags(core_id, cfg)
        managed_bals, slot_bal_map = self.build_managed_balancers(
            cfg, new_outbounds, active_map, core_id=core_id
        )
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
        device_store: Optional[WarpDeviceStore] = None,
        registrar: Optional[WarpRegistrar] = None,
    ):
        self.client = client
        self.state = state
        self.config = config or Config()
        self.dry_run = dry_run
        self.engine = RoutingEngine()
        self.warp = WarpHealthManager(self.config, self.state)
        self.device_store = device_store if device_store is not None else WarpDeviceStore()
        self.registrar = registrar if registrar is not None else WarpRegistrar()
        self._lock_depth = 0

    @contextlib.contextmanager
    def _exclusive_guard(self):
        """
        Reentrant cross-process lock + external state reload so concurrent CLI writes
        (--migrate-masque, --refresh, --compact) and the background Daemon never
        clobber each other's state or Panel balancers.
        """
        if self.dry_run or self._lock_depth > 0:
            self._lock_depth += 1
            try:
                yield
            finally:
                self._lock_depth -= 1
            return

        with _interprocess_lock(self.state.path.with_suffix(".lock")):
            self._lock_depth += 1
            try:
                self.config.reload_if_newer()
                self.state.reload_if_newer()
                self.device_store.reload_if_newer()
                yield
            finally:
                self._lock_depth -= 1

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
        force_new_identity: bool = False,
        license_key: str = "",
        routing_only: bool = False,
    ) -> int:
        """
        Run a full user-routing sync + zero-downtime WARP health check cycle.

        Returns the number of cores that were updated.
        """
        dry_snap = self.state.snapshot() if self.dry_run else None
        dev_snap = self.device_store.snapshot() if self.dry_run else None
        try:
            with self._exclusive_guard():
                return self._sync_impl(
                    manual_refresh_targets=manual_refresh_targets,
                    core_selector=core_selector,
                    force_spawn=force_spawn,
                    force_new_identity=force_new_identity,
                    license_key=license_key,
                    routing_only=routing_only,
                )
        finally:
            if dry_snap is not None:
                self.state.restore(dry_snap)
            if dev_snap is not None:
                self.device_store.restore(dev_snap)

    def _sync_impl(
        self,
        manual_refresh_targets: Optional[set[str]] = None,
        core_selector: Optional[str] = None,
        force_spawn: bool = False,
        force_new_identity: bool = False,
        license_key: str = "",
        routing_only: bool = False,
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
            if slots and not routing_only and (self.config.auto_heal_warp or manual_refresh_targets):
                telemetry = self.warp.poll_core_observatory(self.client, cid, nodes, core_config=ccfg)

            pre_core_snap = self.state.snapshot()
            masque_ready, _, _ = core_masque_readiness(nodes, cid)
            if routing_only:
                new_outbounds = copy.deepcopy(ccfg.get("outbounds", []))
                active_map = self.warp.resolve_active_tags(cid, ccfg)
                warp_changed = False
            else:
                new_outbounds, active_map, warp_changed = self.warp.heal_or_refresh_core(
                    core_id=cid,
                    core_name=cname,
                    core_config=ccfg,
                    telemetry=telemetry,
                    manual_refresh_targets=manual_refresh_targets,
                    force_spawn=force_spawn,
                    force_new_identity=force_new_identity,
                    registrar=self.registrar,
                    device_store=self.device_store,
                    masque_ready=masque_ready,
                    license_key=license_key,
                    dry_run=self.dry_run,
                )

            managed_bals, slot_balancer_map = self.warp.build_managed_balancers(
                ccfg, new_outbounds, active_map, telemetry=telemetry, core_id=cid
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
        is_safe, unsafe_reason = LiveSafetyValidator.check(
            config,
            updated_config,
            live_remove_supported=self.config.live_remove_supported,
        )
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
        with self._exclusive_guard():
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
        with self._exclusive_guard():
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
            telemetry = self.warp.poll_core_observatory(self.client, cid, nodes, core_config=ccfg)
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

    def _audit_core_warp(
        self,
        core: dict,
        nodes: list[dict],
        users: list[dict],
    ) -> dict[str, Any]:
        """Collect read-only diagnostic audit metrics for one Xray core."""
        cid = core["id"]
        cname = core.get("name", f"core-{cid}")
        ccfg = core.get("config", {})
        slots = self.warp.collect_slots(ccfg.get("outbounds", []))
        active_map = self.warp.resolve_active_tags(cid, ccfg)
        obs_enabled = has_observatory_configured(ccfg)
        masque_ready, blockers, assigned_nodes = core_masque_readiness(nodes, cid)
        telemetry = (
            self.warp.poll_core_observatory(self.client, cid, nodes, core_config=ccfg)
            if slots else {}
        )

        # Map users routed to slots on this core via note directives
        assigned_names = {str(n.get("name", "")).lower() for n in assigned_nodes if n.get("name")}
        routed_counts: dict[str, int] = {b: 0 for b in slots}
        routed_pool = 0
        for u in users:
            for d in parse_routing_directives(u.get("note", "")):
                if d["node"].lower() not in assigned_names:
                    continue
                target = d["outbound"].lower()
                if target == WARP_POOL_TAG:
                    routed_pool += 1
                    continue
                for base_tag in slots:
                    if base_tag.lower() == target:
                        routed_counts[base_tag] += 1
                        break

        fp_groups: dict[str, list[str]] = {}
        ep_groups: dict[str, list[str]] = {}
        slot_reports: list[dict[str, Any]] = []
        bal_selectors: dict[str, str] = {}
        for bal in (ccfg.get("routing") or {}).get("balancers") or []:
            if not isinstance(bal, dict):
                continue
            btag = str(bal.get("tag", ""))
            sels = bal.get("selector") or []
            if btag.startswith(HA_BALANCER_PREFIX) and len(sels) == 1 and isinstance(sels[0], str):
                bal_selectors[btag[len(HA_BALANCER_PREFIX):]] = sels[0]

        for base_tag, gens in slots.items():
            act_tag = active_map[base_tag]
            act_ob = next((ob for ob in gens.values() if ob["tag"] == act_tag), gens[max(gens.keys())])
            proto = str(act_ob.get("protocol", "?")).lower()
            ep = self.warp.get_outbound_endpoint(act_ob) or "-"
            settings = act_ob.get("settings") or {}
            stream = act_ob.get("streamSettings") or {}
            issues: list[str] = []
            bal_sel = bal_selectors.get(base_tag)
            if bal_sel and bal_sel != act_tag:
                issues.append(f"panel balancer routes to '{bal_sel}' vs state '{act_tag}'")

            secret = ""
            if proto == "wireguard":
                secret = str(settings.get("secretKey", ""))
                if settings.get("mtu") != 1280:
                    issues.append(f"mtu={settings.get('mtu')}(want 1280)")
                if not settings.get("noKernelTun"):
                    issues.append("missing noKernelTun=true")
                if not settings.get("reserved"):
                    issues.append("missing reserved")
                sockopt = stream.get("sockopt") or {}
                if not sockopt.get("domainStrategy"):
                    issues.append("missing domainStrategy")
                if "cloudflareclient.com" in ep.lower():
                    issues.append("non-diversified domain endpoint")
            elif proto == "masque":
                warp_blk = (stream.get("masqueSettings") or {}).get("warp") or {}
                secret = str(warp_blk.get("privateKey", ""))
                xmux = (stream.get("masqueSettings") or {}).get("xmux")
                if (
                    isinstance(xmux, dict)
                    and "hMaxReusableSecs" in xmux
                    and not xmux.get("maxConnections")
                    and not xmux.get("maxConcurrency")
                ):
                    issues.append("partial xmux bug (run --optimize-warp)")

            fp = key_fingerprint(secret)
            if fp:
                fp_groups.setdefault(fp, []).append(base_tag)
            if ep and ep != "-":
                ep_groups.setdefault(ep, []).append(base_tag)

            baseline = self.state.get_latency_baseline(cid, base_tag)
            obs_list = telemetry.get(act_tag, [])
            degraded, deg_reason = self.warp.is_tag_degraded(obs_list, baseline_ms=baseline) if obs_list else (False, "no telemetry")

            slot_reports.append({
                "slot": base_tag,
                "active_tag": act_tag,
                "protocol": proto,
                "endpoint": ep,
                "fingerprint": fp,
                "retired": max(0, len(gens) - 1),
                "routed_users": routed_counts.get(base_tag, 0),
                "baseline_ms": baseline,
                "degraded": degraded,
                "health_note": deg_reason,
                "observations": obs_list,
                "issues": issues,
            })

        duplicate_keys = {fp: tags for fp, tags in fp_groups.items() if len(tags) > 1}
        duplicate_eps = {ep: tags for ep, tags in ep_groups.items() if len(tags) > 1}
        for sr in slot_reports:
            fp = sr["fingerprint"]
            if fp in duplicate_keys:
                others = [t for t in duplicate_keys[fp] if t != sr["slot"]]
                sr["issues"].append(f"DUPLICATE IDENTITY with {', '.join(others)} (fp={fp})")
            ep = sr["endpoint"]
            if ep in duplicate_eps:
                others = [t for t in duplicate_eps[ep] if t != sr["slot"]]
                sr["issues"].append(f"shared endpoint with {', '.join(others)}")

        return {
            "core_id": cid,
            "core_name": cname,
            "assigned_nodes": assigned_nodes,
            "masque_ready": masque_ready,
            "masque_blockers": blockers,
            "observatory_enabled": obs_enabled,
            "retired_total": sum(s["retired"] for s in slot_reports),
            "routed_pool_users": routed_pool,
            "slots": slot_reports,
            "duplicate_keys": duplicate_keys,
        }

    def diagnose(self, core_selector: Optional[str] = None) -> dict[str, Any]:
        """
        Read-only diagnostic audit of Xray node versions, duplicate WARP identities,
        tunnel config hygiene, retired generations, latency baselines, and user impact.
        """
        nodes = self.client.get_nodes()
        users = self.client.get_users()
        cores = self._filter_cores(self.client.get_cores(), core_selector)

        reports: list[dict[str, Any]] = []
        print("\n=== PasarGuard WARP & MASQUE Diagnostic Report (read-only) ===")
        for core in cores:
            if str(core.get("type", "xray")).lower() != "xray":
                continue
            rep = self._audit_core_warp(core, nodes, users)
            if not rep["slots"]:
                continue
            reports.append(rep)

            masque_status = "MASQUE-READY" if rep["masque_ready"] else "UPGRADE NEEDED"
            print(
                f"\nCore: {rep['core_name']} (id={rep['core_id']}) | "
                f"Observatory: {'ENABLED' if rep['observatory_enabled'] else 'MISSING'} | "
                f"Xray MASQUE Gate (>=26.10.21): {masque_status}"
            )
            if rep["assigned_nodes"]:
                node_strs = []
                for n in rep["assigned_nodes"]:
                    ok, detail = node_supports_masque(n)
                    tag = "OK" if ok else f"NO({detail})"
                    node_strs.append(f"{n.get('name', n.get('id'))}[{n.get('status', '?')}]={n.get('xray_version') or '?'}:{tag}")
                print("  Nodes: " + ", ".join(node_strs))
            else:
                print("  Nodes: (none assigned)")

            if rep["duplicate_keys"]:
                for fp, tags in rep["duplicate_keys"].items():
                    print(
                        f"  ! CRITICAL DUPLICATE IDENTITY (key fp={fp}): slots {', '.join(tags)} share the same Cloudflare secretKey!"
                    )

            print("-" * 100)
            print(
                f"{'Slot':<10} {'Active':<16} {'Proto':<10} {'Endpoint':<22} {'KeyFP':<13} {'Users':<5} {'BaseMs':<7} {'Issues'}"
            )
            print("-" * 100)
            for s in rep["slots"]:
                base_str = f"{int(s['baseline_ms'])}ms" if s["baseline_ms"] else "-"
                iss_str = "; ".join(s["issues"]) if s["issues"] else ("OK" if not s["degraded"] else s["health_note"])
                print(
                    f"{s['slot']:<10} {s['active_tag']:<16} {s['protocol']:<10} "
                    f"{s['endpoint']:<22} {s['fingerprint'] or '-':<13} "
                    f"{s['routed_users']:<5} {base_str:<7} {iss_str}"
                )

            recs: list[str] = []
            if not rep["observatory_enabled"]:
                recs.append("Run `--optimize-warp` to enable Xray Observatory + HA balancers.")
            if not rep["masque_ready"] and rep["masque_blockers"]:
                recs.append(
                    "Upgrade Xray on node(s) in PasarGuard Panel to >= 26.10.21 before migrating to MASQUE: "
                    + ", ".join(rep["masque_blockers"])
                )
            elif rep["masque_ready"]:
                wg_slots = [s["slot"] for s in rep["slots"] if s["protocol"] == "wireguard"]
                if wg_slots:
                    recs.append(
                        f"Ready for MASQUE migration: trial `--migrate-masque {wg_slots[0]} --core {rep['core_id']}`, "
                        f"then `--migrate-masque all --core {rep['core_id']}`."
                    )
            if rep["duplicate_keys"]:
                recs.append(
                    "Break shared WireGuard identity throttling via `--refresh <slot> --new-identity --force-spawn` or `--migrate-masque`."
                )
            if rep["retired_total"] >= self.config.max_live_generations:
                recs.append(f"{rep['retired_total']} retired outbounds present; consider scheduled/manual `--compact`.")
            if recs:
                print("  Recommendations:")
                for r in recs:
                    print(f"    • {r}")
        print("")
        return {"cores": reports}

    def migrate_to_masque(
        self,
        target_spec: str,
        core_selector: Optional[str] = None,
        probe_timeout: int = 45,
        wait_probe: bool = True,
        license_key: str = "",
    ) -> int:
        """
        Zero-downtime two-stage migration of WARP WireGuard slot(s) to freshly enrolled
        Cloudflare WARP-over-MASQUE outbounds (requires Xray >= 26.10.21 on ALL assigned nodes):
          Stage A: AddOutbound (`warpN__rNNNN`, routing untouched -> 0 Xray restarts)
          Verify : Poll Observatory until staged MASQUE outbounds report OK
          Stage B: ReplaceRouting (live switch verified slots -> 0 dropped users)

        Returns number of slots successfully migrated (or previewed).
        """
        raw_targets = [t.strip().lower() for t in target_spec.split(",") if t.strip()]
        if not raw_targets:
            logger.error("No target slots provided for --migrate-masque")
            return 0
        migrate_all = "all" in raw_targets
        normalized_targets = {split_generation_tag(t)[0] for t in raw_targets if t != "all"}

        with self._exclusive_guard():
            return self._migrate_to_masque_impl(
                migrate_all=migrate_all,
                normalized_targets=normalized_targets,
                core_selector=core_selector,
                probe_timeout=probe_timeout,
                wait_probe=wait_probe,
                license_key=license_key,
            )

    def _migrate_to_masque_impl(
        self,
        migrate_all: bool,
        normalized_targets: set[str],
        core_selector: Optional[str],
        probe_timeout: int,
        wait_probe: bool,
        license_key: str,
    ) -> int:
        nodes = self.client.get_nodes()
        cores = self._filter_cores(self.client.get_cores(), core_selector)
        eff_license = (license_key or self.config.warp_license or "").strip()
        migrated_slots = 0

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
            candidate_bases = [
                b for b in slots
                if migrate_all or b.lower() in normalized_targets
            ]
            if not candidate_bases:
                continue

            # Gate 1: Strict Xray >= 26.10.21 version verification on ALL assigned nodes
            ready, blockers, assigned = core_masque_readiness(nodes, cid)
            if not ready:
                logger.error(
                    f"Core '{cname}' (id={cid}): refusing MASQUE migration — Xray >= 26.10.21 is required on ALL "
                    f"assigned nodes. Blockers: {'; '.join(blockers)}. Update Xray in PasarGuard Panel first."
                )
                continue

            if wait_probe and not has_observatory_configured(ccfg):
                logger.error(
                    f"Core '{cname}' (id={cid}): Observatory is not configured; cannot verify new MASQUE "
                    f"outbounds before cutover. Run '--optimize-warp' first (or pass '--no-wait')."
                )
                continue

            slots_to_migrate: list[str] = []
            for base_tag in candidate_bases:
                act_tag = active_map[base_tag]
                act_ob = next((ob for ob in slots[base_tag].values() if ob["tag"] == act_tag), None)
                if act_ob and str(act_ob.get("protocol", "")).lower() == "masque":
                    logger.info(f"Core '{cname}': slot '{base_tag}' (active='{act_tag}') is already MASQUE — skipping.")
                    continue
                slots_to_migrate.append(base_tag)

            if not slots_to_migrate:
                continue

            # Reuse any already-staged healthy MASQUE generation (e.g. left in core config from an earlier run)
            pre_telemetry = self.warp.poll_core_observatory(self.client, cid, nodes, core_config=ccfg)
            pre_verified: list[tuple[str, str, str]] = []
            need_enroll: list[str] = []
            for base_tag in slots_to_migrate:
                adopted = None
                for _, cand_ob in sorted(slots[base_tag].items(), reverse=True):
                    if str(cand_ob.get("protocol", "")).lower() == "masque":
                        cand_tag = cand_ob["tag"]
                        if self.warp.is_tag_confirmed_healthy(pre_telemetry.get(cand_tag, [])):
                            adopted = (base_tag, cand_tag, self.warp.get_outbound_endpoint(cand_ob))
                            break
                if adopted:
                    pre_verified.append(adopted)
                else:
                    need_enroll.append(base_tag)

            if self.dry_run:
                node_vers = ", ".join(
                    f"{n.get('name', n.get('id'))}={n.get('xray_version')}" for n in assigned
                )
                adopt_msg = (
                    f"promote {len(pre_verified)} already-healthy staged MASQUE outbound(s) {[p[1] for p in pre_verified]} and "
                    if pre_verified else ""
                )
                enroll_msg = (
                    f"enroll {len(need_enroll)} new Cloudflare MASQUE device(s) for [{', '.join(need_enroll)}]"
                    if need_enroll else "make 0 new registrations"
                )
                logger.info(
                    f"Core '{cname}' (id={cid}) [DRY RUN MASQUE]: node Xray versions OK ({node_vers}); "
                    f"would {adopt_msg}{enroll_msg} → live Stage B cutover."
                )
                continue

            # Gate 2: Cloudflare registration hourly budget check (only for slots requiring new enrollment)
            if need_enroll:
                recent = self.state.prune_registrations()
                remaining_budget = max(0, self.config.max_registrations_per_hour - len(recent))
                if len(need_enroll) > remaining_budget:
                    logger.error(
                        f"Core '{cname}' (id={cid}): requested {len(need_enroll)} MASQUE registration(s), "
                        f"but only {remaining_budget} slot(s) remain in current 1-hour limit "
                        f"(max_registrations_per_hour={self.config.max_registrations_per_hour}). "
                        f"Migrate a smaller batch (e.g. trial 1 slot first) or raise max_registrations_per_hour in config.json."
                    )
                    continue

            for base_tag, existing_tag, ep in pre_verified:
                logger.info(
                    f"Core '{cname}': Reusing already-staged healthy MASQUE outbound '{existing_tag}' ({ep}) for '{base_tag}' (0 new registrations)."
                )

            newly_verified: list[tuple[str, str, str]] = []
            if need_enroll:
                # Stage A: Register fresh Cloudflare MASQUE identities & append outbounds ONLY (0 Xray restarts)
                stage_a_cfg = copy.deepcopy(ccfg)
                used_endpoints = self.warp._collect_used_endpoints(stage_a_cfg.get("outbounds", []))
                staged: list[tuple[str, str, str]] = []

                for base_tag in need_enroll:
                    gens = slots[base_tag]
                    next_gen = max(gens.keys()) + 1
                    new_tag = format_generation_tag(base_tag, next_gen)
                    try:
                        self.state.record_registration()
                        rec = self.registrar.register_masque(license_key=eff_license)
                    except WarpRateLimitError as e:
                        logger.error(
                            f"Core '{cname}': Cloudflare rate limit hit while enrolling '{base_tag}': {e}. Stopping registration batch."
                        )
                        break
                    except WarpRegistrationError as e:
                        logger.error(f"Core '{cname}': MASQUE registration failed for '{base_tag}': {e}")
                        continue

                    self.device_store.put(cid, base_tag, rec)
                    port = self.warp._pick_masque_port(rec["endpoint_ip"], used_endpoints)
                    ep = f"{rec['endpoint_ip']}:{port}"
                    used_endpoints.add(ep)
                    new_ob = self.registrar.build_masque_outbound(
                        new_tag, rec, port=port, alpn=self.config.masque_alpn
                    )
                    stage_a_cfg.setdefault("outbounds", []).append(new_ob)
                    staged.append((base_tag, new_tag, ep))
                    logger.info(f"Core '{cname}': Enrolled MASQUE device for '{base_tag}' → staged outbound '{new_tag}' ({ep})")

                if staged:
                    is_safe, unsafe_reason = LiveSafetyValidator.check(
                        ccfg, stage_a_cfg, live_remove_supported=self.config.live_remove_supported
                    )
                    if not is_safe:
                        logger.error(f"Core '{cname}': Stage A refused (would restart Xray: {unsafe_reason})")
                        staged = []

                if staged:
                    payload_a = {
                        "name": core.get("name"),
                        "config": stage_a_cfg,
                        "type": core.get("type"),
                        "exclude_inbound_tags": list(core.get("exclude_inbound_tags", [])),
                        "fallbacks_inbound_tags": list(core.get("fallbacks_inbound_tags", [])),
                    }
                    self.client.update_core(cid, payload_a, restart_nodes=True)
                    self.device_store.save()
                    self.state.save()
                    logger.info(
                        f"Core '{cname}': Stage A AddOutbound pushed live for {len(staged)} MASQUE outbound(s) (0 Xray restarts; users untouched)."
                    )

                    # Observatory verification loop
                    if not wait_probe:
                        newly_verified = list(staged)
                    else:
                        deadline = time.monotonic() + max(1, int(probe_timeout))
                        pending = list(staged)
                        while pending:
                            telemetry = self.warp.poll_core_observatory(self.client, cid, nodes, core_config=stage_a_cfg)
                            still_pending: list[tuple[str, str, str]] = []
                            for item in pending:
                                if self.warp.is_tag_confirmed_healthy(telemetry.get(item[1], [])):
                                    newly_verified.append(item)
                                    logger.info(f"Core '{cname}': Probe verified MASQUE outbound '{item[1]}' ({item[2]}) [OK]")
                                else:
                                    still_pending.append(item)
                            pending = still_pending
                            rem = deadline - time.monotonic()
                            if not pending or rem <= 0:
                                break
                            time.sleep(min(3.0, rem))

                        for base_tag, new_tag, ep in pending:
                            logger.warning(
                                f"Core '{cname}': staged MASQUE outbound '{new_tag}' ({ep}) did not pass Observatory probe "
                                f"within {probe_timeout}s; keeping '{base_tag}' on its existing working outbound."
                            )
                else:
                    logger.error(f"Core '{cname}': no new MASQUE outbounds were enrolled; skipping Stage A.")

            all_verified = pre_verified + newly_verified
            if not all_verified:
                logger.error(
                    f"Core '{cname}': zero MASQUE outbounds verified healthy; skipping Stage B cutover (users unaffected)."
                )
                continue

            # Stage B: Live ReplaceRouting cutover ONLY for verified slots
            now = time.time()
            for base_tag, new_tag, ep in all_verified:
                self.state.set_active_tag(cid, base_tag, new_tag)
                self.state.identity_created_ts[f"{cid}:{new_tag}"] = now
                self.state.last_rotation_mode[f"{cid}:{base_tag}"] = "masque"
                self.state.fail_counts[f"{cid}:{new_tag}"] = 0
                # Reset WireGuard latency history so MASQUE probes aren't compared to old WG baseline
                self.state.latency_history.pop(f"{cid}:{base_tag}", None)
                migrated_slots += 1
            self.state.save()

            self.sync(core_selector=str(cid), routing_only=True)
            logger.info(
                f"Core '{cname}': Stage B live ReplaceRouting complete for {len(all_verified)} MASQUE slot(s) (0 dropped connections)."
            )

        return migrated_slots


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
            try:
                with self.syncer._exclusive_guard():
                    if self._reload_requested:
                        self._reload_requested = False
                        self.syncer.config.load()
                        self.syncer.state.load()
                        self.syncer.device_store.load()
                    self.syncer.sync()
                    if not self.syncer.dry_run:
                        self.syncer.state.save()
                        self.syncer.device_store.save()
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
  %(prog)s --diagnose                   Read-only audit: node Xray versions, duplicate keys, latency baselines
  %(prog)s --optimize-warp              One-time setup: enable Observatory, MTU=1280, KeepAlive=20 & HA balancers
  %(prog)s --status                     View live WARP outbound latency & health across all nodes
  %(prog)s --refresh warp2              Live-refresh 'warp2' with a new Anycast IP:port (0 user drops!)
  %(prog)s --refresh warp2 --new-identity --force-spawn   Re-enroll a fresh Cloudflare identity for 'warp2'
  %(prog)s --migrate-masque warp15      Two-stage zero-downtime migration of 'warp15' to WARP-over-MASQUE
  %(prog)s --migrate-masque all         Migrate all WARP slots to MASQUE (requires Xray >= 26.10.21)
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
        "--diagnose",
        action="store_true",
        help="Read-only audit of node Xray versions (>=26.10.21), duplicate keys, tunnel hygiene & latency baselines",
    )
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
        "--new-identity",
        action="store_true",
        help="With --refresh, register a fresh Cloudflare WARP identity (WireGuard or MASQUE per prefer_protocol)",
    )
    parser.add_argument(
        "--migrate-masque",
        type=str,
        default=None,
        metavar="TAG",
        help="Zero-downtime two-stage migration of WARP slot(s) to MASQUE (e.g. 'warp15', 'warp1,warp2', or 'all')",
    )
    parser.add_argument(
        "--probe-timeout",
        type=int,
        default=45,
        help="Seconds to wait for Observatory OK before Stage B MASQUE cutover (default: 45)",
    )
    parser.add_argument(
        "--no-wait",
        action="store_true",
        help="With --migrate-masque, skip waiting for Observatory probe before Stage B routing cutover",
    )
    parser.add_argument(
        "--warp-license",
        type=str,
        default="",
        help="Optional Cloudflare WARP+ license key for new registrations / --migrate-masque",
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
        help="Optional core ID or core name filter (for --diagnose, --migrate-masque, --refresh, --optimize-warp, --compact, --status)",
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
    device_store = WarpDeviceStore()
    device_store.load()

    client = PanelClient(config)
    syncer = RouteSync(client, state, config=config, dry_run=args.dry_run, device_store=device_store)

    try:
        if args.diagnose:
            syncer.diagnose(core_selector=args.core)
        elif args.status:
            syncer.print_status(core_selector=args.core)
        elif args.migrate_masque:
            syncer.migrate_to_masque(
                target_spec=args.migrate_masque,
                core_selector=args.core,
                probe_timeout=args.probe_timeout,
                wait_probe=not args.no_wait,
                license_key=args.warp_license,
            )
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
                force_new_identity=args.new_identity,
                license_key=args.warp_license,
            )
        elif args.daemon:
            interval = args.interval or config.poll_interval
            daemon = Daemon(syncer, interval)
            daemon.run()
        else:
            syncer.sync(core_selector=args.core, license_key=args.warp_license)
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)
    finally:
        client.close()
        if not args.dry_run:
            state.save()
            device_store.save()


if __name__ == "__main__":
    main()
