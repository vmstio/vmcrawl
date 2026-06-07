#!/usr/bin/env python3

# =============================================================================
# IMPORTS
# =============================================================================
try:
    import argparse
    import asyncio
    import atexit
    import csv
    import gc
    import getpass
    import hashlib
    import ipaddress
    import json
    import mimetypes
    import os
    import random
    import re
    import socket
    import ssl
    import subprocess
    import sys
    import threading
    import time
    from datetime import UTC, date, datetime, timedelta
    from io import StringIO
    from typing import Any
    from urllib.parse import urlparse

    import httpx
    import idna.core
    import paramiko
    import psycopg
    import toml
    from cachetools import TTLCache
    from dotenv import load_dotenv
    from packaging import version
    from psycopg import sql
    from psycopg_pool import ConnectionPool
    from tqdm import tqdm
except ImportError as exception:
    print(f"Error importing module: {exception}")
    sys.exit(1)

# =============================================================================
# IDNA EMOJI DOMAIN SUPPORT
# =============================================================================
# The idna library (IDNA2008) rejects emoji codepoints, which prevents httpx
# from connecting to emoji domains (e.g. 🍕.ws / xn--vi8h.ws). Patch
# check_label to allow InvalidCodepoint errors through while preserving all
# other IDNA validation.

_original_idna_check_label = idna.core.check_label


def _permissive_idna_check_label(label: str | bytes | bytearray) -> None:
    try:
        _original_idna_check_label(label)
    except idna.core.InvalidCodepoint:
        pass


idna.core.check_label = _permissive_idna_check_label

# =============================================================================
# ENVIRONMENT AND CONFIGURATION
# =============================================================================

# Detect the current filename
current_filename = os.path.basename(__file__)

# Load environment variables from .env file
try:
    _ = load_dotenv()
except Exception as exception:
    print(f"Error loading .env file: {exception}")
    sys.exit(1)

# =============================================================================
# APPLICATION METADATA
# =============================================================================

toml_file_path = os.path.join(os.path.dirname(__file__), "pyproject.toml")
try:
    project_info = toml.load(toml_file_path)
    appname: str = str(project_info["project"]["name"])
    appversion: str = str(project_info["project"]["version"])
except FileNotFoundError:
    print(f"Error: {toml_file_path} not found.")
    sys.exit(1)
except toml.TomlDecodeError:
    print(f"Error: {toml_file_path} is not a valid TOML file.")
    sys.exit(1)
except KeyError as exception:
    print(f"Error: Missing expected key in TOML file: {exception}")
    sys.exit(1)

# =============================================================================
# CONSTANTS
# =============================================================================

# Terminal color codes
colors = {
    "bold": "\033[1m",
    "reset": "\033[0m",
    "cyan": "\033[96m",
    "gray": "\033[90m",
    "green": "\033[92m",
    "magenta": "\033[95m",
    "orange": "\033[38;5;208m",
    "pink": "\033[38;5;198m",
    "purple": "\033[94m",
    "red": "\033[91m",
    "yellow": "\033[93m",
    "white": "\033[0m",
}
EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_INTERRUPTED = 130

# Track per-domain processing start times so error output can include elapsed time
_domain_start_times: dict[str, float] = {}
_domain_start_times_lock = threading.Lock()


def _set_domain_start_time(domain: str) -> None:
    with _domain_start_times_lock:
        _domain_start_times[domain] = time.monotonic()


def _clear_domain_start_time(domain: str) -> None:
    with _domain_start_times_lock:
        _domain_start_times.pop(domain, None)


def _get_domain_elapsed_seconds(domain: str) -> float | None:
    with _domain_start_times_lock:
        started_at = _domain_start_times.get(domain)
    if started_at is None:
        return None
    return max(0.0, time.monotonic() - started_at)


def echo(text: str, color: str, use_tqdm: bool = False, **kwargs: Any) -> None:
    """Print colored output, optionally using tqdm.write."""
    if use_tqdm:
        text = text.lower()
    effective_color = color if color else "cyan"

    if ":" in text:
        before_colon, after_colon = text.split(":", 1)
        if effective_color in {"yellow", "orange", "red", "green", "cyan"}:
            elapsed_seconds = _get_domain_elapsed_seconds(before_colon.strip())
            if elapsed_seconds is not None:
                after_colon = (
                    f"{after_colon} {colors.get('gray', '')}[{elapsed_seconds:.2f}s]"
                    f"{colors.get(effective_color, '')}"
                )
        colored_text = (
            f"{before_colon}:{colors.get(effective_color, '')}"
            f"{after_colon}{colors['reset']}"
        )
    else:
        colored_text = f"{colors.get(effective_color, '')}{text}{colors['reset']}"

    if use_tqdm:
        tqdm.write(colored_text, **kwargs)
    else:
        print(colored_text, **kwargs)


# HTTP status codes for special handling
http_codes_to_hardfail = [999, 451, 418, 410]  # gone

MASTODON_COMPATIBLE_SOFTWARE = ("mastodon", "hometown", "kmyblue")

# Failure classifications parsed from the leading token of raw_domains.reason.
# Scheduling and pruning are driven entirely by reason; there are no terminal
# bad_* columns. HARD (gone: 410/451/418/999) and ROBOT (robots.txt disallow)
# are the only classifications that purge a domain from the published
# mastodon_domains list at detection. Every other type only reschedules.
PURGE_ON_DETECTION_TYPES = ("HARD", "ROBOT")
TRACKED_ERROR_TYPES = (
    "DNS",
    "SSL",
    "TCP",
    "TYPE",
    "FILE",
    "API",
    "JSON",
    "HARD",
    "ROBOT",
)

# Per-error-type base reschedule cadence in hours (env-overridable). The queue
# reschedules a failed domain at base * 2**attempts, ceilinged per the cap in
# reschedule_domain. Transient types use short bases and back off; ROBOT/HARD
# use long flat intervals (base >= cap, so the backoff is a no-op for them).
RETRY_BASE_HOURS: dict[str, int] = {
    "DNS": max(1, int(os.getenv("VMCRAWL_RETRY_DNS_HOURS", "24"))),
    "SSL": max(1, int(os.getenv("VMCRAWL_RETRY_SSL_HOURS", "24"))),
    "TCP": max(1, int(os.getenv("VMCRAWL_RETRY_TCP_HOURS", "12"))),
    "CONTENT": max(1, int(os.getenv("VMCRAWL_RETRY_CONTENT_HOURS", "24"))),
    "HTTP2XX": max(1, int(os.getenv("VMCRAWL_RETRY_HTTP2XX_HOURS", "48"))),
    "HTTP3XX": max(1, int(os.getenv("VMCRAWL_RETRY_HTTP3XX_HOURS", "48"))),
    "HTTP4XX": max(1, int(os.getenv("VMCRAWL_RETRY_HTTP4XX_HOURS", "48"))),
    "HTTP5XX": max(1, int(os.getenv("VMCRAWL_RETRY_HTTP5XX_HOURS", "6"))),
    "ROBOT": max(1, int(os.getenv("VMCRAWL_RETRY_ROBOT_HOURS", "720"))),
    "HARD": max(1, int(os.getenv("VMCRAWL_RETRY_HARD_HOURS", "2160"))),
}

# Precomposed psycopg.sql fragments so call sites never interpolate values
# or identifiers into SQL text directly. Built once at import time.
_MASTODON_COMPATIBLE_IN_CLAUSE = sql.SQL("({})").format(
    sql.SQL(", ").join(sql.Literal(s) for s in MASTODON_COMPATIBLE_SOFTWARE)
)

# Maps the leading token of reason -> base cadence hours. Mirrors the prefix
# logic of get_error_type(): explicit DNS/SSL/TCP/HARD/ROBOT tokens, HTTP status
# codes keyed by leading digit (2xx/3xx/4xx/5xx), and TYPE/FILE/JSON/API (plus
# any unknown reason) falling to the CONTENT base via ELSE. The doubled %% in the
# LIKE patterns survives psycopg's parameter substitution in reschedule_domain.
_REASON_BASE_HOURS_CASE = sql.SQL(
    "CASE"
    "  WHEN reason LIKE 'DNS%%' THEN {dns}"
    "  WHEN reason LIKE 'SSL%%' THEN {ssl}"
    "  WHEN reason LIKE 'TCP%%' THEN {tcp}"
    "  WHEN reason LIKE 'HARD%%' THEN {hard}"
    "  WHEN reason LIKE 'ROBOT%%' THEN {robot}"
    "  WHEN reason ~ '^5[0-9][0-9]' THEN {http5xx}"
    "  WHEN reason ~ '^4[0-9][0-9]' THEN {http4xx}"
    "  WHEN reason ~ '^3[0-9][0-9]' THEN {http3xx}"
    "  WHEN reason ~ '^2[0-9][0-9]' THEN {http2xx}"
    "  ELSE {content} "
    "END"
).format(
    dns=sql.Literal(RETRY_BASE_HOURS["DNS"]),
    ssl=sql.Literal(RETRY_BASE_HOURS["SSL"]),
    tcp=sql.Literal(RETRY_BASE_HOURS["TCP"]),
    hard=sql.Literal(RETRY_BASE_HOURS["HARD"]),
    robot=sql.Literal(RETRY_BASE_HOURS["ROBOT"]),
    http5xx=sql.Literal(RETRY_BASE_HOURS["HTTP5XX"]),
    http4xx=sql.Literal(RETRY_BASE_HOURS["HTTP4XX"]),
    http3xx=sql.Literal(RETRY_BASE_HOURS["HTTP3XX"]),
    http2xx=sql.Literal(RETRY_BASE_HOURS["HTTP2XX"]),
    content=sql.Literal(RETRY_BASE_HOURS["CONTENT"]),
)


def is_mastodon_compatible_software(software_name: str | None) -> bool:
    """Return True when NodeInfo software is Mastodon-compatible."""
    if software_name is None:
        return False
    return software_name.lower() in MASTODON_COMPATIBLE_SOFTWARE


# Pre-compiled regex patterns for version cleaning (performance optimization)
RE_VERSION_SUFFIX_SPLIT = re.compile(r"[+~_ /@&(]|\bpatch\b")
RE_VERSION_HAS_PRERELEASE = re.compile(
    r"(?<![a-zA-Z])(?:alpha|beta|rc|nightly)(?![a-zA-Z])"
)
RE_VERSION_PARTS = re.compile(r"^(\d+)\.(\d+)\.(\d+)(-.+)?$")
RE_VERSION_EXTRACT_SEMVER = re.compile(r"^(\d+\.\d+\.\d+)")
RE_VERSION_DATE_SUFFIX = re.compile(r"-(\d{2})(\d{2})(\d{2})$")
RE_VERSION_NIGHTLY = re.compile(
    r"4\.\d+\.0-nightly\.(\d{4}-\d{2}-\d{2})(-security)?"
)
RE_VERSION_NIGHTLY_DATE = re.compile(r"-nightly-\d{8}")
RE_VERSION_RC = re.compile(r"(?<![a-zA-Z])rc(\d+)")
RE_VERSION_BETA = re.compile(r"(?<![a-zA-Z])beta(\d+)")
RE_VERSION_ALPHA = re.compile(r"(?<![a-zA-Z])alpha(\d+)")
RE_VERSION_ALPHA_SUFFIX = re.compile(r"-[a-zA-Z]")
RE_VERSION_DIGIT_SUFFIX = re.compile(r"-\d")
RE_VERSION_MALFORMED_PRERELEASE = re.compile(r"(alpha|beta|rc)\d+$")
RE_VERSION_TRAILING_SUFFIX = re.compile(r"^(\d+\.\d+\.\d+)[a-zA-Z][a-zA-Z0-9]*$")
RE_VERSION_MULTIPLE_DASHES = re.compile(r"-{2,}")

# Pre-compiled regex patterns for domain validation (high frequency in fetch loops)
RE_DOMAIN_FORMAT = re.compile(r"^[^\s/:@]+\.[^\s/:@]{2,}$")
RE_VOWEL_PATTERN = re.compile(r"\.[aeiou]{4}")

# Pre-compiled regex patterns for URL and error handling
RE_MULTIPLE_SLASHES = re.compile(r"/+")
RE_CLEANUP_BRACKETS = re.compile(r"\s*(\[[^\]]*\]|\([^)]*\))")
RE_CONTENT_TYPE_CHARSET = re.compile(r";.*$")
RE_FUNCTION_DEF = re.compile(r"def (\w+)")
RE_QUOTED_STRING = re.compile(r"'[^']+'")
RE_JSON_TRAILING_COMMA = re.compile(r",(\s*[}\]])")
RE_JSON_DOUBLE_QUOTED_VALUE = re.compile(r':\s*""([^"\r\n]*)""')

# =============================================================================
# DATABASE CONNECTION
# =============================================================================

# Optional SSH tunnel for remote database access
# Set VMCRAWL_SSH_HOST to enable tunneling through an SSH server
_ssh_transport: paramiko.Transport | None = None
_ssh_tunnel_port: int | None = None
_ssh_host = os.getenv("VMCRAWL_SSH_HOST")
_ssh_lock = threading.Lock()

if _ssh_host:
    _db_host = os.getenv("VMCRAWL_POSTGRES_HOST", "localhost")
    _db_port = int(os.getenv("VMCRAWL_POSTGRES_PORT", "5432"))
    _ssh_port = int(os.getenv("VMCRAWL_SSH_PORT", "22"))
    _ssh_user = os.getenv("VMCRAWL_SSH_USER") or getpass.getuser()
    _ssh_key_path = os.path.expanduser(os.getenv("VMCRAWL_SSH_KEY", "~/.ssh/id_rsa"))
    _ssh_key_pass = os.getenv("VMCRAWL_SSH_KEY_PASS")

    def _load_ssh_key() -> paramiko.PKey:
        for key_class in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
            try:
                return key_class.from_private_key_file(
                    _ssh_key_path, password=_ssh_key_pass
                )
            except (paramiko.SSHException, ValueError):
                continue
        raise paramiko.SSHException(f"Unable to load SSH key: {_ssh_key_path}")

    _ssh_pkey = _load_ssh_key()

    def _ensure_ssh_transport() -> paramiko.Transport | None:
        """Return a live SSH transport, rebuilding it if the previous one died.

        Invoked for every new tunneled connection, so a dropped tunnel is
        transparently re-established on demand (e.g. when the database pool
        reconnects) without restarting the crawler. The local listening port is
        preserved across reconnects, so the connection string never changes.
        """
        global _ssh_transport
        with _ssh_lock:
            if _ssh_transport is not None and _ssh_transport.is_active():
                return _ssh_transport
            if _ssh_transport is not None:
                try:
                    _ssh_transport.close()
                except Exception:
                    pass
                _ssh_transport = None
            try:
                transport = paramiko.Transport((_ssh_host, _ssh_port))
                transport.set_keepalive(30)  # detect drops promptly
                transport.connect(username=_ssh_user, pkey=_ssh_pkey)
                _ssh_transport = transport
                echo(
                    f"SSH tunnel connected: 127.0.0.1:{_ssh_tunnel_port}"
                    f" -> {_db_host}:{_db_port} via {_ssh_host}",
                    "cyan",
                )
            except Exception as exc:
                echo(f"SSH tunnel connection failed: {exc}", "yellow")
                _ssh_transport = None
            return _ssh_transport

    def _invalidate_ssh_transport(dead: paramiko.Transport) -> None:
        """Drop a transport that failed mid-use so the next call rebuilds it."""
        global _ssh_transport
        with _ssh_lock:
            if _ssh_transport is dead:
                try:
                    _ssh_transport.close()
                except Exception:
                    pass
                _ssh_transport = None

    try:
        # Bind a persistent local listening socket first so the forwarded port
        # stays stable across tunnel reconnects (the conn string never changes).
        _tunnel_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _tunnel_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _tunnel_sock.bind(("127.0.0.1", 0))
        _ssh_tunnel_port = _tunnel_sock.getsockname()[1]
        _tunnel_sock.listen(20)

        # Fail fast at startup if the tunnel can't be established at all.
        if _ensure_ssh_transport() is None:
            raise RuntimeError(f"Unable to establish SSH tunnel via {_ssh_host}")

        def _ssh_tunnel_accept_loop() -> None:
            """Forward local connections through the tunnel, reconnecting it on
            demand if it has dropped."""
            while True:
                try:
                    _tunnel_sock.settimeout(1.0)
                    client_sock, _ = _tunnel_sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break

                transport = _ensure_ssh_transport()
                if transport is None:
                    client_sock.close()
                    continue
                try:
                    channel = transport.open_channel(
                        "direct-tcpip",
                        (_db_host, _db_port),
                        client_sock.getpeername(),
                        timeout=10,
                    )
                except Exception:
                    # The tunnel may have dropped before is_active() noticed.
                    # Tear it down so the next connection rebuilds it.
                    _invalidate_ssh_transport(transport)
                    client_sock.close()
                    continue

                def _forward(src: Any, dst: Any) -> None:
                    try:
                        while True:
                            data = src.recv(65536)
                            if not data:
                                break
                            dst.sendall(data)
                    except Exception:
                        pass
                    finally:
                        try:
                            src.close()
                        except Exception:
                            pass
                        try:
                            dst.close()
                        except Exception:
                            pass

                threading.Thread(
                    target=_forward, args=(client_sock, channel), daemon=True
                ).start()
                threading.Thread(
                    target=_forward, args=(channel, client_sock), daemon=True
                ).start()

        _tunnel_thread = threading.Thread(target=_ssh_tunnel_accept_loop, daemon=True)
        _tunnel_thread.start()
    except Exception as exception:
        echo(f"Error establishing SSH tunnel: {exception}", "red")
        if _ssh_transport is not None:
            try:
                _ssh_transport.close()
            except Exception:
                pass
        sys.exit(1)

_db_connect_host = (
    "127.0.0.1" if _ssh_tunnel_port else os.getenv("VMCRAWL_POSTGRES_HOST", "localhost")
)
_db_connect_port = (
    str(_ssh_tunnel_port)
    if _ssh_tunnel_port
    else os.getenv("VMCRAWL_POSTGRES_PORT", "5432")
)

conn_string = (
    f"postgresql://{os.getenv('VMCRAWL_POSTGRES_USER')}:"
    f"{os.getenv('VMCRAWL_POSTGRES_PASS')}@"
    f"{_db_connect_host}:"
    f"{_db_connect_port}/"
    f"{os.getenv('VMCRAWL_POSTGRES_DATA')}"
)

# Create connection pool for thread-safe database access
# Scale connection pool size with number of worker threads
# With PgBouncer: Connection multiplexing allows more application connections
# Without PgBouncer: May need to adjust based on database server capacity
max_workers = int(os.getenv("VMCRAWL_MAX_THREADS", "2"))
# Balance pool size for multiple concurrent instances (4-6) within server limit (96 total)
# 6 instances × 15 connections = 90 connections (leaves headroom)
# 4 instances × 15 connections = 60 connections (plenty of headroom)
max_db_connections = 15  # Fixed size to fit within server pool limit

try:
    db_pool = ConnectionPool(
        conn_string,
        min_size=2,  # Keep 2 warm connections
        max_size=max_db_connections,
        timeout=30,
        max_waiting=max_workers
        * 3,  # Allow more queuing since we have fewer connections
        # Validate connections before handing them out. When the SSH tunnel
        # drops mid-crawl the pool fills with dead sockets; without this check
        # workers receive them and fail with "ssl error: unexpected eof".
        check=ConnectionPool.check_connection,
    )

    # Register cleanup handler to prevent threading errors on early exit
    def cleanup_db_connections():
        try:
            db_pool.close(timeout=5)
        except Exception:
            pass
        if _ssh_transport is not None:
            try:
                _ssh_transport.close()
            except Exception:
                pass

    _ = atexit.register(cleanup_db_connections)
except psycopg.Error as exception:
    echo(f"Error connecting to PostgreSQL database: {exception}", "red")
    sys.exit(1)

# =============================================================================
# DNS CACHING
# =============================================================================

# Type alias for DNS cache key and value
# Key: (host, port, family, type, proto, flags)
# Value: list of 5-tuples from getaddrinfo (varies by address family)
_DNSCacheKey = tuple[str, int | str | None, int, int, int, int]
_DNSCacheValue = list[
    tuple[
        socket.AddressFamily,
        socket.SocketKind,
        int,
        str,
        tuple[str, int] | tuple[str, int, int, int] | tuple[int, bytes],
    ]
]

# Thread-safe DNS cache to reduce redundant lookups
# TTL of 300 seconds (5 minutes), max 10000 entries
_dns_cache: TTLCache[_DNSCacheKey, _DNSCacheValue] = TTLCache(maxsize=10000, ttl=300)
_dns_cache_lock = threading.Lock()

# Store original getaddrinfo before monkey-patching
_original_getaddrinfo = socket.getaddrinfo


def _cached_getaddrinfo(
    host: str,
    port: int | str | None,
    family: int = 0,
    type: int = 0,
    proto: int = 0,
    flags: int = 0,
) -> _DNSCacheValue:
    """Thread-safe cached DNS resolution."""
    cache_key: _DNSCacheKey = (host, port, family, type, proto, flags)

    # Check cache first (with lock for thread safety)
    with _dns_cache_lock:
        if cache_key in _dns_cache:
            return _dns_cache[cache_key]

    # Perform actual DNS lookup (outside lock to allow concurrent lookups)
    result: _DNSCacheValue = _original_getaddrinfo(
        host, port, family, type, proto, flags
    )  # type: ignore[assignment]

    # Cache the result
    with _dns_cache_lock:
        _dns_cache[cache_key] = result

    return result


# Monkey-patch socket.getaddrinfo with cached version
socket.getaddrinfo = _cached_getaddrinfo  # type: ignore[assignment]

# =============================================================================
# HTTP CLIENT CONFIGURATION
# =============================================================================

http_timeout = int(os.getenv("VMCRAWL_HTTP_TIMEOUT", "5"))
domain_timeout = int(os.getenv("VMCRAWL_DOMAIN_TIMEOUT", "30"))
http_redirect = int(os.getenv("VMCRAWL_HTTP_REDIRECT", "2"))
http_custom_user_agent = f"{appname}/{appversion} (https://{appname}.com)"
http_custom_headers = {"User-Agent": http_custom_user_agent}

# Memory protection: limit response sizes to prevent memory bombs
# Max response size: 10MB (should be plenty for any legitimate Mastodon API response)
max_response_size = int(os.getenv("VMCRAWL_MAX_RESPONSE_SIZE", str(10 * 1024 * 1024)))
dns_retry_attempts = max(1, int(os.getenv("VMCRAWL_DNS_RETRY_ATTEMPTS", "3")))
dns_retry_base_delay_ms = max(
    0, int(os.getenv("VMCRAWL_DNS_RETRY_BASE_DELAY_MS", "80"))
)
dns_retry_jitter_ms = max(0, int(os.getenv("VMCRAWL_DNS_RETRY_JITTER_MS", "40")))
dns_retry_max_total_delay_ms = max(
    0, int(os.getenv("VMCRAWL_DNS_RETRY_MAX_TOTAL_DELAY_MS", "500"))
)

# Create limits object for httpx
# Scale connection limits with number of worker threads
# Each thread may need multiple connections (robots.txt, host-meta, nodeinfo, etc.)
limits = httpx.Limits(
    max_keepalive_connections=max_workers * 5,
    max_connections=max_workers * 10,
    keepalive_expiry=30.0,
)

# Per-host outbound concurrency cap. Prevents the worker pool from piling
# onto a single victim host (either a slow instance or a redirect chain
# pointed at one target), which would otherwise turn the crawler into a
# reflected DoS tool. A value of 2 lets parallel discovery checks
# (host-meta + webfinger) run without serialization while still capping
# concurrent pressure on any one host.
_max_concurrent_per_host = max(
    1, int(os.getenv("VMCRAWL_MAX_CONCURRENT_PER_HOST", "2"))
)
_host_semaphores: dict[str, asyncio.Semaphore] = {}


def _get_host_semaphore(host: str) -> asyncio.Semaphore:
    """Return the per-host semaphore, creating it on first use."""
    sem = _host_semaphores.get(host)
    if sem is None:
        sem = asyncio.Semaphore(_max_concurrent_per_host)
        _host_semaphores[host] = sem
    return sem


# =============================================================================
# DURABLE CRAWL QUEUE CONFIGURATION (see docs/durable-queue.md)
# =============================================================================

# Opt in to the Postgres lease-queue daemon. When false, the crawler keeps its
# existing menu / file / target / whole-batch headless behavior unchanged.
queue_mode = os.getenv("VMCRAWL_QUEUE_MODE", "false").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
# Domains claimed per round, lease TTL before a claim is reclaimable, and how
# long to sleep when nothing is due.
queue_batch = max(1, int(os.getenv("VMCRAWL_QUEUE_BATCH", "100")))
queue_lease_seconds = max(1, int(os.getenv("VMCRAWL_QUEUE_LEASE_SECONDS", "900")))
queue_poll_seconds = max(1, int(os.getenv("VMCRAWL_QUEUE_POLL_SECONDS", "15")))
# Recrawl cadences and transient-failure backoff, all expressed in hours.
recrawl_hours = max(1, int(os.getenv("VMCRAWL_RECRAWL_HOURS", "1")))
recrawl_nonmasto_hours = max(1, int(os.getenv("VMCRAWL_RECRAWL_NONMASTO_HOURS", "168")))
# Global ceiling for the per-type exponential backoff (base * 2**attempts). A
# transient type backs off up to this cap; ROBOT/HARD bases already exceed it so
# they stay flat. Default 720h (30d) keeps even persistently-dead domains on a
# monthly revival check rather than abandoning them.
retry_cap_hours = max(1, int(os.getenv("VMCRAWL_RETRY_CAP_HOURS", "720")))
# Inline peer discovery: when the daemon crawls a healthy Mastodon instance with
# more than peers_min_active monthly users, it also pulls that instance's peers
# in the same pass and imports new domains, making the queue self-feeding. The
# mastodon_domains.peers flag throttles instances whose peers endpoint has failed.
queue_peers_enabled = os.getenv("VMCRAWL_QUEUE_PEERS", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
peers_min_active = max(0, int(os.getenv("VMCRAWL_PEERS_MIN_ACTIVE", "10")))


def _worker_id() -> str:
    """Identity recorded in raw_domains.claimed_by for observability."""
    return f"{socket.gethostname()}:{os.getpid()}"

# Create SSL context with TLS 1.2+ and disable post-quantum key exchange
# Some servers reject MLKEM (post-quantum crypto) with "tlsv1 alert internal error"
# This is a known issue with OpenSSL 3.6.0+ and certain server configurations
ssl_context = ssl.create_default_context()
ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
# Disable MLKEM post-quantum key exchange (SSL_OP_NO_MLKEM)
ssl_context.options |= 0x800000

# SSRF guard: block requests whose hostname resolves to a private, loopback,
# link-local (includes 169.254.169.254 cloud metadata), multicast, reserved,
# or unspecified address. Applied to every request including redirects, since
# httpx invokes the transport per hop.
_allow_private_ips = os.getenv("VMCRAWL_ALLOW_PRIVATE_IPS", "").lower() in (
    "1",
    "true",
    "yes",
)


def _is_blocked_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


class SSRFGuardTransport(httpx.AsyncHTTPTransport):
    """httpx transport that refuses to connect to non-public addresses.

    Validates the destination on every request (including every redirect
    hop) before delegating to the real transport. Raises httpx.ConnectError
    on block, which existing error handlers treat as an unreachable host.
    """

    async def handle_async_request(
        self, request: httpx.Request
    ) -> httpx.Response:
        host = request.url.host
        if not host:
            raise httpx.ConnectError("Missing host in URL")

        # Hostname may already be an IP literal (common SSRF vector).
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None:
            if _is_blocked_ip(literal):
                raise httpx.ConnectError(
                    f"SSRF guard: blocked non-public address {host}"
                )
            return await super().handle_async_request(request)

        # Otherwise resolve DNS and check every returned address.
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(
                host, None, type=socket.SOCK_STREAM
            )
        except socket.gaierror as e:
            raise httpx.ConnectError(f"DNS resolution failed for {host}: {e}") from e

        for info in infos:
            sockaddr = info[4]
            ip_str = sockaddr[0]
            try:
                resolved = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if _is_blocked_ip(resolved):
                raise httpx.ConnectError(
                    f"SSRF guard: {host} resolves to non-public address {ip_str}"
                )

        return await super().handle_async_request(request)


def _build_transport(http2: bool) -> httpx.AsyncHTTPTransport:
    cls = httpx.AsyncHTTPTransport if _allow_private_ips else SSRFGuardTransport
    return cls(
        http1=True,
        http2=http2,
        verify=ssl_context,
        limits=limits,
    )


# Async HTTP client - initialized lazily to work with asyncio event loop
# Use get_http_client() to access
_http_client: httpx.AsyncClient | None = None
_http1_client: httpx.AsyncClient | None = None


def get_http_client() -> httpx.AsyncClient:
    """Get or create the async HTTP client (lazy initialization)."""
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(
            transport=_build_transport(http2=True),
            follow_redirects=True,
            headers=http_custom_headers,
            timeout=http_timeout,
            max_redirects=http_redirect,
        )
    return _http_client


def get_http1_client() -> httpx.AsyncClient:
    """Get or create an HTTP/1.1-only fallback client."""
    global _http1_client
    if _http1_client is None:
        _http1_client = httpx.AsyncClient(
            transport=_build_transport(http2=False),
            follow_redirects=True,
            headers=http_custom_headers,
            timeout=http_timeout,
            max_redirects=http_redirect,
        )
    return _http1_client


async def close_http_client() -> None:
    """Close the async HTTP clients."""
    global _http_client, _http1_client
    if _http_client is not None:
        await _http_client.aclose()
        _http_client = None
    if _http1_client is not None:
        await _http1_client.aclose()
        _http1_client = None


def _is_running_headless():
    """Check if running without a TTY (headless mode)."""
    try:
        return not os.isatty(sys.stdout.fileno())
    except Exception:
        return True


# =============================================================================
# UTILITY FUNCTIONS - Caching
# =============================================================================


def _get_cache_file_path(url: str) -> str:
    """Create a unique cache file path based on the URL hash."""
    url_hash = hashlib.sha256(url.encode()).hexdigest()
    systemd_cache = os.environ.get("CACHE_DIRECTORY")
    if systemd_cache:
        cache_dir = systemd_cache
    else:
        xdg_cache = os.environ.get("XDG_CACHE_HOME")
        base = xdg_cache if xdg_cache else os.path.expanduser("~/.cache")
        cache_dir = os.path.join(base, "vmcrawl")
    os.makedirs(cache_dir, mode=0o700, exist_ok=True)
    return os.path.join(cache_dir, f"{url_hash}.cache")


def _is_cache_valid(cache_file_path: str, max_age_seconds: int) -> bool:
    """Check if a cache file exists and is still valid."""
    if not os.path.exists(cache_file_path):
        return False
    cache_age = time.time() - os.path.getmtime(cache_file_path)
    return cache_age < max_age_seconds


# =============================================================================
# UTILITY FUNCTIONS - Validation
# =============================================================================


async def parse_json_with_fallback(
    response: httpx.Response,
    domain: str,
    target: str,
    suppress_errors: bool = False,
) -> Any | bool:
    """Parse JSON from response with fallback decoder for malformed JSON.

    Args:
        response: httpx Response object
        domain: Domain being processed (for error reporting)
        target: Target endpoint name (for error reporting)

    Returns:
        Parsed JSON data or False on error
    """

    def _normalize_common_json_issues(raw_text: str) -> str:
        """Normalize common non-standard JSON output seen on some instances."""
        text = raw_text.lstrip("\ufeff")
        # Fix JSON-with-trailing-commas (common in hand-written emitters).
        text = RE_JSON_TRAILING_COMMA.sub(r"\1", text)
        # Fix values emitted as: ""text"" (invalid JSON), e.g. nodeDescription.
        text = RE_JSON_DOUBLE_QUOTED_VALUE.sub(r': "\1"', text)
        return text

    try:
        return response.json()
    except json.JSONDecodeError:
        decoder = json.JSONDecoder()
        try:
            data, _ = decoder.raw_decode(response.text, 0)
            return data
        except json.JSONDecodeError:
            try:
                normalized_text = _normalize_common_json_issues(response.text)
                data, _ = decoder.raw_decode(normalized_text, 0)
                return data
            except json.JSONDecodeError as exception:
                if suppress_errors:
                    return False
                await asyncio.to_thread(
                    _handle_json_exception,
                    domain,
                    target,
                    exception,
                )
                return False


# =============================================================================
# HTTP FUNCTIONS
# =============================================================================


async def get_httpx(url: str, timeout: float | None = None) -> httpx.Response:
    """Make async HTTP GET request with size limits."""

    def _is_retryable_dns_error(exception: httpx.RequestError) -> bool:
        """Return True for transient DNS/connect failures worth a quick retry."""
        if isinstance(exception, (httpx.ConnectError, httpx.ConnectTimeout)):
            return True

        error_text = str(exception).casefold()
        dns_indicators = (
            "no address associated with hostname",
            "temporary failure in name resolution",
            "nodename nor servname provided",
            "name or service not known",
            "getaddrinfo",
        )
        if any(indicator in error_text for indicator in dns_indicators):
            return True

        # Walk chained causes for low-level resolver errors.
        seen: set[int] = set()
        cause: BaseException | None = exception
        while cause is not None and id(cause) not in seen:
            seen.add(id(cause))
            if isinstance(cause, socket.gaierror):
                return True
            cause = cause.__cause__ or cause.__context__

        return False

    def _compute_retry_delay_seconds(attempt: int, elapsed_backoff: float) -> float:
        """Calculate bounded exponential backoff with jitter."""
        if dns_retry_max_total_delay_ms <= 0:
            return 0.0

        base_delay = (dns_retry_base_delay_ms / 1000.0) * (2**attempt)
        jitter = random.uniform(
            -(dns_retry_jitter_ms / 1000.0),
            dns_retry_jitter_ms / 1000.0,
        )
        delay = max(0.0, base_delay + jitter)
        remaining_budget = max(
            0.0, (dns_retry_max_total_delay_ms / 1000.0) - elapsed_backoff
        )
        return min(delay, remaining_budget)

    async def _stream_get_with_size_limit(client: httpx.AsyncClient) -> httpx.Response:
        stream_kwargs: dict = {}
        if timeout is not None:
            stream_kwargs["timeout"] = timeout
        async with client.stream("GET", url, **stream_kwargs) as response:
            # Check Content-Length header first if available
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > max_response_size:
                msg = f"Response too large: {content_length} bytes (max: {max_response_size})"
                raise ValueError(msg)

            # Stream the response and check size as we download
            chunks = []
            total_size = 0

            async for chunk in response.aiter_bytes(chunk_size=8192):
                chunks.append(chunk)
                total_size += len(chunk)

                if total_size > max_response_size:
                    msg = f"Response too large: {total_size} bytes (max: {max_response_size})"
                    raise ValueError(msg)

            # All data received within size limit - construct final response
            final_response = httpx.Response(
                status_code=response.status_code,
                headers=response.headers,
                request=response.request,
            )
            # Directly set the content to bypass decompression
            final_response._content = b"".join(chunks)  # pyright: ignore[reportPrivateUsage]

            return final_response

    host = urlparse(url).hostname or ""
    semaphore = _get_host_semaphore(host) if host else None

    async def _run() -> httpx.Response:
        total_backoff = 0.0
        for attempt in range(dns_retry_attempts):
            try:
                try:
                    return await _stream_get_with_size_limit(get_http_client())
                except httpx.RemoteProtocolError:
                    # Some servers advertise HTTP/2 but terminate h2 sessions.
                    # Retry once with HTTP/1.1 for this request.
                    return await _stream_get_with_size_limit(get_http1_client())
            except httpx.RequestError as exception:
                if attempt >= dns_retry_attempts - 1 or not _is_retryable_dns_error(
                    exception
                ):
                    raise

                retry_delay = _compute_retry_delay_seconds(attempt, total_backoff)
                if retry_delay > 0:
                    await asyncio.sleep(retry_delay)
                    total_backoff += retry_delay

        # Defensive fallback: loop should always return or raise.
        msg = f"Failed to fetch URL after {dns_retry_attempts} attempts: {url}"
        raise RuntimeError(msg)

    if semaphore is None:
        return await _run()
    async with semaphore:
        return await _run()


async def get_domain_endings() -> set[str]:
    """Fetch and cache the set of valid TLDs from IANA.

    Uses database storage with a 7-day cache expiration.
    Falls back to file cache if database is unavailable.
    Excludes hardcoded unsupported TLDs before returning.
    """
    tlds: set[str] = set()

    # Try to get from database first
    try:
        last_updated = get_tld_last_updated()
        max_cache_age_days = 7

        # Check if database cache is valid (less than 7 days old)
        if last_updated:
            # Ensure last_updated is timezone-aware before subtracting.
            # PostgreSQL may return a naive datetime (TIMESTAMP WITHOUT TIME ZONE)
            # or an aware one (TIMESTAMP WITH TIME ZONE); handle both.
            if last_updated.tzinfo is None:
                last_updated = last_updated.replace(tzinfo=UTC)
            age = datetime.now(UTC) - last_updated
            if age.days < max_cache_age_days:
                tlds = get_tlds_from_db()
                if tlds:
                    return _exclude_tlds(tlds)

        # Database cache is stale or empty, fetch new data
        tlds = await fetch_tlds_from_iana()
        if tlds:
            _ = import_tlds(tlds)
            return _exclude_tlds(tlds)

    except Exception as e:
        echo(f"Database TLD lookup failed, using file cache: {e}", "yellow")

    # Fallback to file-based cache if database fails
    url = "http://data.iana.org/TLD/tlds-alpha-by-domain.txt"
    cache_file_path = _get_cache_file_path(url)
    max_cache_age = 604800  # 7 days in seconds

    if _is_cache_valid(cache_file_path, max_cache_age):
        with open(cache_file_path) as cache_file:
            # Use set for O(1) lookup
            tlds = {line.strip().lower() for line in cache_file if line.strip()}
            return _exclude_tlds(tlds)

    domain_endings_response = await get_httpx(url)
    if domain_endings_response.status_code in [200]:
        # Use set for O(1) lookup
        domain_endings = {
            line.strip().lower()
            for line in domain_endings_response.text.splitlines()
            if line.strip() and not line.startswith("#")
        }
        with open(cache_file_path, "w") as cache_file:
            _ = cache_file.write("\n".join(sorted(domain_endings)))
        return _exclude_tlds(domain_endings)

    msg = (
        f"Failed to fetch domain endings. "
        f"HTTP Status Code: {domain_endings_response.status_code}"
    )
    raise Exception(msg)


# =============================================================================
# VERSION FUNCTIONS - Mastodon Version Retrieval
# =============================================================================


async def read_main_version_info(url: str) -> dict[str, str] | None:
    """Parse Mastodon version.rb file to extract version information."""
    version_info: dict[str, str] = {}
    try:
        response = await get_httpx(url)
        _ = response.raise_for_status()
        lines = response.text.splitlines()

        for i, line in enumerate(lines):
            match = RE_FUNCTION_DEF.search(line)
            if match:
                key = match.group(1)
                if key in ["major", "minor", "patch", "default_prerelease"]:
                    if i + 1 >= len(lines):
                        continue
                    value = lines[i + 1].strip()
                    if value.isnumeric() or RE_QUOTED_STRING.match(value):
                        version_info[key] = value.replace("'", "")
    except (httpx.HTTPError, ValueError, RuntimeError) as exception:
        # ValueError/RuntimeError cover oversized/malformed responses and
        # exhausted retries from get_httpx, which are not httpx.HTTPError.
        echo(f"Failed to retrieve Mastodon main version: {exception}", "red")
        return None

    return version_info


async def get_highest_mastodon_version() -> str | None:
    """Get the highest stable Mastodon release version from GitHub."""
    highest_version: str | None = None
    try:
        release_url = "https://api.github.com/repos/mastodon/mastodon/releases"
        response = await get_httpx(release_url)
        if response.status_code == 200:
            releases = response.json()
            highest_version = None
            for release in releases:
                release_version = release["tag_name"].lstrip("v")
                if version.parse(release_version).is_prerelease:
                    continue
                if highest_version is None or version.parse(
                    release_version,
                ) > version.parse(highest_version):
                    highest_version = release_version
    except (httpx.HTTPError, ValueError, RuntimeError) as exception:
        # ValueError/RuntimeError cover oversized/malformed responses and
        # exhausted retries from get_httpx; ValueError also covers a malformed
        # response.json() (JSONDecodeError) and an unparseable release tag
        # (packaging's InvalidVersion) — all of which were previously uncaught.
        echo(f"Failed to retrieve Mastodon release version: {exception}", "red")
        return None

    return highest_version


async def get_all_tracked_mastodon_versions():
    """Get the latest version for each tracked branch (release + EOL) from GitHub.

    Uses gh CLI to get more releases (authenticated, higher limits).
    Returns a dict with only branches that have releases found on GitHub.
    Branches not found in recent releases are excluded (preserving their DB value).
    """
    # Get all tracked branches from database (release + EOL)
    branches = get_all_tracked_branches()
    tracked_versions = dict.fromkeys(branches, "")

    try:
        # Use gh CLI to get up to 500 releases (should cover all versions)
        result = subprocess.run(
            [
                "gh",
                "release",
                "list",
                "--repo",
                "mastodon/mastodon",
                "--limit",
                "500",
                "--json",
                "tagName",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        releases = json.loads(result.stdout)

        for release in releases:
            release_version = release["tagName"].lstrip("v")

            for branch in branches:
                if release_version.startswith(branch):
                    if not tracked_versions[branch] or (
                        version.parse(release_version)
                        > version.parse(tracked_versions[branch] or "0.0.0")
                    ):
                        tracked_versions[branch] = release_version

    except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError):
        # If gh fails, fall back to HTTP API
        echo("gh CLI failed, falling back to HTTP API", "yellow")
        try:
            url = "https://api.github.com/repos/mastodon/mastodon/releases"
            response = await get_httpx(url)
            _ = response.raise_for_status()
            releases = response.json()

            for release in releases:
                release_version = release["tag_name"].lstrip("v")

                for branch in branches:
                    if release_version.startswith(branch):
                        if not tracked_versions[branch] or (
                            version.parse(release_version)
                            > version.parse(tracked_versions[branch] or "0.0.0")
                        ):
                            tracked_versions[branch] = release_version
        except (httpx.HTTPError, ValueError, RuntimeError) as exception:
            # get_httpx/raise_for_status/response.json() or version parsing
            # failed; return whatever was gathered (possibly empty) so callers
            # preserve existing DB values instead of crashing the run.
            echo(
                f"Failed to retrieve tracked versions from GitHub: {exception}",
                "red",
            )

    # Only return branches that were actually found in GitHub releases
    # This prevents overwriting old EOL versions with placeholder values
    return {k: v for k, v in tracked_versions.items() if v}


async def get_main_version_release():
    """Get the current main branch version string."""
    version_info = None

    try:
        # Try using gh CLI first (returns raw file content)
        result = subprocess.run(
            [
                "gh",
                "api",
                "repos/mastodon/mastodon/contents/lib/mastodon/version.rb",
                "-H",
                "Accept: application/vnd.github.raw+json",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        content = result.stdout

        # Parse the version.rb content
        version_info = {}
        lines = content.splitlines()
        for i, line in enumerate(lines):
            match = RE_FUNCTION_DEF.search(line)
            if match:
                key = match.group(1)
                if key in ["major", "minor", "patch", "default_prerelease"]:
                    if i + 1 >= len(lines):
                        continue
                    value = lines[i + 1].strip()
                    if value.isnumeric() or RE_QUOTED_STRING.match(value):
                        version_info[key] = value.replace("'", "")

    except (subprocess.CalledProcessError, FileNotFoundError):
        # If gh fails, fall back to HTTP
        echo("gh CLI failed for main version, falling back to HTTP API", "yellow")
        url = "https://raw.githubusercontent.com/mastodon/mastodon/refs/heads/main/lib/mastodon/version.rb"
        version_info = await read_main_version_info(url)

    if not version_info:
        return "0.0.0-alpha.0"

    major = version_info.get("major", "0")
    minor = version_info.get("minor", "0")
    patch = version_info.get("patch", "0")
    pre = version_info.get("default_prerelease", "alpha.0")

    obtained_main_version = f"{major}.{minor}.{patch}-{pre}"
    return obtained_main_version


async def get_main_version_branch():
    """Get the current main branch number (e.g., '4.3')."""
    url = "https://raw.githubusercontent.com/mastodon/mastodon/refs/heads/main/lib/mastodon/version.rb"
    version_info = await read_main_version_info(url)
    if not version_info:
        return "0.0"

    major = version_info.get("major", "0")
    minor = version_info.get("minor", "0")

    obtained_main_branch = f"{major}.{minor}"
    return obtained_main_branch


def get_nightly_version_ranges() -> (
    list[tuple[str, datetime | None, datetime | None, bool]]
):
    """Get nightly version ranges from the database."""

    def _to_utc_datetime(value: date | datetime | None) -> datetime | None:
        """Normalize DATE/TIMESTAMP values from PostgreSQL to aware UTC datetimes."""
        if value is None:
            return None
        if isinstance(value, datetime):
            return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
        return datetime.combine(value, datetime.min.time(), tzinfo=UTC)

    with db_pool.connection() as conn, conn.cursor() as cur:
        _ = cur.execute(
            """
            SELECT version, start_date, end_date, is_security
            FROM nightly_versions
            ORDER BY start_date DESC
        """,
        )
        nightly_version_ranges = [
            (row[0], row[1], row[2], row[3]) for row in cur.fetchall()
        ]
        nightly_version_ranges = [
            (
                version,
                _to_utc_datetime(start_date),
                _to_utc_datetime(end_date),
                bool(is_security),
            )
            for version, start_date, end_date, is_security in nightly_version_ranges
        ]
    return nightly_version_ranges


# =============================================================================
# VERSION FUNCTIONS - Version String Cleaning
# =============================================================================


def _parse_version(version: str) -> tuple[int, int, int, str | None] | None:
    """Parse a version string into its components.

    Returns tuple of (major, minor, patch, prerelease) or None if invalid.
    """
    match = RE_VERSION_PARTS.match(version)
    if match:
        return int(match[1]), int(match[2]), int(match[3]), match[4]
    return None


def clean_version(
    software_version_full: str,
    nightly_version_ranges: list[tuple[str, datetime | None, datetime | None, bool]],
) -> str:
    """Apply all version cleaning transformations.

    Optimized to use pre-compiled regex patterns and minimize string operations.
    Follows the original processing order to maintain identical behavior.
    """
    # Phase 1: Strip primary suffixes (single regex split instead of 8 chained splits)
    version = RE_VERSION_SUFFIX_SPLIT.split(software_version_full, maxsplit=1)[0]

    # Phase 2: Normalize strings and fix formatting issues (includes double-dash fix)
    version = _clean_version_normalize(version)

    # Phase 3: Convert date-based suffixes to nightly format
    version = _clean_version_date(version)

    # Phase 4: Remove additional suffixes (conditional on prerelease presence)
    version = _clean_version_suffix_conditional(version)

    # Phase 5: Normalize development version formats (rc, beta)
    version = RE_VERSION_RC.sub(r"-rc.\1", version)
    version = RE_VERSION_BETA.sub(r"-beta.\1", version)
    version = RE_VERSION_MULTIPLE_DASHES.sub("-", version)  # Fix dashes from Phase 5

    # Phase 6: Map nightly versions to releases
    version = _clean_version_nightly(version, nightly_version_ranges)

    # Phase 7: Version-specific fixes (parse once, use for multiple checks)
    version = _clean_version_fixes(version)

    return version


def _clean_version_normalize(version: str) -> str:
    """Remove unwanted strings, fix typos, and normalize formatting."""
    # Remove -pre suffix and everything after
    if "-pre" in version:
        version = version.split("-pre", maxsplit=1)[0]

    # Remove known unwanted strings and fix typos
    version = (
        version.replace("-theconnector", "")
        .replace("-theatlsocial", "")
        .replace("mastau", "alpha")
    )
    version = RE_VERSION_MULTIPLE_DASHES.sub("-", version).rstrip("-")

    # Truncate versions with extra components (e.g., "4.5.4.0.5" -> "4.5.4")
    # Only truncates if remainder starts with "." (extra version components)
    # Preserves malformed prerelease tags for later processing
    if not RE_VERSION_PARTS.match(version):
        match = RE_VERSION_EXTRACT_SEMVER.match(version)
        if match:
            base = match.group(1)
            remainder = version[match.end() :]
            if remainder.startswith("."):
                # Extra version components - find where prerelease starts
                # e.g., "4.3.0.1-alpha.1" -> base "4.3.0", keep "-alpha.1"
                dash_pos = remainder.find("-")
                if dash_pos != -1:
                    version = base + remainder[dash_pos:]
                else:
                    version = base

    return version


def _clean_version_date(version: str) -> str:
    """Convert date-based suffixes to nightly format."""
    match = RE_VERSION_DATE_SUFFIX.search(version)
    if match:
        yy, mm, dd = match.groups()
        try:
            datetime.strptime(f"20{yy}-{mm}-{dd}", "%Y-%m-%d")
        except ValueError:
            return version
        return RE_VERSION_DATE_SUFFIX.sub(f"-nightly.20{yy}-{mm}-{dd}", version)
    return version


def _clean_version_suffix_conditional(version: str) -> str:
    """Remove additional suffixes unless they are valid prerelease identifiers."""
    if not RE_VERSION_HAS_PRERELEASE.search(version):
        version = RE_VERSION_ALPHA_SUFFIX.split(version, maxsplit=1)[0]
    if "nightly" not in version:
        version = RE_VERSION_DIGIT_SUFFIX.split(version, maxsplit=1)[0]
    return version


def _clean_version_nightly(
    version: str,
    nightly_version_ranges: list[tuple[str, datetime | None, datetime | None, bool]],
) -> str:
    """Map nightly versions to their corresponding release versions."""
    # Remove simple nightly date format
    version = RE_VERSION_NIGHTLY_DATE.sub("", version)

    # Check for detailed nightly format
    match = RE_VERSION_NIGHTLY.match(version)
    if match:
        nightly_date_str, is_security = match.groups()
        try:
            nightly_date = datetime.strptime(nightly_date_str, "%Y-%m-%d").replace(
                tzinfo=UTC
            )
        except ValueError:
            return version

        if is_security:
            # A "-security" build is a dedicated release image. If it has an
            # explicit security pin (start_date = the build's labelled date),
            # use it directly so it stays mapped regardless of how the regular
            # nightly stream moves around it.
            for ver, start_date, _end_date, sec in nightly_version_ranges:
                if sec and start_date is not None and start_date == nightly_date:
                    return ver
            # No pin: fall back to legacy behavior. The "-security" image is
            # labelled with the next nightly's date, so shift forward a day.
            nightly_date += timedelta(days=1)

        for ver, start_date, end_date, sec in nightly_version_ranges:
            if (
                not sec
                and start_date is not None
                and end_date is not None
                and start_date <= nightly_date <= end_date
            ):
                return ver

    return version


_clean_version_fixes_warned = False


def _clean_version_fixes(version: str) -> str:
    """Apply version-specific fixes using parsed components."""
    global _clean_version_fixes_warned
    if (
        not version_main_branch
        and not version_latest_release
        and not _clean_version_fixes_warned
    ):
        echo(
            "Warning: version globals not loaded; version-fixing logic will be skipped",
            "yellow",
        )
        _clean_version_fixes_warned = True

    # Handle arbitrary trailing letter suffixes (e.g., "3.4.6ht", "4.2.10kb10")
    # These are fork/instance identifiers that should be stripped
    trailing_match = RE_VERSION_TRAILING_SUFFIX.match(version)
    if trailing_match:
        # Check if it's a known prerelease tag that needs special handling
        suffix_start = len(trailing_match.group(1))
        suffix = version[suffix_start:]
        if not RE_VERSION_MALFORMED_PRERELEASE.match(suffix):
            # Not a prerelease tag, strip the suffix entirely
            version = trailing_match.group(1)

    # Handle malformed prerelease tags (e.g., "4.3.4alpha1" without dash)
    # For non-zero patch: strip them entirely (4.3.4alpha1 -> 4.3.4)
    # For zero patch: normalize them (4.3.0alpha1 -> 4.3.0-alpha.1)
    malformed_match = RE_VERSION_MALFORMED_PRERELEASE.search(version)
    if malformed_match:
        base_version = version[: malformed_match.start()].rstrip("-")
        # Check if this is a zero patch version
        base_parts = base_version.split(".")
        if len(base_parts) == 3 and base_parts[2] == "0":
            # Zero patch: normalize the prerelease tag
            tag = malformed_match.group(0)
            # Convert "alpha1" to "-alpha.1", "beta2" to "-beta.2", etc.
            normalized = RE_VERSION_RC.sub(r"-rc.\1", tag)
            normalized = RE_VERSION_BETA.sub(r"-beta.\1", normalized)
            normalized = RE_VERSION_ALPHA.sub(r"-alpha.\1", normalized)
            version = base_version + normalized
        else:
            # Non-zero patch: strip the malformed tag
            version = base_version

    # Add missing prerelease suffix to main branch versions
    if (
        version_main_branch
        and version.startswith(version_main_branch)
        and "-" not in version
    ):
        return f"{version}-alpha.1"

    # Strip prerelease suffix from stable release versions
    if (
        version_latest_release
        and version.startswith(version_latest_release)
        and "-" in version
        and not version_latest_release.endswith(".0")
    ):
        return version.split("-", maxsplit=1)[0]

    # Parse version for remaining checks
    parts = _parse_version(version)
    if not parts:
        return version

    x, y, z, prerelease = parts

    # Remove prerelease suffix from non-zero patch versions
    if z != 0 and prerelease:
        return f"{x}.{y}.{z}"

    # Correct patch versions that exceed the latest release
    if version_latest_release:
        _vlr_parts = version_latest_release.split(".")
        if len(_vlr_parts) >= 3:
            a, b, c = (
                int(_vlr_parts[0]),
                int(_vlr_parts[1]),
                int(_vlr_parts[2].split("-")[0]),
            )
        else:
            a, b, c = (0, 0, 0)
    else:
        a, b, c = (0, 0, 0)

    _vmb_parts = version_main_branch.split(".") if version_main_branch else []
    m = int(_vmb_parts[1]) if len(_vmb_parts) >= 2 else 0

    if x == a:
        if y == b and z > c:
            return f"{x}.{y}.0{prerelease or ''}"
        if y == m and z != 0:
            return f"{x}.{y}.0{prerelease or ''}"

    return version


# =============================================================================
# DATABASE FUNCTIONS - Patch Versions
# =============================================================================


def get_backport_branches() -> list[str]:
    """Get list of active backport branches from the database.

    Replaces the hardcoded backport_branches list.
    Returns branches in order by n_level (newest first).
    """
    with db_pool.connection() as conn, conn.cursor() as cur:
        try:
            _ = cur.execute(
                """
                SELECT branch
                FROM release_versions
                WHERE status = 'release'
                ORDER BY n_level
                """,
            )
            return [row[0] for row in cur.fetchall()]
        except Exception as e:
            echo(f"Failed to load backport branches from database: {e}", "red")
            return []


def get_all_tracked_branches() -> list[str]:
    """Get list of all tracked branches (release + EOL) from the database.

    Used for updating version information from GitHub.
    Returns branches in order by n_level (newest first).
    """
    with db_pool.connection() as conn, conn.cursor() as cur:
        try:
            _ = cur.execute(
                """
                SELECT branch
                FROM release_versions
                WHERE status IN ('release', 'eol')
                ORDER BY n_level
                """,
            )
            return [row[0] for row in cur.fetchall()]
        except Exception as e:
            echo(f"Failed to load tracked branches from database: {e}", "red")
            return []


def get_release_versions_from_db() -> dict[str, Any]:
    """Load release version information from the database.

    Returns a dictionary with version information from the release_versions table.
    """
    with db_pool.connection() as conn, conn.cursor() as cur:
        try:
            # Get all versions ordered by n_level
            _ = cur.execute(
                """
                SELECT branch, status, n_level, latest
                FROM release_versions
                ORDER BY n_level
                """,
            )
            all_results = cur.fetchall()

            if not all_results:
                return {}

            result = {}
            main_version = None
            main_branch_value = None
            release_versions = []

            for row in all_results:
                branch, status, n_level, latest = row

                # n_level = -1 is the main branch
                if n_level == -1:
                    main_version = latest
                    main_branch_value = branch

                # n_level >= 0 are release branches
                if status == "release" and n_level >= 0:
                    release_versions.append(latest)

            if main_version:
                result["main_release"] = main_version
                result["main_branch"] = main_branch_value

            if release_versions:
                result["latest_stable"] = release_versions[0]
                result["backport_releases"] = release_versions

                # Build all_patched list
                if main_version:
                    result["all_patched"] = [main_version] + release_versions
                else:
                    result["all_patched"] = release_versions

            return result
        except Exception as e:
            echo(f"Failed to load version info from database: {e}", "red")
            return {}


# =============================================================================


# =============================================================================
# DATABASE FUNCTIONS - Error Logging
# =============================================================================


def log_error(domain: str, error_to_print: str) -> None:
    """Log an error for a domain to the error_log table."""
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            _ = cursor.execute(
                """
                    INSERT INTO error_log (domain, error)
                    VALUES (%s, %s)
                """,
                (domain, error_to_print),
            )
            conn.commit()
        except Exception as exception:
            echo(
                f"{domain}: Failed to log error {exception}",
                "red",
                use_tqdm=True,
            )
            conn.rollback()


def get_error_type(reason: str | None) -> str | None:
    """Classify a reason string by its leading token.

    HTTP status codes map to HTTP{2,3,4,5}XX; the explicit prefixes map to
    themselves. Mirrors the SQL classification in ``_REASON_BASE_HOURS_CASE`` so
    Python-side decisions (error counting, purge-at-detection) agree with the
    reschedule cadence the queue derives from the same reason.
    """
    if not reason or len(reason) < 3:
        return None
    if reason[0] in "2345" and reason[1:3].isdigit():
        return f"HTTP{reason[0]}XX"
    return next((t for t in TRACKED_ERROR_TYPES if reason.startswith(t)), None)


def increment_domain_error(domain: str, error_reason: str) -> None:
    """Record a crawl failure's classification in ``reason``.

    There are no terminal bad_* flags and no error counter. Scheduling is derived
    from ``reason`` by the queue (see ``reschedule_domain``); this function just
    records the latest failure reason.

    HARD (gone: 410/451/418/999) and ROBOT (robots.txt disallow) are definitive,
    so on detection the domain is purged from the published mastodon_domains list
    immediately; it still records its reason and reschedules on its long interval.
    All other failure types leave the published row untouched (last-known-good).

    Note: Domain is expected to be pre-normalized to lowercase by caller.
    """
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            _ = cursor.execute(
                "SELECT alias FROM raw_domains WHERE domain = %s",
                (domain,),
            )
            result = cursor.fetchone()
            # Aliases are canonicalized elsewhere; never record errors on them.
            if result and result[0]:
                return

            # Definitive "gone"/disallowed: drop from the published list at detection.
            if get_error_type(error_reason) in PURGE_ON_DETECTION_TYPES:
                delete_domain_if_known(domain)

            _ = cursor.execute(
                "INSERT INTO raw_domains (domain, reason)"
                " VALUES (%s, %s)"
                " ON CONFLICT(domain) DO UPDATE SET reason = EXCLUDED.reason",
                (domain, error_reason),
            )
            conn.commit()
        except Exception as exception:
            echo(
                f"{domain}: Failed to increment domain error {exception}",
                "red",
                use_tqdm=True,
            )
            conn.rollback()


def clear_domain_error(domain: str) -> None:
    """Clear a domain's recorded error reason.

    Note: Domain is expected to be pre-normalized to lowercase by caller.
    """
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            _ = cursor.execute(
                "INSERT INTO raw_domains (domain, reason)"
                " VALUES (%s, NULL)"
                " ON CONFLICT(domain) DO UPDATE SET reason = excluded.reason",
                (domain,),
            )
            conn.commit()
        except Exception as exception:
            echo(
                f"{domain}: Failed to clear domain errors {exception}",
                "red",
                use_tqdm=True,
            )
            conn.rollback()


def _save_matrix_nodeinfo(domain: str) -> None:
    """Save nodeinfo as 'matrix' for Matrix servers.

    Note: Domain is expected to be pre-normalized to lowercase by caller.
    """
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            _ = cursor.execute(
                """
                    INSERT INTO raw_domains (domain, nodeinfo, reason)
                    VALUES (%s, %s, %s)
                    ON CONFLICT(domain) DO UPDATE SET
                    nodeinfo = excluded.nodeinfo,
                    reason = excluded.reason
                """,
                (domain, "matrix", None),
            )
            conn.commit()
        except Exception as exception:
            echo(
                f"{domain}: Failed to save Matrix nodeinfo {exception}",
                "red",
                use_tqdm=True,
            )
            conn.rollback()


# =============================================================================
# DATABASE FUNCTIONS - Domain CRUD Operations
# =============================================================================


def delete_domain_if_known(domain: str) -> None:
    """Delete a domain from the mastodon_domains table."""
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            _ = cursor.execute(
                """
                    DELETE FROM mastodon_domains WHERE domain = %s
                    """,
                (domain,),
            )
            conn.commit()
        except Exception as exception:
            echo(
                f"{domain}: Failed to delete known domain {exception}",
                "red",
                use_tqdm=True,
            )
            conn.rollback()


def mark_domain_as_alias(domain: str) -> None:
    """Mark a domain as an alias in raw_domains and clear all other state.

    When a domain is identified as an alias to another canonical domain,
    all error tracking, flags, and status information should be cleared
    since they no longer apply.

    Args:
        domain: The domain to mark as an alias (should be pre-normalized to lowercase)
    """
    # Build list of all state columns to clear
    state_columns = ["reason", "nodeinfo"]

    # Build SET clause: alias = TRUE, col1 = NULL, col2 = NULL, ...
    set_clause = sql.SQL("alias = TRUE, ") + sql.SQL(", ").join(
        sql.SQL("{} = NULL").format(sql.Identifier(col)) for col in state_columns
    )

    query = sql.SQL("""
        INSERT INTO raw_domains (domain, alias)
        VALUES (%s, TRUE)
        ON CONFLICT(domain) DO UPDATE SET {}
    """).format(set_clause)

    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            _ = cursor.execute(query, (domain,))
            conn.commit()
        except Exception as exception:
            echo(
                f"{domain}: Failed to mark as alias: {exception}",
                "red",
                use_tqdm=True,
            )
            conn.rollback()


def delete_domain_from_raw(domain: str) -> None:
    """Delete a domain from the raw_domains table."""
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            _ = cursor.execute(
                """
                    DELETE FROM raw_domains WHERE domain = %s
                    """,
                (domain,),
            )
            conn.commit()
        except Exception as exception:
            echo(
                f"{domain}: Failed to delete known domain {exception}",
                "red",
                use_tqdm=True,
            )
            conn.rollback()


def save_nodeinfo_software(domain: str, software_data: dict[str, Any]) -> None:
    """Save software name from nodeinfo to raw_domains.nodeinfo for the domain.

    When nodeinfo is set to non-Mastodon-compatible software, also clears
    reason since this is not an error condition - it's just a different platform.

    Args:
        domain: The domain being processed
        software_data: The 'software' dict from nodeinfo_20_result (contains
            'name')

    Note: Domain is expected to be pre-normalized to lowercase by caller.
    """
    software_name = software_data.get("name", "unknown").lower().replace(" ", "-")

    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            if not is_mastodon_compatible_software(software_name):
                # For non-Mastodon platforms, clear reason
                _ = cursor.execute(
                    """
                        INSERT INTO raw_domains
                        (domain, nodeinfo, reason)
                        VALUES (%s, %s, %s)
                        ON CONFLICT(domain) DO UPDATE SET
                        nodeinfo = excluded.nodeinfo,
                        reason = excluded.reason
                        """,
                    (domain, software_name, None),
                )
            else:
                # For Mastodon-compatible software, just update nodeinfo
                _ = cursor.execute(
                    """
                        INSERT INTO raw_domains (domain, nodeinfo)
                        VALUES (%s, %s)
                        ON CONFLICT(domain) DO UPDATE SET
                        nodeinfo = excluded.nodeinfo
                        """,
                    (domain, software_name),
                )
            conn.commit()
        except Exception as exception:
            echo(
                f"{domain}: Failed to save nodeinfo software {exception}",
                "red",
                use_tqdm=True,
            )
            conn.rollback()


def update_mastodon_domain(
    actual_domain,
    software_version,
    software_version_full,
    active_month_users,
):
    """Insert or update a Mastodon domain in the database.

    Uses timestamp checking to prevent stale data from overwriting fresh data
    when multiple crawlers process the same domain concurrently.
    """
    # Validate that domain is not empty
    if not actual_domain or not actual_domain.strip():
        echo("Attempted to insert empty domain, skipping", "yellow", use_tqdm=True)
        return

    actual_domain = actual_domain.strip().lower()

    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            new_timestamp = datetime.now(UTC)
            _ = cursor.execute(
                """
                    INSERT INTO mastodon_domains
                    (domain, software_version,
                     active_users_monthly, timestamp, full_version)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT(domain) DO UPDATE SET
                    software_version = excluded.software_version,
                    active_users_monthly = excluded.active_users_monthly,
                    timestamp = excluded.timestamp,
                    full_version = excluded.full_version
                    WHERE mastodon_domains.timestamp < excluded.timestamp
                """,
                (
                    actual_domain,
                    software_version,
                    active_month_users,
                    new_timestamp,
                    software_version_full,
                ),
            )
            conn.commit()
        except Exception as exception:
            echo(f"{actual_domain}: {exception}", "red", use_tqdm=True)
            conn.rollback()


def cleanup_old_domains():
    """Delete known domains older than 3 days.

    Uses a transaction-scoped advisory lock to ensure only one crawler instance
    performs cleanup at a time, preventing race conditions where multiple
    instances might delete domains that other instances just updated.
    """
    # Use a fixed advisory lock ID for cleanup operations
    CLEANUP_LOCK_ID = 999999999

    try:
        with db_pool.connection() as conn, conn.cursor() as cursor:
            try:
                # Try to acquire cleanup lock (non-blocking). Transaction-scoped lock
                # auto-releases on commit/rollback, which is safer with pooled connections.
                _ = cursor.execute(
                    "SELECT pg_try_advisory_xact_lock(%s)", (CLEANUP_LOCK_ID,)
                )
                result = cursor.fetchone()
                lock_acquired = result[0] if result else False

                if not lock_acquired:
                    # Another instance is already running cleanup, skip
                    echo(
                        "cleanup_old_domains: skipped (advisory lock held by another session)",
                        "yellow",
                    )
                    return

                _ = cursor.execute(
                    """
                        DELETE FROM mastodon_domains
                        WHERE timestamp <=
                            (CURRENT_TIMESTAMP - INTERVAL '72 hours')::timestamp
                        RETURNING domain
                        """,
                )
                deleted_domains = [row[0] for row in cursor.fetchall()]
                if deleted_domains:
                    for d in deleted_domains:
                        echo(
                            f"{d}: Removed from active instance list",
                            "yellow",
                            use_tqdm=True,
                        )
                conn.commit()
            except Exception as exception:
                echo(f"Failed to clean up old domains: {exception}", "red")
                conn.rollback()
    except psycopg.Error as exception:
        # Couldn't even acquire a connection (pool exhausted or backend
        # unreachable, e.g. a dropped SSH tunnel). Skip cleanup this cycle
        # rather than crashing the crawler.
        echo(f"Failed to clean up old domains: {exception}", "red")


# =============================================================================
# DATABASE FUNCTIONS - Domain List Retrieval
# =============================================================================


def get_dni_domains():
    """Get list of DNI (Do Not Interact) domains to filter domains.

    Only returns domains with force='hard' for enforcement.
    Domains with force='soft' are stored but not actively enforced.
    """
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            _ = cursor.execute("SELECT domain FROM dni WHERE force = 'hard'")
            # Use set for O(1) lookup instead of O(n) list iteration
            return {row[0] for row in cursor}
        except Exception as exception:
            echo(f"Failed to obtain DNI domain list: {exception}", "red")
            conn.rollback()
    return set()


def get_not_masto_domains():
    """Get list of domains where nodeinfo is not Mastodon-compatible."""
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            query = sql.SQL(
                "SELECT domain FROM raw_domains "
                "WHERE nodeinfo IS NOT NULL AND nodeinfo NOT IN {clause}"
            ).format(clause=_MASTODON_COMPATIBLE_IN_CLAUSE)
            _ = cursor.execute(query)
            # Use set for O(1) lookup, stream results
            return {row[0].strip() for row in cursor if row[0] and row[0].strip()}
        except Exception as exception:
            echo(f"Failed to obtain non-mastodon domains: {exception}", "red")
            conn.rollback()
    return set()


async def load_domain_filter_data():
    """Load all domain filter data in parallel.

    Returns a dictionary containing all filter sets needed for crawling.
    Uses asyncio.gather with to_thread to run database queries concurrently.
    """
    (
        dni_domains,
        not_masto_domains,
        nightly_version_ranges,
    ) = await asyncio.gather(
        asyncio.to_thread(get_dni_domains),
        asyncio.to_thread(get_not_masto_domains),
        asyncio.to_thread(get_nightly_version_ranges),
    )

    return {
        "dni_domains": dni_domains,
        "not_masto_domains": not_masto_domains,
        "nightly_version_ranges": nightly_version_ranges,
    }


# =============================================================================
# FETCH FUNCTIONS - Peer Discovery
# =============================================================================


def ensure_mastodon_peers_column() -> bool:
    """Ensure mastodon_domains has a peers column used by fetch mode."""
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            _ = cursor.execute(
                "ALTER TABLE mastodon_domains "
                "ADD COLUMN IF NOT EXISTS peers BOOLEAN DEFAULT TRUE"
            )
            conn.commit()
            return True
        except Exception as e:
            echo(f"Failed to ensure peers column exists: {e}", "red")
            conn.rollback()
            return False


def fetch_domain_list(db_limit, db_offset, randomize=False):
    """Fetch list of domains to query for peers.

    When not randomizing, uses SQL LIMIT/OFFSET for efficiency.
    When randomizing, fetches all qualifying domains then shuffles in Python.
    """
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            min_active = int(os.getenv("VMCRAWL_FETCH_MIN_ACTIVE", "100"))

            base_query = sql.SQL(
                "SELECT domain FROM mastodon_domains "
                "WHERE active_users_monthly > %s "
                "AND (peers IS NULL OR peers = TRUE) "
                "ORDER BY active_users_monthly DESC"
            )
            base_params = (min_active,)

            if randomize:
                # For random selection, fetch all and shuffle in Python
                _ = cursor.execute(base_query, base_params)
                # Stream results through cursor iterator
                result = [row[0] for row in cursor]
                random.shuffle(result)
                # Apply limit after shuffle
                result = result[: int(db_limit)]
            else:
                # For ordered selection, use SQL LIMIT/OFFSET for efficiency
                fetch_limit = int(db_limit) + int(db_offset)
                query_with_limit = base_query + sql.SQL(" LIMIT %s")
                _ = cursor.execute(query_with_limit, (*base_params, fetch_limit))
                all_domains = [row[0] for row in cursor]
                start = int(db_offset)
                end = start + int(db_limit)
                result = all_domains[start:end]

            return result if result else ["vmst.io"]
        except Exception as e:
            echo(f"Failed to obtain primary domain list: {e}", "red")
            conn.rollback()
            return None


def get_existing_domains() -> set[str] | None:
    """Get set of domains already in raw_domains table.

    Returns a set directly for O(1) membership testing, avoiding
    intermediate list allocation.
    """
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            _ = cursor.execute("SELECT domain FROM raw_domains")
            # Build set directly from cursor iterator (memory efficient)
            existing_domains = {row[0] for row in cursor}
            conn.commit()
            return existing_domains
        except Exception as e:
            echo(f"Failed to get list of existing domains: {e}", "red")
            conn.rollback()
            return None


def disable_peer_fetch(domain, use_tqdm=False):
    """Disable peer polling for a domain in mastodon_domains."""
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            _ = cursor.execute(
                "UPDATE mastodon_domains SET peers = FALSE WHERE domain = %s",
                (domain,),
            )
            if cursor.rowcount > 0:
                echo(f"{domain}: peer polling disabled", "orange", use_tqdm=use_tqdm)
            conn.commit()
        except Exception as e:
            echo(
                f"Failed to disable peer polling for {domain}: {e}",
                "orange",
                use_tqdm=use_tqdm,
            )
            conn.rollback()
            return


# Each row contributes 1 bind param (domain); Postgres caps a single statement at
# 65535 params, so chunk well under that. A peers list can be tens of thousands of
# domains (a large instance returns 30k+), which would otherwise blow the limit in
# one multi-row INSERT.
_IMPORT_CHUNK = 1000


def import_domains(domains, use_tqdm=False):
    """Import new domains into raw_domains table (chunked, ON CONFLICT DO NOTHING)."""
    if not domains:
        return
    # De-dup while normalizing so a single batch can't carry the same domain twice.
    unique = list({d.lower() for d in domains})
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            for start in range(0, len(unique), _IMPORT_CHUNK):
                chunk = unique[start : start + _IMPORT_CHUNK]
                placeholders = sql.SQL(",").join(sql.SQL("(%s)") for _ in chunk)
                query = sql.SQL(
                    "INSERT INTO raw_domains (domain) VALUES {} "
                    "ON CONFLICT (domain) DO NOTHING"
                ).format(placeholders)
                _ = cursor.execute(query, chunk)
            conn.commit()
        except Exception as e:
            echo(f"Failed to import domain list: {e}", "red", use_tqdm=use_tqdm)
            conn.rollback()
            return


def _is_valid_fetch_domain(domain):
    """Check if a domain string is valid for fetching."""
    return (
        RE_DOMAIN_FORMAT.match(domain)
        and not _is_ip_address(domain)
        and not _detect_vowels(domain)
    )


def _is_ip_address(domain):
    """Check if a string is an IP address."""
    try:
        _ = ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def _detect_vowels(domain):
    """Detect domains with suspicious vowel patterns."""
    try:
        return bool(RE_VOWEL_PATTERN.search(domain))
    except Exception as e:
        echo(f"Error detecting vowels: {e}", "red")
        return False


async def fetch_peer_domains(
    api_url,
    domain,
    domain_endings,
    dni,
):
    """Fetch peer domains from a Mastodon instance API.

    Args:
        api_url: The API URL to fetch peers from
        domain: The domain being queried
        domain_endings: Set of valid TLDs (e.g., {"com", "org"})
        dni: Set of DNI domains to filter out

    Returns:
        tuple: (list of filtered domains, error_type or None)
            error_type can be: None (success), "no_peers", "transient"
    """
    try:
        api_response = await get_httpx(api_url)
        data = api_response.json()

        # Filter domains using O(1) TLD membership checks
        filtered_domains = []
        for item in data:
            # Skip invalid domains early (most common rejection)
            if not item.islower() or not _is_valid_fetch_domain(item):
                continue

            # Check against DNI list (substring match required)
            if _is_dni_domain(item, dni):
                continue

            # Check valid TLD using direct O(1) set membership
            if not _has_valid_tld(item, domain_endings):
                continue

            filtered_domains.append(item)

        return (filtered_domains, None)
    except json.JSONDecodeError:
        # JSON decode errors indicate HTML or non-JSON response - disable polling
        await asyncio.to_thread(disable_peer_fetch, domain, True)
        return ([], "no_peers")
    except Exception as e:
        error_str = str(e).lower()

        # Only disable polling for persistent issues, not transient errors
        # Authentication issues: 401, 403, unauthorized, forbidden
        # 404 errors: endpoint doesn't exist
        persistent_error_indicators = [
            "401",
            "403",
            "404",
            "unauthorized",
            "forbidden",
            "not authorized",
        ]

        if any(indicator in error_str for indicator in persistent_error_indicators):
            await asyncio.to_thread(disable_peer_fetch, domain, True)
            return ([], "no_peers")
        else:
            # Transient errors - don't mark the domain
            return ([], "transient")


async def process_fetch_domain(
    domain,
    domain_endings,
    pbar,
    dni,
    existing_domains,
):
    """Process a single domain to fetch its peers.

    Args:
        domain: Domain to fetch peers from
        domain_endings: Set of valid TLDs (e.g., {"com", "org"})
        pbar: tqdm progress bar instance for status updates
        dni: Set of DNI domains to filter out
        existing_domains: Set of domains already in database

    Returns:
        tuple: (domain, unique_domains list, status message or None, status color)
    """
    # Use fixed-width display to prevent bar from jumping (truncate long domains)
    domain_display = domain[:25].ljust(25)
    pbar.set_postfix_str(domain_display)
    pbar.refresh()

    api_url = f"https://{domain}/api/v1/instance/peers"

    domains, error_type = await fetch_peer_domains(api_url, domain, domain_endings, dni)
    unique_domains = [d for d in domains if d not in existing_domains]

    if unique_domains:
        status = f"{len(unique_domains)} new"
        status_color = "green"
        await asyncio.to_thread(import_domains, unique_domains, True)
    elif domains:
        status = f"0 new ({len(domains)} known)"
        status_color = "cyan"
    elif error_type == "no_peers":
        # disable_peer_fetch() already emits an orange terminal alert
        status = None
        status_color = "cyan"
    elif error_type == "transient":
        status = "Error (transient)"
        status_color = "yellow"
    else:
        status = "No peers"
        status_color = "yellow"

    return (domain, unique_domains, status, status_color)


def get_peers_fetch_eligibility(domain: str) -> tuple[int, bool] | None:
    """Return (active_users_monthly, peers_enabled) for a known Mastodon instance.

    Returns None when the domain is not in mastodon_domains (not a valid Mastodon
    server, so not a peer-discovery source). ``peers`` NULL is treated as enabled.
    Used by the queue daemon's inline peer discovery.
    """
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            _ = cursor.execute(
                "SELECT active_users_monthly, peers FROM mastodon_domains "
                "WHERE domain = %s",
                (domain,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            return (row[0] or 0, row[1] is not False)
        except Exception as exception:
            echo(
                f"{domain}: Failed to read peer eligibility {exception}",
                "red",
                use_tqdm=True,
            )
            conn.rollback()
            return None


async def maybe_fetch_peers(domain: str, domain_endings, dni) -> None:
    """Inline peer discovery for the queue daemon (see docs/durable-queue.md).

    Called after a domain is crawled in queue mode. When the domain is a healthy
    Mastodon instance with more than ``peers_min_active`` monthly users and its
    peers endpoint has not been disabled, fetch its peers and import any new
    domains into raw_domains (where they become due immediately). Failure
    handling — transient vs. disabling a dead endpoint — is delegated to
    ``fetch_peer_domains``; imports are ON CONFLICT DO NOTHING.
    """
    eligibility = await asyncio.to_thread(get_peers_fetch_eligibility, domain)
    if eligibility is None:
        return
    active_users, peers_enabled = eligibility
    if not peers_enabled or active_users <= peers_min_active:
        return

    api_url = f"https://{domain}/api/v1/instance/peers"
    domains, _error_type = await fetch_peer_domains(api_url, domain, domain_endings, dni)
    if domains:
        await asyncio.to_thread(import_domains, domains, True)


async def run_fetch_mode(args: argparse.Namespace) -> int:
    """Run the fetch mode to discover new domains from instance peers."""
    # Validate argument combinations
    if (args.limit or args.offset) and args.target:
        echo("You cannot set both limit/offset and target arguments", "red")
        return EXIT_FAILURE

    if args.offset and args.random:
        echo("You cannot set both offset and random arguments", "red")
        return EXIT_FAILURE

    # Set defaults from arguments or environment
    if args.limit is not None:
        db_limit = args.limit
    else:
        db_limit = int(os.getenv("VMCRAWL_FETCH_LIMIT", "10"))

    if args.offset is not None:
        db_offset = args.offset
    else:
        db_offset = int(os.getenv("VMCRAWL_FETCH_OFFSET", "0"))

    echo(f"{appname} v{appversion} (fetch mode)", "bold")
    if _is_running_headless():
        echo("Running in headless mode", "cyan")

    if not ensure_mastodon_peers_column():
        echo("Failed to prepare fetch schema, exiting…", "red")
        return EXIT_FAILURE

    domain_endings = await get_domain_endings()

    if args.target is not None:
        domain_list = [args.target]
    else:
        domain_list = fetch_domain_list(db_limit, db_offset, randomize=args.random)

    if not domain_list:
        echo("No domains fetched, exiting…", "yellow")
        return EXIT_FAILURE

    echo(f"Fetching peer data from {len(domain_list)} instances…", "cyan")

    # Pre-fetch filter lists once before concurrent processing
    dni = get_dni_domains() or set()
    existing_domains = get_existing_domains() or set()

    # Collect all newly discovered domains
    all_new_domains = []
    max_workers = int(os.getenv("VMCRAWL_MAX_THREADS", "2"))
    heartbeat_seconds = int(os.getenv("VMCRAWL_PROGRESS_HEARTBEAT_SECONDS", "5"))
    slow_domain_seconds = float(os.getenv("VMCRAWL_SLOW_DOMAIN_SECONDS", "8"))
    shutdown_event = asyncio.Event()
    queue: asyncio.Queue[str | None] = asyncio.Queue()
    active_domains: set[str] = set()
    completed_domains = 0

    # Create progress bar
    pbar = tqdm(total=len(domain_list), desc="Fetching", unit="d")

    def _refresh_progress_postfix() -> None:
        active_count = len(active_domains)
        remaining = max(0, len(domain_list) - completed_domains)
        pbar.set_postfix_str(
            f"inflight={active_count} done={completed_domains}/{len(domain_list)} left={remaining}",
        )
        pbar.refresh()

    async def progress_heartbeat() -> None:
        if heartbeat_seconds <= 0:
            return
        while not shutdown_event.is_set():
            await asyncio.sleep(heartbeat_seconds)
            if shutdown_event.is_set():
                break
            _refresh_progress_postfix()

    async def fetch_worker():
        """Process domains from queue with bounded task count."""
        nonlocal completed_domains
        while True:
            domain = await queue.get()
            if domain is None:
                queue.task_done()
                break

            started_at = time.monotonic()
            try:
                if shutdown_event.is_set():
                    continue

                active_domains.add(domain)
                _set_domain_start_time(domain)
                _refresh_progress_postfix()
                result = await process_fetch_domain(
                    domain,
                    domain_endings,
                    pbar,
                    dni,
                    existing_domains,
                )
                domain_name, new_domains, status, status_color = result

                if new_domains:
                    all_new_domains.extend(new_domains)

                elapsed_seconds = time.monotonic() - started_at
                slow_label = " [slow]" if elapsed_seconds >= slow_domain_seconds else ""
                if status is not None:
                    echo(
                        f"{domain_name}: {status}{slow_label}",
                        status_color,
                        use_tqdm=True,
                    )
            except Exception as e:
                if not shutdown_event.is_set():
                    echo(f"{domain}: Error: {e}", "orange", use_tqdm=True)
            finally:
                active_domains.discard(domain)
                _clear_domain_start_time(domain)
                completed_domains += 1
                _ = pbar.update(1)
                _refresh_progress_postfix()
                queue.task_done()

    try:
        worker_count = max(1, min(max_workers, len(domain_list)))
        workers = [asyncio.create_task(fetch_worker()) for _ in range(worker_count)]
        heartbeat_task = asyncio.create_task(progress_heartbeat())
        for domain in domain_list:
            queue.put_nowait(domain)
        for _ in range(worker_count):
            queue.put_nowait(None)

        try:
            results = await asyncio.gather(*workers, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception) and not shutdown_event.is_set():
                    echo(f"Worker failed: {result}", "orange", use_tqdm=True)
        except asyncio.CancelledError:
            shutdown_event.set()
            for worker in workers:
                _ = worker.cancel()
            raise KeyboardInterrupt
        finally:
            shutdown_event.set()
            _ = heartbeat_task.cancel()
            _ = await asyncio.gather(heartbeat_task, return_exceptions=True)
    except KeyboardInterrupt:
        shutdown_event.set()
        raise
    finally:
        pbar.close()

    echo("Fetching complete!", "bold")

    # If we found new domains, crawl them
    if all_new_domains:
        # Deduplicate while preserving order
        seen = set()
        unique_new_domains = []
        for d in all_new_domains:
            if d not in seen:
                seen.add(d)
                unique_new_domains.append(d)

        echo(
            f"\nProcessing {len(unique_new_domains)} newly discovered domains…",
            "bold",
        )

        # Load filter data for crawling in parallel
        filter_data = await load_domain_filter_data()

        # Use "0" as user_choice (new domains mode)
        await check_and_record_domains(
            unique_new_domains,
            filter_data["not_masto_domains"],
            "0",  # user_choice for new domains
            filter_data["dni_domains"],
            domain_endings,
            filter_data["nightly_version_ranges"],
        )

        echo("Crawling of new domains complete!", "bold")
    else:
        echo("No new domains to crawl.", "yellow")

    return EXIT_SUCCESS


# =============================================================================
# TLD FUNCTIONS - Top-Level Domain Management
# =============================================================================

EXCLUDED_TLDS: set[str] = {"arpa"}


def _exclude_tlds(tlds: set[str]) -> set[str]:
    """Remove hardcoded unsupported TLDs from a TLD set."""
    return {tld for tld in tlds if tld not in EXCLUDED_TLDS}


def get_tld_last_updated() -> datetime | None:
    """Get the timestamp of when TLD data was last updated."""
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            _ = cursor.execute(
                "SELECT MAX(last_updated) FROM tld_cache",
            )
            result = cursor.fetchone()
            return result[0] if result and result[0] else None
        except Exception:
            return None


def get_tlds_from_db() -> set[str]:
    """Get set of TLDs from database."""
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            _ = cursor.execute("SELECT tld FROM tld_cache")
            # Build set directly from cursor iterator (memory efficient)
            tlds: set[str] = {row[0] for row in cursor}
            return _exclude_tlds(tlds)
        except Exception as e:
            echo(f"Failed to get TLDs from database: {e}", "red")
            conn.rollback()
            return set()


def import_tlds(tlds: set[str]) -> int:
    """Import TLDs into database, replacing all existing data."""
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            # Clear existing TLDs
            _ = cursor.execute("DELETE FROM tld_cache")

            filtered_tlds = _exclude_tlds(tlds)

            if filtered_tlds:
                # Use batch insert for efficiency
                values: list[tuple[str]] = [(tld,) for tld in sorted(filtered_tlds)]
                placeholders = sql.SQL(",").join([sql.SQL("(%s)") for _ in values])
                flattened_values: list[str] = [item[0] for item in values]
                query = sql.SQL("INSERT INTO tld_cache (tld) VALUES {}").format(
                    placeholders
                )
                _ = cursor.execute(query, flattened_values)
                inserted_count = cursor.rowcount
                conn.commit()
                return inserted_count
            return 0
        except Exception as e:
            echo(f"Failed to import TLDs: {e}", "red")
            conn.rollback()
            return 0


async def fetch_tlds_from_iana() -> set[str]:
    """Fetch TLDs from IANA."""
    url = "http://data.iana.org/TLD/tlds-alpha-by-domain.txt"

    try:
        domain_endings_response = await get_httpx(url)
        if domain_endings_response.status_code == 200:
            # Use set for O(1) lookup
            domain_endings = {
                line.strip().lower()
                for line in domain_endings_response.text.splitlines()
                if line.strip() and not line.startswith("#")
            }
            return domain_endings
    except Exception as e:
        echo(f"Failed to fetch TLDs from IANA: {e}", "red")

    return set()


# =============================================================================
# DNI FUNCTIONS - Do Not Interact List Management
# =============================================================================

DNI_CSV_URL = "https://about.iftas.org/wp-content/uploads/2025/10/iftas-dni-latest.csv"


def get_existing_dni_domains() -> set[str]:
    """Get set of domains already in dni table."""
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            _ = cursor.execute("SELECT domain FROM dni")
            # Build set directly from cursor iterator (memory efficient)
            existing_domains: set[str] = {row[0] for row in cursor}
            return existing_domains
        except Exception as e:
            echo(f"Failed to get existing DNI domains: {e}", "red")
            conn.rollback()
            return set()


def import_dni_domains(
    domains: list[str], comment: str = "iftas", force: str = "soft"
) -> int:
    """Import new domains into dni table with comment and force level.

    Args:
        domains: List of domain names to import
        comment: Comment to associate with the domains (e.g., "iftas", "iftas-abandoned")
        force: Force level for enforcement - "soft" (default) or "hard"
               Only domains with force="hard" will be used for DNI enforcement
    """
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            if domains:
                # Use batch insert for efficiency
                values: list[tuple[str, str, str]] = [
                    (domain.lower(), comment, force) for domain in domains
                ]
                placeholders = sql.SQL(",").join(
                    [sql.SQL("(%s, %s, %s)") for _ in values]
                )
                flattened_values: list[str] = [
                    item for sublist in values for item in sublist
                ]
                query = sql.SQL(
                    "INSERT INTO dni (domain, comment, force) VALUES {} "
                    + "ON CONFLICT (domain) DO NOTHING"
                ).format(placeholders)
                _ = cursor.execute(query, flattened_values)
                inserted_count = cursor.rowcount
                echo(
                    f"Imported {inserted_count} new DNI domains (force={force})",
                    "green",
                )
                conn.commit()
                return inserted_count
            echo("No new domains to import", "yellow")
            return 0
        except Exception as e:
            echo(f"Failed to import DNI domains: {e}", "red")
            conn.rollback()
            return 0


def list_dni_domains() -> None:
    """Display all domains in the dni table."""
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            _ = cursor.execute(
                "SELECT domain, comment, force, timestamp FROM dni ORDER BY domain",
            )
            domains = cursor.fetchall()

            if not domains:
                echo("No domains found in DNI table", "yellow")
                return

            echo(f"\nDNI Domains ({len(domains)} total):", "cyan")
            echo("-" * 90, "cyan")

            for domain, comment, force, timestamp in domains:
                comment_str = comment if comment else ""
                force_str = force if force else "soft"
                echo(
                    f"{domain:<40} {comment_str:<15} {force_str:<6} {timestamp}",
                    "white",
                )
            echo("", "white")
        except Exception as e:
            echo(f"Failed to list DNI domains: {e}", "red")
            conn.rollback()


def count_dni_domains() -> int:
    """Display count of domains in the dni table."""
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            _ = cursor.execute("SELECT COUNT(*) FROM dni")
            result = cursor.fetchone()
            count: int = result[0] if result else 0
            echo(f"Total DNI domains: {count}", "green")
            return count
        except Exception as e:
            echo(f"Failed to count DNI domains: {e}", "red")
            conn.rollback()
            return 0


def remove_dni_domain(domain: str) -> bool:
    """Remove a domain from the dni table."""
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            _ = cursor.execute("DELETE FROM dni WHERE domain = %s", (domain.lower(),))
            removed = cursor.rowcount > 0
            conn.commit()
            return removed
        except Exception as e:
            echo(f"Failed to remove DNI domain {domain}: {e}", "red")
            conn.rollback()
            return False


def display_domain_search(domain: str) -> None:
    """Display all known data for a domain from raw_domains and mastodon_domains."""
    lookup_domain = domain.strip().lower()
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            echo(f"\nDomain lookup: {lookup_domain}", "bold")
            echo("-" * 70, "cyan")

            _ = cursor.execute(
                "SELECT * FROM raw_domains WHERE domain = %s",
                (lookup_domain,),
            )
            raw_row = cursor.fetchone()
            raw_columns = (
                [desc[0] for desc in cursor.description] if cursor.description else []
            )

            echo("raw_domains:", "yellow")
            if raw_row is None:
                echo("  No row found", "white")
            else:
                for column, value in zip(raw_columns, raw_row, strict=False):
                    display_value = "NULL" if value is None else str(value)
                    echo(f"  {column}: {display_value}", "white")

            _ = cursor.execute(
                "SELECT * FROM dni WHERE domain = %s",
                (lookup_domain,),
            )
            dni_row = cursor.fetchone()
            dni_columns = (
                [desc[0] for desc in cursor.description] if cursor.description else []
            )

            echo("\ndni:", "yellow")
            if dni_row is None:
                echo("  No row found", "white")
            else:
                for column, value in zip(dni_columns, dni_row, strict=False):
                    display_value = "NULL" if value is None else str(value)
                    echo(f"  {column}: {display_value}", "white")

            _ = cursor.execute(
                "SELECT * FROM mastodon_domains WHERE domain = %s",
                (lookup_domain,),
            )
            mastodon_row = cursor.fetchone()
            mastodon_columns = (
                [desc[0] for desc in cursor.description] if cursor.description else []
            )

            echo("\nmastodon_domains:", "yellow")
            if mastodon_row is None:
                echo("  No row found", "white")
            else:
                for column, value in zip(mastodon_columns, mastodon_row, strict=False):
                    display_value = "NULL" if value is None else str(value)
                    echo(f"  {column}: {display_value}", "white")
        except Exception as e:
            echo(f"Failed to search for domain {lookup_domain}: {e}", "red")
            conn.rollback()


async def fetch_dni_csv(url: str) -> str | None:
    """Fetch the DNI CSV file from the specified URL."""
    try:
        echo(f"Fetching DNI list from {url}…", "bold")
        response = await get_httpx(url)

        if response.status_code != 200:
            echo(f"Failed to fetch DNI CSV: HTTP {response.status_code}", "red")
            return None

        echo("DNI CSV fetched successfully", "green")
        return response.text

    except Exception as e:
        echo(f"Error fetching DNI CSV: {e}", "red")
        return None


def _parse_dni_csv(csv_content: str) -> list[str]:
    """Parse the DNI CSV content and extract domains.

    The CSV file uses #domain as the header for the domain column.
    """
    domains: list[str] = []

    try:
        reader = csv.DictReader(StringIO(csv_content))

        # Check if #domain column exists
        if not reader.fieldnames or "#domain" not in reader.fieldnames:
            echo(
                "CSV header '#domain' not found. "
                + f"Available headers: {reader.fieldnames}",
                "red",
            )
            return []

        for row in reader:
            domain = row.get("#domain", "").strip()
            if domain and domain != "#domain":  # Skip empty rows and header repeats
                domains.append(domain.lower())

        echo(f"Parsed {len(domains)} domains from CSV", "green")
        return domains

    except Exception as e:
        echo(f"Error parsing DNI CSV: {e}", "red")
        return []


async def run_dni_mode(args):
    """Run the DNI list management mode."""
    echo(f"{appname} v{appversion} (dni mode)", "bold")
    if _is_running_headless():
        echo("Running in headless mode", "cyan")

    # List domains
    if args.list:
        list_dni_domains()
        return

    # Count domains
    if args.count:
        _ = count_dni_domains()
        return

    # Get existing domains to avoid duplicates
    existing_domains = get_existing_dni_domains()

    # Fetch and import DNI list
    echo("Fetching IFTAS DNI List…", "bold")
    csv_content = await fetch_dni_csv(args.url)
    if not csv_content:
        echo("Failed to fetch DNI CSV", "red")
        return

    domains = _parse_dni_csv(csv_content)
    if not domains:
        echo("No domains parsed from DNI CSV", "yellow")
        return

    new_domains = [d for d in domains if d not in existing_domains]
    echo(
        f"Found {len(new_domains)} new DNI domains (out of {len(domains)} total)",
        "cyan",
    )

    if new_domains:
        imported = import_dni_domains(new_domains, comment="iftas-dni")
        echo(f"Total new domains imported: {imported}", "green")
    else:
        echo("All DNI domains already exist in database", "yellow")

    _ = count_dni_domains()
    echo("DNI import complete!", "bold")


# =============================================================================
# NIGHTLY FUNCTIONS - Nightly Version Management
# =============================================================================


def display_nightly_versions():
    """Display all current nightly version entries."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            _ = cur.execute(
                """
                    SELECT version, start_date, end_date, is_security
                    FROM nightly_versions
                    ORDER BY is_security, start_date DESC
                """,
            )
            versions = cur.fetchall()

            if not versions:
                echo("No nightly versions found in database", "yellow")
                return

            echo("\nCurrent Nightly Versions:", "cyan")
            echo("-" * 70, "cyan")
            echo(
                f"{'Version':<20} {'Start Date':<15} {'End Date':<15} {'Type':<10}",
                "bold",
            )
            echo("-" * 70, "cyan")

            for version, start_date, end_date, is_security in versions:
                kind = "security" if is_security else "range"
                echo(
                    f"{version:<20} {start_date} {end_date} {kind:<10}",
                    "white",
                )
            echo("", "white")
    except Exception as e:
        echo(f"Error fetching nightly versions: {e}", "red")
        raise


def get_active_nightly_version():
    """Get the currently active nightly version (end_date = 2099-12-31)."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            _ = cur.execute(
                """
                    SELECT version, start_date, end_date
                    FROM nightly_versions
                    WHERE end_date = '2099-12-31'
                      AND is_security = FALSE
                    ORDER BY start_date DESC
                    LIMIT 1
                """,
            )
            result = cur.fetchone()
            return result if result else None
    except Exception as e:
        echo(f"Error fetching active version: {e}", "red")
        return None


def add_nightly_version(
    nightly_version,
    start_date,
    end_date="2099-12-31",
    auto_update_previous=True,
):
    """Add a new nightly version to the database.

    Args:
        nightly_version: Version string (e.g., '4.9.0-alpha.7')
        start_date: Start date in YYYY-MM-DD format
        end_date: End date in YYYY-MM-DD format (default: 2099-12-31)
        auto_update_previous: If True, auto-update previous version end_date
    """
    try:
        # Validate dates
        if not _validate_nightly_date(start_date):
            echo(
                f"Invalid start_date format: {start_date}. Use YYYY-MM-DD",
                "red",
            )
            return False

        if not _validate_nightly_date(end_date):
            echo(f"Invalid end_date format: {end_date}. Use YYYY-MM-DD", "yellow")
            return False

        # Check if version already exists
        with db_pool.connection() as conn, conn.cursor() as cur:
            _ = cur.execute(
                """
                    SELECT version FROM nightly_versions
                    WHERE version = %s AND is_security = FALSE
                """,
                (nightly_version,),
            )
            if cur.fetchone():
                echo(
                    f"Version {nightly_version} already exists in database",
                    "yellow",
                )
                return False

        # If auto-update is enabled, update the previous active version
        if auto_update_previous:
            active_version = get_active_nightly_version()
            if active_version:
                old_version, old_start, old_end = active_version
                # Calculate new end date (one day before new start_date)
                new_end_date = (
                    datetime.strptime(start_date, "%Y-%m-%d") - timedelta(days=1)
                ).strftime("%Y-%m-%d")

                echo("\nUpdating previous active version:", "cyan")
                echo(f"  Version: {old_version}", "cyan")
                echo(f"  Old end date: {old_end}", "cyan")
                echo(f"  New end date: {new_end_date}", "cyan")

                with db_pool.connection() as conn, conn.cursor() as cur:
                    _ = cur.execute(
                        """
                            UPDATE nightly_versions
                            SET end_date = %s
                            WHERE version = %s
                        """,
                        (new_end_date, old_version),
                    )
                    conn.commit()

                echo(f"Updated {old_version} end date to {new_end_date}", "green")

        # Insert new version
        with db_pool.connection() as conn, conn.cursor() as cur:
            _ = cur.execute(
                """
                    INSERT INTO nightly_versions (version, start_date, end_date)
                    VALUES (%s, %s, %s)
                """,
                (nightly_version, start_date, end_date),
            )
            conn.commit()

        echo("\nSuccessfully added nightly version:", "green")
        echo(f"  Version: {nightly_version}", "green")
        echo(f"  Start date: {start_date}", "green")
        echo(f"  End date: {end_date}", "green")

        return True

    except Exception as e:
        echo(f"Error adding nightly version: {e}", "red")
        return False


def update_nightly_end_date(nightly_version, new_end_date):
    """Update the end_date for a specific version."""
    try:
        if not _validate_nightly_date(new_end_date):
            echo(f"Invalid date format: {new_end_date}. Use YYYY-MM-DD", "yellow")
            return False

        with db_pool.connection() as conn, conn.cursor() as cur:
            _ = cur.execute(
                """
                    UPDATE nightly_versions
                    SET end_date = %s
                    WHERE version = %s
                """,
                (new_end_date, nightly_version),
            )

            if cur.rowcount == 0:
                echo(f"Version {nightly_version} not found in database", "yellow")
                return False

            conn.commit()

        echo(f"Updated {nightly_version} end date to {new_end_date}", "green")
        return True

    except Exception as e:
        echo(f"Error updating end date: {e}", "red")
        return False


def _validate_nightly_date(date_string):
    """Validate date format (YYYY-MM-DD)."""
    try:
        _ = datetime.strptime(date_string, "%Y-%m-%d")
        return True
    except ValueError:
        return False


def interactive_add_nightly():
    """Interactive mode for adding a new nightly version."""
    echo("\n=== Add New Nightly Version ===", "bold")

    # Show current versions
    display_nightly_versions()

    # Get version (default to the current main branch version)
    default_version = version_main_release
    if not default_version:
        _ = load_versions_from_db()
        default_version = version_main_release

    if default_version:
        version_input = input(
            f"Enter version [default: {default_version}]: ",
        ).strip()
        nightly_version = version_input if version_input else default_version
    else:
        nightly_version = input("Enter version (e.g., 4.9.0-alpha.7): ").strip()

    if not nightly_version:
        echo("Version cannot be empty", "yellow")
        return

    # Get start date
    default_start_date = (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%d")
    start_date_input = input(
        f"Enter start date (YYYY-MM-DD) [default: {default_start_date}]: ",
    ).strip()
    start_date = start_date_input if start_date_input else default_start_date

    # Get end date (optional)
    end_date = input("Enter end date (YYYY-MM-DD) [default: 2099-12-31]: ").strip()
    if not end_date:
        end_date = "2099-12-31"

    # Confirm update of previous version
    active = get_active_nightly_version()
    if active and end_date == "2099-12-31":
        old_version, old_start, old_end = active
        new_end = (
            datetime.strptime(start_date, "%Y-%m-%d") - timedelta(days=1)
        ).strftime("%Y-%m-%d")

        echo("\nThis will update the previous active version:", "yellow")
        echo(f"  {old_version}: {old_end} -> {new_end}", "yellow")

        confirm = input("Continue? (y/n): ").strip().lower()
        if confirm != "y":
            echo("Operation cancelled", "yellow")
            return

    # Add the version
    add_nightly_version(nightly_version, start_date, end_date)


def add_security_nightly_version(version, release_date):
    """Pin a dedicated "-security" nightly build to a specific version.

    Args:
        version: Version the security build maps to (e.g., '4.6.0-alpha.9')
        release_date: The "-security" build's labelled date (YYYY-MM-DD)
    """
    if not _validate_nightly_date(release_date):
        echo(f"Invalid date format: {release_date}. Use YYYY-MM-DD", "red")
        return False

    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            _ = cur.execute(
                """
                    SELECT version FROM nightly_versions
                    WHERE version = %s AND is_security = TRUE
                """,
                (version,),
            )
            if cur.fetchone():
                echo(
                    f"Security mapping for {version} already exists",
                    "yellow",
                )
                return False

            # A security pin is a point entry: start_date == end_date == the date.
            _ = cur.execute(
                """
                    INSERT INTO nightly_versions
                        (version, start_date, end_date, is_security)
                    VALUES (%s, %s, %s, TRUE)
                """,
                (version, release_date, release_date),
            )
            conn.commit()

        echo(
            f"Pinned security build {release_date} -> {version}",
            "green",
        )
        return True

    except Exception as e:
        echo(f"Error adding security mapping: {e}", "red")
        return False


def interactive_add_security_nightly():
    """Interactive mode for pinning a "-security" build to a version."""
    echo("\n=== Add Security Version Mapping ===", "bold")

    # Show current versions
    display_nightly_versions()

    version = input(
        "Enter version this -security build maps to (e.g., 4.6.0-alpha.9): "
    ).strip()
    if not version:
        echo("Version cannot be empty", "yellow")
        return

    release_date = input("Enter the -security build date (YYYY-MM-DD): ").strip()
    if not release_date:
        echo("Date cannot be empty", "yellow")
        return

    add_security_nightly_version(version, release_date)


def run_nightly_mode(args):
    """Run the nightly version management mode."""
    echo(f"{appname} v{appversion} (nightly mode)", "bold")
    if _is_running_headless():
        echo("Running in headless mode", "cyan")

    # List versions
    if args.list:
        display_nightly_versions()
        return

    # Update end date
    if args.update_end_date:
        nightly_version, end_date = args.update_end_date
        _ = update_nightly_end_date(nightly_version, end_date)
        return

    # Add version (command line)
    if args.version and args.start_date:
        add_nightly_version(
            args.version,
            args.start_date,
            args.end_date,
            auto_update_previous=not args.no_auto_update,
        )
        return

    # Add version (interactive) - default behavior
    interactive_add_nightly()


# =============================================================================
# MANAGE MODE - Unified Management Interface
# =============================================================================


def list_flagged_statistics() -> None:
    """Display statistics rows currently flagged as invalid."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            _ = cur.execute(
                """
                SELECT date, invalid_reason, updated_at
                FROM statistics
                WHERE invalid = TRUE
                ORDER BY date DESC
                """
            )
            rows = cur.fetchall()
        if not rows:
            echo("\nNo statistics days are flagged as invalid.", "cyan")
            return
        echo("\nFlagged Statistics Days:", "cyan")
        echo("-" * 70, "cyan")
        echo(f"{'Date':<12} {'Updated At':<26} Reason", "bold")
        echo("-" * 70, "cyan")
        for d, reason, updated in rows:
            updated_str = updated.isoformat(sep=" ", timespec="seconds") if updated else "-"
            echo(f"{str(d):<12} {updated_str:<26} {reason or '(no reason)'}", "white")
    except Exception as e:
        echo(f"Error listing flagged statistics: {e}", "red")


def set_statistics_invalid(target: date, invalid: bool, reason: str | None) -> bool:
    """Set the invalid flag on the statistics row for `target`. Returns True on success."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cur:
            _ = cur.execute(
                """
                UPDATE statistics
                SET invalid = %s, invalid_reason = %s
                WHERE date = %s
                RETURNING date
                """,
                (invalid, reason if invalid else None, target),
            )
            row = cur.fetchone()
            conn.commit()
        if row is None:
            echo(f"No statistics row found for {target.isoformat()}", "yellow")
            return False
        if invalid:
            suffix = f" (reason: {reason})" if reason else ""
            echo(f"Flagged {target.isoformat()} as invalid{suffix}", "green")
        else:
            echo(f"Cleared invalid flag on {target.isoformat()}", "green")
        return True
    except Exception as e:
        echo(f"Error updating statistics row: {e}", "red")
        return False


def get_queue_status() -> dict[str, Any]:
    """Return a snapshot of crawl-queue metrics from the database."""
    query = """
        SELECT
            COUNT(*) FILTER (WHERE alias IS NULL OR alias = FALSE)
                AS total,
            COUNT(*) FILTER (
                WHERE (alias IS NULL OR alias = FALSE)
                  AND (next_crawl_at IS NULL OR next_crawl_at <= now())
                  AND (claimed_at IS NULL
                       OR claimed_at <= now() - make_interval(secs => %(lease)s))
            ) AS due_now,
            COUNT(*) FILTER (
                WHERE claimed_at IS NOT NULL
                  AND claimed_at > now() - make_interval(secs => %(lease)s)
            ) AS in_progress,
            COUNT(*) FILTER (
                WHERE (alias IS NULL OR alias = FALSE)
                  AND next_crawl_at > now()
                  AND (claimed_at IS NULL
                       OR claimed_at <= now() - make_interval(secs => %(lease)s))
            ) AS scheduled,
            COUNT(*) FILTER (
                WHERE claimed_at IS NOT NULL
                  AND claimed_at <= now() - make_interval(secs => %(lease)s)
            ) AS stale_leases,
            COUNT(DISTINCT claimed_by) FILTER (
                WHERE claimed_at IS NOT NULL
                  AND claimed_at > now() - make_interval(secs => %(lease)s)
            ) AS active_workers,
            MIN(next_crawl_at) FILTER (
                WHERE (alias IS NULL OR alias = FALSE)
                  AND next_crawl_at > now()
                  AND claimed_at IS NULL
            ) AS next_due_at
        FROM raw_domains
    """
    worker_query = """
        SELECT claimed_by, COUNT(*) AS domains
        FROM raw_domains
        WHERE claimed_at IS NOT NULL
          AND claimed_at > now() - make_interval(secs => %(lease)s)
          AND claimed_by IS NOT NULL
        GROUP BY claimed_by
        ORDER BY domains DESC, claimed_by
    """
    with db_pool.connection() as conn, conn.cursor() as cursor:
        _ = cursor.execute(query, {"lease": queue_lease_seconds})
        row = cursor.fetchone()
        if not row:
            return {}
        cols = [
            "total",
            "due_now",
            "in_progress",
            "scheduled",
            "stale_leases",
            "active_workers",
            "next_due_at",
        ]
        result = dict(zip(cols, row, strict=False))
        _ = cursor.execute(worker_query, {"lease": queue_lease_seconds})
        result["workers"] = cursor.fetchall()
        return result


def display_queue_status() -> None:
    """Print queue status metrics to stdout."""
    try:
        stats = get_queue_status()
    except Exception as e:
        echo(f"Failed to retrieve queue status: {e}", "red")
        return

    now = datetime.now(UTC)
    echo(f"Queue Status  [{now.strftime('%Y-%m-%d %H:%M:%S UTC')}]", "bold")
    echo("-" * 50, "cyan")
    echo("", "white")
    total = stats.get("total", 0) or 0
    due_now = stats.get("due_now", 0) or 0
    in_progress = stats.get("in_progress", 0) or 0
    scheduled = stats.get("scheduled", 0) or 0
    stale = stats.get("stale_leases", 0) or 0
    workers = stats.get("active_workers", 0) or 0
    next_due_at = stats.get("next_due_at")

    echo(f"  Total domains:    {total:>10,}", "white")
    echo(f"  Due now:          {due_now:>10,}", "yellow" if due_now > 0 else "white")
    echo(f"  In progress:      {in_progress:>10,}", "green" if in_progress > 0 else "white")
    echo(f"  Scheduled:        {scheduled:>10,}", "white")
    echo(f"  Stale leases:     {stale:>10,}", "red" if stale > 0 else "white")
    echo("", "white")
    echo(f"  Active workers:   {workers:>10}", "cyan" if workers > 0 else "white")
    worker_rows = stats.get("workers", [])
    hostnames = [w.split(":")[0] for w, _ in worker_rows]
    duplicate_hosts = {h for h in hostnames if hostnames.count(h) > 1}
    for worker_name, worker_count in worker_rows:
        host = worker_name.split(":")[0]
        label = worker_name if host in duplicate_hosts else host
        echo(f"    {label:<30} {worker_count:>6,}", "cyan")

    if next_due_at is not None:
        diff = next_due_at - now
        secs = max(0, int(diff.total_seconds()))
        if secs < 60:
            eta = f"{secs}s"
        elif secs < 3600:
            eta = f"{secs // 60}m {secs % 60}s"
        else:
            eta = f"{secs // 3600}h {(secs % 3600) // 60}m"
        echo(f"  Next scheduled:   {eta:>10} from now", "white")

    echo("", "white")


def print_manage_menu():
    """Print the management menu options."""
    echo("", "white")
    echo("Management Menu:", "bold")
    echo("-" * 50, "cyan")
    echo("", "white")
    echo("DNI (Do Not Interact) Management:", "yellow")
    echo("   1. Fetch and import IFTAS DNI list", "white")
    echo("   2. List all DNI domains", "white")
    echo("   3. Count DNI domains", "white")
    echo("   4. Add DNI domain manually", "white")
    echo("   5. Remove DNI domain", "white")
    echo("", "white")
    echo("Nightly Version Management:", "yellow")
    echo("   6. List all nightly versions", "white")
    echo("   7. Add a new nightly version", "white")
    echo("   8. Update nightly version end date", "white")
    echo("   s. Add a security version mapping", "white")
    echo("", "white")
    echo("Mastodon Version Management:", "yellow")
    echo("   9. Update latest Mastodon versions", "white")
    echo("  10. Show current version info", "white")
    echo("  11. Promote branch to release", "white")
    echo("  12. Mark branch as EOL", "white")
    echo("  13. Reorder release branches", "white")
    echo("", "white")
    echo("TLD Cache Management:", "yellow")
    echo("  14. Update TLD cache", "white")
    echo("", "white")
    echo("Domain Search:", "yellow")
    echo("  15. Search domain details", "white")
    echo("", "white")
    echo("Statistics Management:", "yellow")
    echo("  16. List flagged statistics days", "white")
    echo("  17. Flag statistics day as invalid", "white")
    echo("  18. Unflag statistics day", "white")
    echo("", "white")
    echo("Queue Status:", "yellow")
    echo("  19. Show live queue status", "white")
    echo("", "white")
    echo("   q. Quit", "white")
    echo("", "white")


def get_manage_choice():
    """Get user's menu choice."""
    choice = input("Enter your choice: ").strip().lower()
    return choice


async def run_manage_mode(args: argparse.Namespace) -> int:
    """Run the unified management mode with menu interface."""
    echo(f"{appname} v{appversion} (manage mode)", "bold")
    if _is_running_headless():
        echo("Running in headless mode", "cyan")

    while True:
        print_manage_menu()
        choice = get_manage_choice()

        if choice in {"q", "quit", "exit"}:
            echo("Exiting management mode", "cyan")
            break

        # DNI Management
        elif choice == "1":
            # Fetch and import IFTAS DNI list
            existing_domains = get_existing_dni_domains()
            echo("Fetching IFTAS DNI List…", "bold")
            csv_content = await fetch_dni_csv(DNI_CSV_URL)
            if not csv_content:
                echo("Failed to fetch DNI CSV", "red")
                continue

            domains = _parse_dni_csv(csv_content)
            if not domains:
                echo("No domains parsed from DNI CSV", "yellow")
                continue

            new_domains = [d for d in domains if d not in existing_domains]
            echo(
                f"Found {len(new_domains)} new DNI domains (out of {len(domains)} total)",
                "cyan",
            )

            if new_domains:
                imported = import_dni_domains(new_domains, comment="iftas-dni")
                echo(f"Total new domains imported: {imported}", "green")
            else:
                echo("All DNI domains already exist in database", "yellow")

            _ = count_dni_domains()
            echo("DNI import complete!", "bold")
            echo("", "white")
            input("Press Enter to continue...")

        elif choice == "2":
            # List all DNI domains
            list_dni_domains()
            input("Press Enter to continue...")

        elif choice == "3":
            # Count DNI domains
            _ = count_dni_domains()
            echo("", "white")
            input("Press Enter to continue...")

        elif choice == "4":
            # Add DNI domain manually
            echo("", "white")
            domain = input("Enter the domain to add: ").strip().lower()
            comment = input("Enter comment: ").strip()
            force = input("Enter force (hard/soft): ").strip().lower()

            if not domain:
                echo("Domain cannot be empty", "yellow")
                echo("", "white")
                input("Press Enter to continue...")
                continue
            if not comment:
                echo("Comment cannot be empty", "yellow")
                echo("", "white")
                input("Press Enter to continue...")
                continue
            if force not in {"hard", "soft"}:
                echo("Force must be 'hard' or 'soft'", "yellow")
                echo("", "white")
                input("Press Enter to continue...")
                continue

            imported = import_dni_domains([domain], comment=comment, force=force)
            if imported > 0:
                echo(
                    f"Added DNI domain: {domain} (comment={comment}, force={force})",
                    "green",
                )
            else:
                echo(f"Domain already exists in DNI table: {domain}", "yellow")
            echo("", "white")
            input("Press Enter to continue...")

        elif choice == "5":
            # Remove DNI domain
            echo("", "white")
            domain = input("Enter the domain to remove: ").strip().lower()
            if not domain:
                echo("Domain cannot be empty", "yellow")
                echo("", "white")
                input("Press Enter to continue...")
                continue

            if remove_dni_domain(domain):
                echo(f"Removed DNI domain: {domain}", "green")
            else:
                echo(f"Domain not found in DNI table: {domain}", "yellow")
            echo("", "white")
            input("Press Enter to continue...")

        # Nightly Version Management
        elif choice == "6":
            # List all nightly versions
            display_nightly_versions()
            input("Press Enter to continue...")

        elif choice == "7":
            # Add a new nightly version (interactive)
            interactive_add_nightly()
            echo("", "white")
            input("Press Enter to continue...")

        elif choice == "8":
            # Update nightly version end date
            echo("", "white")
            version_to_update = input(
                "Enter the version to update (e.g., 4.9.0-alpha.7): "
            ).strip()
            new_end_date = input("Enter the new end date (YYYY-MM-DD): ").strip()
            if version_to_update and new_end_date:
                _ = update_nightly_end_date(version_to_update, new_end_date)
            else:
                echo("Invalid input, operation cancelled", "yellow")
            echo("", "white")
            input("Press Enter to continue...")

        elif choice == "s":
            # Add a security version mapping (interactive)
            interactive_add_security_nightly()
            echo("", "white")
            input("Press Enter to continue...")

        # Mastodon Version Management
        elif choice == "9":
            # Update latest Mastodon versions (only existing branches)
            echo("Fetching latest Mastodon versions from GitHub…", "bold")

            # Fetch fresh version info from GitHub
            main_release = await get_main_version_release()
            tracked_versions = await get_all_tracked_mastodon_versions()

            # Update only the 'latest' column for existing branches
            with db_pool.connection() as conn, conn.cursor() as cur:
                # Update main branch (n_level = -1)
                _ = cur.execute(
                    "UPDATE release_versions SET latest = %s WHERE n_level = -1",
                    (main_release,),
                )
                echo(f"Updated main branch to {main_release}", "white")
                # Update release and EOL branches (tracked_versions is a dict: branch -> version)
                for branch, version_str in tracked_versions.items():
                    _ = cur.execute(
                        "UPDATE release_versions SET latest = %s WHERE branch = %s AND status IN ('release', 'eol')",
                        (version_str, branch),
                    )
                    echo(f"Updated {branch} to {version_str}", "white")
                conn.commit()

            # Reload from database to update global variables
            load_versions_from_db()

            echo("Version information updated successfully!", "green")
            echo(f"Main version: {version_main_release}", "cyan")
            if version_backport_releases:
                echo(
                    f"Supported releases: {', '.join(version_backport_releases)}",
                    "cyan",
                )
            echo("", "white")
            input("Press Enter to continue...")

        elif choice == "10":
            # Show current version info (from database)
            db_versions = get_release_versions_from_db()

            if not db_versions:
                echo(
                    "No version information found in database. Use option 7 to fetch.",
                    "yellow",
                )
            else:
                echo("", "white")
                echo("Current Mastodon Version Information (from database):", "bold")
                echo("-" * 60, "cyan")

                if "main_branch" in db_versions:
                    echo(f"Main branch:       {db_versions['main_branch']}", "white")
                if "main_release" in db_versions:
                    echo(f"Main release:      {db_versions['main_release']}", "white")
                if "latest_stable" in db_versions:
                    echo(f"Latest stable:     {db_versions['latest_stable']}", "white")
                if "backport_releases" in db_versions:
                    echo(
                        f"Backport releases: {', '.join(db_versions['backport_releases'])}",
                        "white",
                    )
                if "all_patched" in db_versions:
                    echo(
                        f"All patched:       {', '.join(db_versions['all_patched'])}",
                        "white",
                    )
                echo("", "white")
            input("Press Enter to continue...")

        elif choice == "11":
            # Promote branch to release
            echo("", "white")
            echo("Promote Branch to Release", "bold")
            echo("-" * 60, "cyan")

            with db_pool.connection() as conn, conn.cursor() as cur:
                # Show main branch and any non-release branches that could be promoted
                _ = cur.execute(
                    """
                    SELECT branch, status, n_level, latest
                    FROM release_versions
                    WHERE status = 'main'
                    ORDER BY n_level
                    """
                )
                promotable = cur.fetchall()

                if not promotable:
                    echo("No branches available to promote", "yellow")
                    echo("", "white")
                    input("Press Enter to continue...")
                    continue

                echo("Branches available to promote:", "white")
                for branch, status, n_level, latest in promotable:
                    echo(f"  {branch} (status={status}, latest={latest})", "white")
                echo("", "white")
                branch = input(
                    "Enter branch to promote to release (or press Enter to cancel): "
                ).strip()
                if not branch:
                    echo("Operation cancelled", "yellow")
                    echo("", "white")
                    input("Press Enter to continue...")
                    continue

                # Check if branch exists and can be promoted
                _ = cur.execute(
                    "SELECT branch, status, n_level FROM release_versions WHERE branch = %s",
                    (branch,),
                )
                existing = cur.fetchone()

                if not existing:
                    echo(f"Branch {branch} not found", "yellow")
                    echo("", "white")
                    input("Press Enter to continue...")
                    continue

                # If it's already a release or EOL, abort
                if existing[1] != "main":
                    echo(
                        f"Branch {branch} has status '{existing[1]}' and cannot be promoted",
                        "yellow",
                    )
                    echo("", "white")
                    input("Press Enter to continue...")
                    continue

                # When adding a new release branch, it becomes n_level=0 (newest)
                # and existing releases/EOL get shifted down (incremented)
                # To avoid primary key conflicts, use a two-step update with large offset
                # Step 1: Move to high temp values (e.g., 1000+) to avoid conflicts
                _ = cur.execute(
                    """
                    UPDATE release_versions
                    SET n_level = n_level + 10000
                    WHERE status IN ('release', 'eol') AND n_level >= 0
                    """
                )
                # Step 2: Move back down, shifted by 1 from original position
                _ = cur.execute(
                    """
                    UPDATE release_versions
                    SET n_level = n_level - 9999
                    WHERE status IN ('release', 'eol') AND n_level >= 10000
                    """
                )

                new_level = 0

                # Fetch latest version for this branch from GitHub
                echo(f"Fetching latest version for branch {branch}...", "cyan")
                url = "https://api.github.com/repos/mastodon/mastodon/releases"
                response = await get_httpx(url)
                _ = response.raise_for_status()
                releases = response.json()

                latest_version = None
                for release in releases:
                    release_version = release["tag_name"].lstrip("v")
                    if release_version.startswith(branch):
                        latest_version = release_version
                        break

                if not latest_version:
                    latest_version = f"{branch}.0"
                    echo(
                        f"No releases found for {branch}, using {latest_version}",
                        "yellow",
                    )

                # If this is the main branch being promoted, delete and re-insert
                # (can't UPDATE the primary key n_level if target value already exists)
                if existing and existing[1] == "main":
                    # Delete the main branch row
                    _ = cur.execute(
                        "DELETE FROM release_versions WHERE branch = %s AND status = 'main'",
                        (branch,),
                    )
                    # Insert as new release branch
                    _ = cur.execute(
                        """
                        INSERT INTO release_versions (branch, status, n_level, latest)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (branch, "release", new_level, latest_version),
                    )
                    echo(
                        f"Promoted main branch {branch} to release (n_level={new_level}, latest={latest_version})",
                        "green",
                    )

                    # Now add a new main branch (next version)
                    # Calculate next version (e.g., 4.6 -> 4.7)
                    parts = branch.split(".")
                    if len(parts) < 2:
                        echo(f"Cannot calculate next branch from malformed branch '{branch}'", "red")
                        continue
                    new_main_branch = f"{parts[0]}.{int(parts[1]) + 1}"
                    new_main_version = f"{new_main_branch}.0-alpha.1"

                    _ = cur.execute(
                        """
                        INSERT INTO release_versions (branch, status, n_level, latest)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (new_main_branch, "main", -1, new_main_version),
                    )
                    echo(
                        f"Created new main branch {new_main_branch} ({new_main_version})",
                        "green",
                    )
                else:
                    # Insert new release branch
                    _ = cur.execute(
                        """
                        INSERT INTO release_versions (branch, status, n_level, latest)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (branch, "release", new_level, latest_version),
                    )
                    echo(
                        f"Added branch {branch} as release (n_level={new_level}, latest={latest_version})",
                        "green",
                    )

                conn.commit()

                # Reload global variables
                load_versions_from_db()

            echo("", "white")
            input("Press Enter to continue...")

        elif choice == "12":
            # Mark branch as EOL
            echo("", "white")
            echo("Mark Branch as EOL", "bold")
            echo("-" * 60, "cyan")

            # Show current release branches
            with db_pool.connection() as conn, conn.cursor() as cur:
                _ = cur.execute(
                    "SELECT branch, n_level, latest FROM release_versions WHERE status = 'release' ORDER BY n_level"
                )
                release_branches = cur.fetchall()

            if not release_branches:
                echo("No release branches found", "yellow")
                echo("", "white")
                input("Press Enter to continue...")
                continue

            echo("Current release branches:", "white")
            for branch, n_level, latest in release_branches:
                echo(f"  {branch} (n_level={n_level}, latest={latest})", "white")
            echo("", "white")
            branch = input(
                "Enter branch to mark as EOL (or press Enter to cancel): "
            ).strip()
            if not branch:
                echo("Operation cancelled", "yellow")
                echo("", "white")
                input("Press Enter to continue...")
                continue

            with db_pool.connection() as conn, conn.cursor() as cur:
                # Check if branch exists and is a release
                _ = cur.execute(
                    "SELECT status, n_level FROM release_versions WHERE branch = %s",
                    (branch,),
                )
                result = cur.fetchone()

                if not result:
                    echo(f"Branch {branch} not found", "yellow")
                    echo("", "white")
                    input("Press Enter to continue...")
                    continue

                status, n_level = result

                if status != "release":
                    echo(
                        f"Branch {branch} is not a release (status={status})", "yellow"
                    )
                    echo("", "white")
                    input("Press Enter to continue...")
                    continue

                # Update status to EOL
                _ = cur.execute(
                    "UPDATE release_versions SET status = 'eol' WHERE branch = %s",
                    (branch,),
                )
                conn.commit()

                echo(f"Marked branch {branch} as EOL", "green")

                # Reload global variables
                load_versions_from_db()

            echo("", "white")
            input("Press Enter to continue...")

        elif choice == "13":
            # Reorder release branches
            echo("", "white")
            echo("Reorder Release Branches", "bold")
            echo("-" * 60, "cyan")

            # Get current release branches
            with db_pool.connection() as conn, conn.cursor() as cur:
                _ = cur.execute(
                    "SELECT branch, n_level, latest FROM release_versions WHERE status = 'release' ORDER BY n_level"
                )
                release_branches = cur.fetchall()

            if not release_branches:
                echo("No release branches found", "yellow")
                echo("", "white")
                input("Press Enter to continue...")
                continue

            echo("Current order (0 is latest stable):", "white")
            for branch, n_level, latest in release_branches:
                echo(f"  {n_level}: {branch} ({latest})", "white")
            echo("", "white")
            echo(
                "Enter new order as comma-separated branches (e.g., 4.6,4.5,4.4)",
                "cyan",
            )
            new_order = input("New order: ").strip()

            if not new_order:
                echo("Operation cancelled", "yellow")
                echo("", "white")
                input("Press Enter to continue...")
                continue

            new_branches = [b.strip() for b in new_order.split(",")]

            # Validate that all current branches are included
            current_branches = {b[0] for b in release_branches}
            new_branches_set = set(new_branches)

            if current_branches != new_branches_set:
                echo(
                    "Error: New order must include all current release branches", "red"
                )
                echo(f"Expected: {', '.join(sorted(current_branches))}", "yellow")
                echo(f"Got: {', '.join(new_branches)}", "yellow")
                echo("", "white")
                input("Press Enter to continue...")
                continue

            # Update n_level for each branch
            with db_pool.connection() as conn, conn.cursor() as cur:
                for new_level, branch in enumerate(new_branches):
                    _ = cur.execute(
                        "UPDATE release_versions SET n_level = %s WHERE branch = %s AND status = 'release'",
                        (new_level, branch),
                    )
                conn.commit()

                echo("Branch order updated successfully!", "green")

                # Show new order
                _ = cur.execute(
                    "SELECT branch, n_level, latest FROM release_versions WHERE status = 'release' ORDER BY n_level"
                )
                new_release_branches = cur.fetchall()

                echo("\nNew order:", "white")
                for branch, n_level, latest in new_release_branches:
                    echo(f"  {n_level}: {branch} ({latest})", "white")
                # Reload global variables
                load_versions_from_db()

            echo("", "white")
            input("Press Enter to continue...")

        elif choice == "14":
            # Refresh TLD cache from IANA
            echo("", "white")
            echo("Updating TLD cache from IANA…", "bold")
            tlds = await fetch_tlds_from_iana()
            if not tlds:
                echo("Failed to fetch TLD data; cache not updated", "red")
                echo("", "white")
                input("Press Enter to continue...")
                continue

            imported = import_tlds(tlds)
            if imported > 0:
                echo(f"TLD cache updated with {imported} entries", "green")
            else:
                echo("TLD cache update completed with no entries", "yellow")

            last_updated = get_tld_last_updated()
            if last_updated is not None:
                echo(f"TLD cache last_updated: {last_updated}", "cyan")
            echo("", "white")
            input("Press Enter to continue...")

        elif choice == "15":
            # Search and display all known data for a domain
            echo("", "white")
            domain = input("Enter domain to search: ").strip().lower()
            if not domain:
                echo("Domain cannot be empty", "yellow")
                echo("", "white")
                input("Press Enter to continue...")
                continue
            display_domain_search(domain)
            echo("", "white")
            input("Press Enter to continue...")

        # Statistics Management
        elif choice == "16":
            list_flagged_statistics()
            echo("", "white")
            input("Press Enter to continue...")

        elif choice == "17":
            echo("", "white")
            date_str = input("Enter date to flag (YYYY-MM-DD): ").strip()
            if not date_str:
                echo("Date cannot be empty", "yellow")
                echo("", "white")
                input("Press Enter to continue...")
                continue
            try:
                target = date.fromisoformat(date_str)
            except ValueError:
                echo("Invalid date format, expected YYYY-MM-DD", "yellow")
                echo("", "white")
                input("Press Enter to continue...")
                continue
            reason = input("Enter reason (optional): ").strip() or None
            _ = set_statistics_invalid(target, True, reason)
            echo("", "white")
            input("Press Enter to continue...")

        elif choice == "18":
            echo("", "white")
            date_str = input("Enter date to unflag (YYYY-MM-DD): ").strip()
            if not date_str:
                echo("Date cannot be empty", "yellow")
                echo("", "white")
                input("Press Enter to continue...")
                continue
            try:
                target = date.fromisoformat(date_str)
            except ValueError:
                echo("Invalid date format, expected YYYY-MM-DD", "yellow")
                echo("", "white")
                input("Press Enter to continue...")
                continue
            _ = set_statistics_invalid(target, False, None)
            echo("", "white")
            input("Press Enter to continue...")

        # Queue Status
        elif choice == "19":
            echo("", "white")
            echo("Live queue status — refreshing every 5s. Ctrl+C to return.", "cyan")
            try:
                while True:
                    _ = os.system("clear")
                    echo(f"{appname} v{appversion} (manage mode)", "bold")
                    display_queue_status()
                    echo("Ctrl+C to return to menu", "cyan")
                    await asyncio.sleep(5)
            except KeyboardInterrupt:
                pass

        else:
            echo("Invalid choice, please try again", "yellow")

    return EXIT_SUCCESS


# =============================================================================
# ERROR HANDLING FUNCTIONS
# =============================================================================


def _handle_incorrect_file_type(domain, target, content_type):
    """Handle responses with incorrect content type."""
    if content_type == "" or content_type is None:
        content_type = "missing Content-Type"
    clean_content_type = RE_CONTENT_TYPE_CHARSET.sub("", content_type).strip()
    error_message = f"{target} is {clean_content_type}"
    echo(f"{domain}: {error_message}", "yellow", use_tqdm=True)
    log_error(domain, error_message)
    increment_domain_error(domain, f"TYPE+{target}")


def _handle_http_status_code(domain, target, response):
    """Handle non-fatal HTTP status codes."""
    code = response.status_code
    error_message = f"HTTP {code} on {target}"
    echo(f"{domain}: {error_message}", "yellow", use_tqdm=True)
    log_error(domain, error_message)
    increment_domain_error(domain, f"{code}+{target}")


def _handle_http_failed(domain, target, response):
    """Handle HTTP 410/418/451/999 hard-fail codes via error counting."""
    code = response.status_code
    error_message = f"HTTP {code} on {target}"
    echo(f"{domain}: {error_message}", "yellow", use_tqdm=True)
    log_error(domain, error_message)
    increment_domain_error(domain, f"HARD+{target}")


def _clean_exception_message(error_message: str, default: str) -> str:
    """Normalize noisy exception strings into concise error messages."""
    cleaned_message = (
        RE_CLEANUP_BRACKETS.sub("", error_message)
        .replace(":", "")
        .replace(",", "")
        .split(" for ", 1)[0]
        .lstrip()
        .rstrip(" .")
    )
    return cleaned_message or default


def _iter_exception_chain(exception: BaseException):
    """Yield exception plus chained causes/contexts exactly once."""
    seen: set[int] = set()
    current: BaseException | None = exception
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = current.__cause__ or current.__context__


def _classify_request_exception(exception: Exception) -> str:
    """Classify transport-layer exceptions into FILE/SSL/DNS/TCP buckets."""
    error_message_lower = str(exception).casefold()

    if isinstance(exception, ValueError) and "too large" in error_message_lower:
        return "FILE"
    if "bad file descriptor" in error_message_lower:
        return "FILE"

    ssl_indicators = (
        "_ssl.c",
        "ssl",
        "tls",
        "certificate",
        "cert",
        "sslcertverficationerror",
        "handshake",
        "cipher",
    )
    if any(indicator in error_message_lower for indicator in ssl_indicators):
        return "SSL"

    dns_indicators = (
        "no address associated with hostname",
        "temporary failure in name resolution",
        "address family not supported",
        "nodename nor servname provided",
        "name or service not known",
        "getaddrinfo",
        "name resolution",
    )
    if any(indicator in error_message_lower for indicator in dns_indicators):
        return "DNS"

    for cause in _iter_exception_chain(exception):
        if isinstance(cause, socket.gaierror):
            return "DNS"
        if isinstance(cause, ssl.SSLError):
            return "SSL"

    return "TCP"


def _handle_tcp_exception(domain, target, exception):
    """Handle TCP/connection exceptions with appropriate categorization."""
    error_message = str(exception)
    error_reason = _classify_request_exception(exception)

    if error_reason == "FILE":
        if (
            isinstance(exception, ValueError)
            and "too large" in error_message.casefold()
        ):
            echo(f"{domain}: Response too large", "orange", use_tqdm=True)
            log_error(domain, "Response exceeds size limit")
            increment_domain_error(domain, f"{error_reason}+{target}")
            return
        if "bad file descriptor" in error_message.casefold():
            echo(f"{domain}: Connection closed unexpectedly", "orange", use_tqdm=True)
            log_error(domain, "Bad file descriptor")
            increment_domain_error(domain, f"{error_reason}+{target}")
            return
        cleaned_message = _clean_exception_message(error_message, "File/stream error")
        echo(f"{domain}: {cleaned_message}", "orange", use_tqdm=True)
        log_error(domain, cleaned_message)
        increment_domain_error(domain, f"{error_reason}+{target}")
        return

    if error_reason == "SSL":
        cleaned_message = _clean_exception_message(
            error_message, "SSL connection error"
        )
        echo(f"{domain}: {cleaned_message}", "orange", use_tqdm=True)
        log_error(domain, cleaned_message)
        increment_domain_error(domain, f"{error_reason}+{target}")
        return

    if error_reason == "DNS":
        cleaned_message = _clean_exception_message(
            error_message, "DNS resolution failed"
        )
        echo(f"{domain}: {cleaned_message}", "orange", use_tqdm=True)
        log_error(domain, cleaned_message)
        increment_domain_error(domain, f"{error_reason}+{target}")
        return

    # All remaining transport failures are categorized as TCP.
    cleaned_message = _clean_exception_message(error_message, "TCP error")
    echo(f"{domain}: {cleaned_message}", "orange", use_tqdm=True)
    log_error(domain, cleaned_message)
    increment_domain_error(domain, f"{error_reason}+{target}")


def _handle_json_exception(domain, target, exception):
    """Handle JSON parsing exceptions."""
    error_message = str(exception)
    error_reason = f"JSON+{target}"
    echo(f"{domain}: {target} {error_message}", "yellow", use_tqdm=True)
    log_error(domain, error_message)
    increment_domain_error(domain, f"{error_reason}")


# =============================================================================
# DOMAIN PROCESSING - Validation and Filtering
# =============================================================================


def _should_skip_domain(
    domain,
    not_masto_domains,
    user_choice,
    bypass_skip_filters=False,
):
    """Check if a domain should be skipped based on its status.

    When ``bypass_skip_filters`` is True (durable queue daemon), no domain is
    skipped on its recorded state, so a domain that has *migrated* to Mastodon
    from other software can be re-detected. The claim query is the authoritative
    filter in queue mode; every domain it hands back is meant to be (re)crawled.

    In the non-queue (menu/file/target) paths, the only recorded-state skip is a
    known not-Mastodon platform. There are no terminal failure flags: a failing
    domain is simply rescheduled on its per-type cadence by the queue, never
    excluded here.
    """
    if bypass_skip_filters:
        return False
    if user_choice != "10" and domain in not_masto_domains:
        echo(f"{domain}: Other Platform", "cyan", use_tqdm=True)
        return True
    return False


def _has_valid_tld(domain: str, domain_endings: set[str]) -> bool:
    """Check TLD validity in O(1) time using direct set membership."""
    domain_parts = domain.rsplit(".", 1)
    if len(domain_parts) != 2:
        return False
    return domain_parts[1] in domain_endings


def _is_dni_domain(domain: str, dni_domains: set[str]) -> bool:
    """Check if a domain matches a configured DNI entry at a label boundary.

    An entry matches the domain itself or any subdomain of it: DNI ``example.com``
    matches ``example.com`` and ``a.b.example.com``, but not ``notexample.com`` or
    ``example.community``. This mirrors the label-boundary match in the queue claim
    query (see ``claim_due_domains``) and avoids the over-matching of a raw
    substring test (``"evil.com" in "notevil.computer"``).
    """
    return any(
        domain == dni or domain.endswith(f".{dni}") for dni in dni_domains if dni
    )


def _is_dni_or_invalid_tld(domain, dni_domains, domain_endings):
    """Check if a domain is on the DNI list or has an invalid TLD.

    Args:
        domain: Domain to check
        dni_domains: Set of DNI domains to filter out
        domain_endings: Set of valid TLDs (e.g., {"com", "org"})
    """
    if _is_dni_domain(domain, dni_domains):
        echo(f"{domain}: Purging known DNI domain", "cyan", use_tqdm=True)
        delete_domain_if_known(domain)
        delete_domain_from_raw(domain)
        return True
    if not _has_valid_tld(domain, domain_endings):
        echo(f"{domain}: Purging invalid TLD", "cyan", use_tqdm=True)
        delete_domain_if_known(domain)
        delete_domain_from_raw(domain)
        return True
    return False


# =============================================================================
# DOMAIN PROCESSING - Protocol Checks
# =============================================================================


async def check_robots_txt(domain):
    """Check robots.txt to ensure crawling is allowed.

    This is the first HTTP request to each domain.
    If robots.txt is missing (404 or other non-200 status), allows crawling to continue.
    Only blocks crawling if robots.txt explicitly disallows it (status 200 with disallow rules).
    """
    target = "robots_txt"
    url = f"https://{domain}/robots.txt"
    try:
        response = await get_httpx(url)

        if response.status_code == 200:
            content_type = response.headers.get("Content-Type", "")
            if (
                content_type in mimetypes.types_map.values()
                and not content_type.startswith("text/")
            ):
                await asyncio.to_thread(
                    _handle_incorrect_file_type,
                    domain,
                    target,
                    content_type,
                )
                return False
            robots_txt = response.text
            lines = robots_txt.splitlines()
            user_agent = None
            for line in lines:
                line = line.strip().lower()
                if line.startswith("user-agent:"):
                    user_agent = line.split(":", 1)[1].strip()
                elif line.startswith("disallow:"):
                    disallow_path = line.split(":", 1)[1].strip()
                    if user_agent in ["*", appname.lower()] and (
                        disallow_path == "/" or disallow_path == "*"
                    ):
                        error_to_print = "Crawling is prohibited by robots.txt"
                        echo(
                            f"{domain}: {error_to_print}",
                            "yellow",
                            use_tqdm=True,
                        )
                        await asyncio.to_thread(log_error, domain, error_to_print)
                        await asyncio.to_thread(
                            increment_domain_error,
                            domain,
                            "ROBOT+robots_txt",
                        )
                        return False
        elif response.status_code in http_codes_to_hardfail:
            await asyncio.to_thread(
                _handle_http_failed, domain, target, response
            )
            return False
        # Missing robots.txt (404 or other non-200 status) - allow crawling
    except httpx.RequestError as exception:
        await asyncio.to_thread(
            _handle_tcp_exception,
            domain,
            target,
            exception,
        )
        return False
    except (ValueError, RuntimeError) as exception:
        # get_httpx raises ValueError for oversized/malformed responses and
        # RuntimeError when retries are exhausted; attribute them to this
        # endpoint instead of letting them bubble to the worker's generic
        # "shutdown" handler.
        await asyncio.to_thread(
            _handle_tcp_exception,
            domain,
            target,
            exception,
        )
        return False
    return True


async def check_host_meta(domain):
    """Check host-meta endpoint to discover backend domain.

    Returns the backend domain if found, or None if not available.
    """
    url = f"https://{domain}/.well-known/host-meta"
    try:
        response = await get_httpx(url, timeout=3)
        if response.status_code == 200:
            # host-meta is typically XML
            if not response.content:
                return None

            try:
                # Parse XML to extract the webfinger template URL.
                # defusedxml neutralizes billion-laughs / quadratic blowup
                # attacks in untrusted host-meta payloads.
                from defusedxml import ElementTree as ET

                root = ET.fromstring(response.content)

                # Look for Link element with rel="lrdd"
                # Namespace handling for XRD
                ns = {"xrd": "http://docs.oasis-open.org/ns/xri/xrd-1.0"}
                link = root.find(".//xrd:Link[@rel='lrdd']", ns)

                if link is None:
                    # Try without namespace
                    link = root.find(".//Link[@rel='lrdd']")

                if link is not None:
                    template = link.get("template")
                    if template:
                        # Extract domain from template URL
                        # Template format: https://domain/.well-known/webfinger?resource={uri}
                        parsed = urlparse(template)
                        backend_domain = parsed.netloc
                        if backend_domain and backend_domain != domain:
                            return backend_domain

            except Exception:  # noqa: BLE001
                # XML parsing failed, not a valid host-meta
                # Broad exception is intentional - any parsing error should be silent
                return None

        # host-meta not available or failed
        return None

    except (httpx.RequestError, ValueError, RuntimeError):
        # Connection errors are expected when host-meta isn't available.
        # ValueError/RuntimeError cover oversized/malformed responses and
        # exhausted retries from get_httpx; this is a silent discovery probe,
        # so the real error is recorded later by the nodeinfo fallback path.
        return None


async def check_webfinger(domain):
    """Check WebFinger endpoint for backend domain discovery.

    Returns {"backend_domain": domain} on success, None on failure.
    Failures are silent (no logging) since this is a fallback method.
    """
    target = "webfinger"
    url = f"https://{domain}/.well-known/webfinger?resource=acct:{domain}@{domain}"
    try:
        response = await get_httpx(url, timeout=3)
        content_type = response.headers.get("Content-Type", "")
        content_length = response.headers.get("Content-Length", "")

        if response.status_code == 200:
            # Validate content type
            if "json" not in content_type:
                return None

            # Validate content exists
            if not response.content or content_length == "0":
                return None

            # Parse and validate JSON structure
            data = await parse_json_with_fallback(response, domain, target)
            if not data or not isinstance(data, dict):
                return None

            # Check for specific error message indicating non-Mastodon platform
            error = data.get("error")
            message = data.get("message")
            if (
                error == "unknown"
                and message == "Failed to resolve actor via webfinger"
            ):
                return None

            # Validate aliases exist
            aliases = data.get("aliases", [])
            if not aliases:
                return None

            # Find first HTTPS alias
            first_alias = next((alias for alias in aliases if "https" in alias), None)
            if not first_alias:
                return None

            # Extract and validate backend domain
            backend_domain = urlparse(first_alias).netloc
            if "localhost" in backend_domain:
                return None

            return {"backend_domain": backend_domain}

        if response.status_code in http_codes_to_hardfail:
            # Hard failures should still be logged
            _handle_http_failed(domain, target, response)
            return None
        # Other HTTP errors are silent (fallback behavior)
        return None
    except httpx.RequestError:
        # Connection errors are silent (fallback behavior)
        return None
    except json.JSONDecodeError:
        # JSON errors are silent (fallback behavior)
        return None
    except (ValueError, RuntimeError):
        # Oversized/malformed responses or exhausted retries from get_httpx;
        # silent like other webfinger fallback failures. JSONDecodeError (a
        # ValueError subclass) is handled by the clause above.
        return None


async def discover_backend_domain_parallel(domain: str) -> tuple[str, str]:
    """Discover backend domain by running host-meta and webfinger checks in parallel.

    Launches both checks simultaneously and returns the first successful result.
    This reduces latency compared to sequential fallback when host-meta fails.

    Args:
        domain: The domain to check

    Returns:
        Tuple of (backend_domain, discovery_method) where:
        - backend_domain: The discovered backend domain, or original domain if both fail
        - discovery_method: "host-meta", "webfinger", or "fallback"
    """

    async def run_host_meta():
        result = await check_host_meta(domain)
        return ("host-meta", result) if result else None

    async def run_webfinger():
        result = await check_webfinger(domain)
        if result:
            return ("webfinger", result["backend_domain"])
        return None

    # Run both checks in parallel with asyncio.gather
    results = await asyncio.gather(run_host_meta(), run_webfinger())

    # Return first successful result (prefer host-meta if both succeed)
    for result in results:
        if result:
            method, backend = result
            return (backend, method)

    # Both failed, use original domain as fallback
    return (domain, "fallback")


def _sanitize_nodeinfo_url(url: str) -> str:
    """Fix malformed nodeinfo URLs.

    Common issues:
    1. HTTP is used with port 443 (should be HTTPS)
       Example: http://domain:443/nodeinfo/2.0.json
    2. Double slashes in path (should be single slash)
       Example: https://domain//api/nodeinfo/2.0.json
    """
    parsed = urlparse(url)

    # If using http:// with port 443, change to https://
    if parsed.scheme == "http" and parsed.port == 443:
        # Reconstruct URL with https and remove explicit port 443
        netloc = parsed.hostname or parsed.netloc.split(":")[0]
        path = parsed.path
        query = f"?{parsed.query}" if parsed.query else ""
        fragment = f"#{parsed.fragment}" if parsed.fragment else ""
        url = f"https://{netloc}{path}{query}{fragment}"
        parsed = urlparse(url)

    # Fix double (or more) slashes in path
    if "//" in parsed.path:
        # Replace multiple consecutive slashes with single slash
        clean_path = RE_MULTIPLE_SLASHES.sub("/", parsed.path)
        query = f"?{parsed.query}" if parsed.query else ""
        fragment = f"#{parsed.fragment}" if parsed.fragment else ""
        url = f"{parsed.scheme}://{parsed.netloc}{clean_path}{query}{fragment}"

    return url


async def check_nodeinfo(
    domain,
    backend_domain,
    suppress_errors=False,
):
    """Check NodeInfo well-known endpoint for NodeInfo 2.0 URL.

    When suppress_errors is True, error handlers are not called, preventing
    error accumulation during probe attempts (e.g., trying nodeinfo at the
    original domain before backend discovery).
    """
    target = "nodeinfo"
    url = f"https://{backend_domain}/.well-known/nodeinfo"
    try:
        response = await get_httpx(url)
        if response.status_code == 200:
            content_type = response.headers.get("Content-Type", "")
            if "json" not in content_type:
                if suppress_errors:
                    return {
                        "suppressed_error": content_type,
                        "suppressed_error_type": "type",
                    }
                if not suppress_errors:
                    await asyncio.to_thread(
                        _handle_incorrect_file_type,
                        domain,
                        target,
                        content_type,
                    )
                return None if suppress_errors else False
            if not response.content:
                if suppress_errors:
                    return {
                        "suppressed_error": "reply is empty",
                        "suppressed_error_type": "json",
                    }
                if not suppress_errors:
                    exception = "reply is empty"
                    await asyncio.to_thread(
                        _handle_json_exception,
                        domain,
                        target,
                        exception,
                    )
                return None if suppress_errors else False
            data = await parse_json_with_fallback(
                response,
                domain,
                target,
                suppress_errors=suppress_errors,
            )
            if data is False:
                if suppress_errors:
                    return {
                        "suppressed_error": "invalid json in nodeinfo reply",
                        "suppressed_error_type": "json",
                    }
                return None if suppress_errors else False
            if not isinstance(data, dict):
                if suppress_errors:
                    return {
                        "suppressed_error": "nodeinfo reply is not an object",
                        "suppressed_error_type": "json",
                    }
                return None

            # Check if this is a Matrix server (has m.server field)
            if "m.server" in data:
                echo(f"{domain}: Matrix", "cyan", use_tqdm=True)
                # Save nodeinfo as "matrix" and mark as non-Mastodon
                await asyncio.to_thread(_save_matrix_nodeinfo, domain)
                await asyncio.to_thread(clear_domain_error, domain)
                return False

            # Check if this is actually nodeinfo data returned directly
            # instead of a well-known document with links
            if "software" in data and "version" in data:
                # This is nodeinfo data returned directly at the well-known endpoint
                # Return it as if it came from a nodeinfo_20 request
                echo(
                    f"{domain}: NodeInfo data returned directly at well-known endpoint",
                    "white",
                    use_tqdm=True,
                )
                # Return a special marker indicating we already have the nodeinfo data
                return {"nodeinfo_20_url": None, "nodeinfo_20_data": data}

            # Support both lowercase and capitalized field names
            links = data.get("links") or data.get("Links")

            # Handle case where server returns a single link object instead of array
            if (
                links is None
                and ("rel" in data or "Rel" in data)
                and ("href" in data or "Href" in data)
            ):
                echo(
                    f"{domain}: Single link object returned instead of array",
                    "white",
                    use_tqdm=True,
                )
                # Wrap the single object in an array for consistent processing
                links = [data]

            if links is not None and len(links) == 0:
                if suppress_errors:
                    return {
                        "suppressed_error": "empty links array in reply",
                        "suppressed_error_type": "json",
                    }
                if not suppress_errors:
                    exception = "empty links array in reply"
                    await asyncio.to_thread(
                        _handle_json_exception,
                        domain,
                        target,
                        exception,
                    )
                return None if suppress_errors else False
            if links:
                nodeinfo_20_url = None
                for i, link in enumerate(links):
                    # Support both lowercase and capitalized field names
                    rel_value = link.get("rel", "") or link.get("Rel", "")
                    type_value = link.get("type", "") or link.get("Type", "")
                    href_value = link.get("href", "") or link.get("Href", "")
                    if (
                        "nodeinfo.diaspora.software/ns/schema/" in rel_value
                        or "nodeinfo.diaspora.software/ns/schema/" in type_value
                        or "/nodeinfo/" in href_value
                    ):
                        # Support both lowercase and capitalized field names
                        if "href" in link or "Href" in link:
                            nodeinfo_20_url = link.get("href") or link.get("Href")
                            break
                        if (
                            i + 1 < len(links)
                            and ("href" in links[i + 1] or "Href" in links[i + 1])
                            and "rel" not in links[i + 1]
                            and "Rel" not in links[i + 1]
                        ):
                            nodeinfo_20_url = links[i + 1].get("href") or links[
                                i + 1
                            ].get("Href")
                            break

                if nodeinfo_20_url:
                    # Sanitize URL to fix common misconfigurations
                    nodeinfo_20_url = _sanitize_nodeinfo_url(nodeinfo_20_url)
                    return {"nodeinfo_20_url": nodeinfo_20_url}

            if not suppress_errors:
                exception = "no links in reply"
                await asyncio.to_thread(
                    _handle_json_exception,
                    domain,
                    target,
                    exception,
                )
            elif suppress_errors:
                return {
                    "suppressed_error": "no links in reply",
                    "suppressed_error_type": "json",
                }
            return None if suppress_errors else False
        if response.status_code in http_codes_to_hardfail:
            await asyncio.to_thread(
                _handle_http_failed, domain, target, response
            )
            return False
        if suppress_errors:
            return {"suppressed_error": response, "suppressed_error_type": "http"}
        await asyncio.to_thread(
            _handle_http_status_code,
            domain,
            target,
            response,
        )
    except httpx.RequestError as exception:
        if suppress_errors:
            return {
                "suppressed_error": exception,
                "suppressed_error_type": _classify_request_exception(exception).lower(),
            }
        await asyncio.to_thread(
            _handle_tcp_exception,
            domain,
            target,
            exception,
        )
    except json.JSONDecodeError as exception:
        if suppress_errors:
            return {"suppressed_error": exception, "suppressed_error_type": "json"}
        await asyncio.to_thread(
            _handle_json_exception,
            domain,
            target,
            exception,
        )
    except (ValueError, RuntimeError) as exception:
        # Oversized/malformed responses (ValueError) or exhausted retries
        # (RuntimeError) from get_httpx; classify like other transport errors.
        # JSONDecodeError (a ValueError subclass) is handled by the clause above.
        if suppress_errors:
            return {
                "suppressed_error": exception,
                "suppressed_error_type": _classify_request_exception(exception).lower(),
            }
        await asyncio.to_thread(
            _handle_tcp_exception,
            domain,
            target,
            exception,
        )
    return None


async def check_nodeinfo_20(
    domain,
    nodeinfo_20_url,
    from_cache=False,
):
    """Fetch and parse NodeInfo 2.0 data."""
    target = "nodeinfo_20" if not from_cache else "nodeinfo_20 (cached)"
    try:
        response = await get_httpx(nodeinfo_20_url)
        if response.status_code == 200:
            content_type = response.headers.get("Content-Type", "")
            if "json" not in content_type:
                await asyncio.to_thread(
                    _handle_incorrect_file_type,
                    domain,
                    target,
                    content_type,
                )
                return False
            if not response.content:
                exception = "reply empty"
                await asyncio.to_thread(
                    _handle_json_exception,
                    domain,
                    target,
                    exception,
                )
                return False
            nodeinfo_20_result = await parse_json_with_fallback(
                response, domain, target
            )
            if nodeinfo_20_result is False:
                return False
            return nodeinfo_20_result
        if response.status_code in http_codes_to_hardfail:
            await asyncio.to_thread(
                _handle_http_failed, domain, target, response
            )
            return False
        await asyncio.to_thread(
            _handle_http_status_code,
            domain,
            target,
            response,
        )
    except httpx.RequestError as exception:
        await asyncio.to_thread(
            _handle_tcp_exception,
            domain,
            target,
            exception,
        )
        return False
    except json.JSONDecodeError as exception:
        await asyncio.to_thread(
            _handle_json_exception,
            domain,
            target,
            exception,
        )
        return False
    except (ValueError, RuntimeError) as exception:
        # Oversized/malformed responses (ValueError) or exhausted retries
        # (RuntimeError) from get_httpx; classify like other transport errors.
        # JSONDecodeError (a ValueError subclass) is handled by the clause above.
        await asyncio.to_thread(
            _handle_tcp_exception,
            domain,
            target,
            exception,
        )
        return False
    return None


# =============================================================================
# DOMAIN PROCESSING - Instance Processing
# =============================================================================


def _is_mastodon_instance(nodeinfo_20_result: dict[str, Any]) -> bool:
    """Check if the NodeInfo response indicates a Mastodon-compatible instance."""
    if not isinstance(nodeinfo_20_result, dict):
        return False

    software = nodeinfo_20_result.get("software")
    if software is None:
        return False

    software_name = software.get("name")
    if software_name is None:
        return False

    return is_mastodon_compatible_software(software_name)


def mark_as_non_mastodon(domain, other_platform):
    """Mark a domain as a non-Mastodon platform."""
    if not other_platform:
        other_platform = "Unknown"
    other_platform = other_platform.lower().replace(" ", "-")
    echo(f"{domain}: {other_platform}", "cyan", use_tqdm=True)
    clear_domain_error(domain)
    delete_domain_if_known(domain)


async def get_instance_uri(
    backend_domain: str, domain: str
) -> tuple[str | None, bool, bool]:
    """Fetch the instance API and extract the domain/uri field.

    First tries v2 instance API for 'domain' field, then falls back to
    v1 instance API for 'uri' field if v2 fails.

    Returns:
        tuple: (domain/uri string or None, is_401 boolean, is_hardfail boolean)
            - First element is the domain/uri if successful, None otherwise
            - Second element is True if a 401 response was encountered, False otherwise
            - Third element is True if a hard-fail code (410/418/451/999) was
              encountered, in which case _handle_http_failed has already been
              invoked and the caller should return early
    """
    # Try v2 API first
    instance_api_v2_url = f"https://{backend_domain}/api/v2/instance"
    target_v2 = "instance_api_v2"

    try:
        response = await get_httpx(instance_api_v2_url)
        if response.status_code == 401:
            return (None, True, False)
        if response.status_code in http_codes_to_hardfail:
            await asyncio.to_thread(
                _handle_http_failed, domain, target_v2, response
            )
            return (None, False, True)
        if response.status_code == 200:
            content_type = response.headers.get("Content-Type", "")
            if "json" in content_type and response.content:
                instance_data = await parse_json_with_fallback(
                    response, backend_domain, target_v2
                )
                if instance_data and isinstance(instance_data, dict):
                    v2_domain = instance_data.get("domain")
                    # Normalize domain to lowercase for consistent comparison
                    if v2_domain:
                        return (v2_domain.strip().lower(), False, False)
    except (httpx.RequestError, ValueError, RuntimeError):
        # ValueError covers JSON decode errors plus oversized/malformed
        # responses from get_httpx; RuntimeError covers exhausted retries.
        pass  # Fall through to v1 API

    # Fallback to v1 API
    instance_api_v1_url = f"https://{backend_domain}/api/v1/instance"
    target_v1 = "instance_api"

    try:
        response = await get_httpx(instance_api_v1_url)
        if response.status_code == 401:
            return (None, True, False)
        if response.status_code in http_codes_to_hardfail:
            await asyncio.to_thread(
                _handle_http_failed, domain, target_v1, response
            )
            return (None, False, True)
        if response.status_code == 200:
            content_type = response.headers.get("Content-Type", "")
            if "json" not in content_type:
                return (None, False, False)
            if not response.content:
                return (None, False, False)

            instance_data = await parse_json_with_fallback(
                response, backend_domain, target_v1
            )
            if instance_data is False or not instance_data:
                return (None, False, False)

            if isinstance(instance_data, dict):
                uri = instance_data.get("uri")
                # Normalize to bare hostname: some instances return a full URL
                # (e.g. "https://example.com/") instead of just "example.com"
                if uri:
                    parsed = urlparse(uri if "://" in uri else f"https://{uri}")
                    hostname = (parsed.hostname or "").strip().lower()
                    return (hostname or None, False, False)
                return (None, False, False)
            return (None, False, False)
        return (None, False, False)
    except httpx.RequestError:
        return (None, False, False)
    except json.JSONDecodeError:
        return (None, False, False)
    except (ValueError, RuntimeError):
        # Oversized/malformed responses or exhausted retries from get_httpx;
        # caller (process_domain) records the API error when uri is None.
        return (None, False, False)


def process_mastodon_instance(
    domain,
    nodeinfo_20_result,
    nightly_version_ranges,
    actual_domain=None,
):
    """Process a confirmed Mastodon instance and update the database.

    Args:
        domain: The original domain being crawled (used for error tracking)
        nodeinfo_20_result: NodeInfo 2.0 data
        nightly_version_ranges: Version ranges for nightly builds
        actual_domain: The canonical domain from instance API
            (used for database updates)
    """
    # Use actual_domain for database operations if provided,
    # otherwise fall back to domain
    db_domain = actual_domain if actual_domain else domain

    software_version_full = nodeinfo_20_result["software"]["version"]
    software_version = clean_version(
        nodeinfo_20_result["software"]["version"],
        nightly_version_ranges,
    )

    usage = nodeinfo_20_result.get("usage", {})
    users = usage.get("users")
    if users is None:
        # Some implementations use singular "user" instead of "users".
        users = usage.get("user")

    if not isinstance(users, dict) or not users:
        error_to_print = "No usage data in NodeInfo"
        echo(f"{db_domain}: {error_to_print}", "yellow", use_tqdm=True)
        log_error(domain, error_to_print)
        increment_domain_error(domain, "JSON+nodeinfo_20")
        return

    required_fields = [
        ("total", "No user data in NodeInfo"),
        ("activeMonth", "No MAU data in NodeInfo"),
    ]

    for field, error_msg in required_fields:
        # Allow 0 user counts, but reject null values.
        if field not in users or users[field] is None:
            echo(f"{db_domain}: {error_msg}", "yellow", use_tqdm=True)
            log_error(domain, error_msg)
            increment_domain_error(domain, "JSON+nodeinfo_20")
            return

    active_month_users = users["activeMonth"]

    if version_main_branch and version.parse(
        software_version.split("-")[0]
    ) > version.parse(version_main_branch):
        error_to_print = "Mastodon version invalid"
        echo(f"{db_domain}: {error_to_print}", "yellow", use_tqdm=True)
        log_error(domain, error_to_print)
        increment_domain_error(domain, "JSON+nodeinfo_20")
        return

    # Use db_domain (actual_domain if available) for database updates
    update_mastodon_domain(
        db_domain,
        software_version,
        software_version_full,
        active_month_users,
    )

    clear_domain_error(db_domain)

    # If actual_domain is different from domain, mark original as alias and delete from mastodon_domains
    if actual_domain and actual_domain != domain:
        mark_domain_as_alias(domain)
        delete_domain_if_known(domain)

    version_info = f"Mastodon v{software_version}"
    if software_version != nodeinfo_20_result["software"]["version"]:
        version_info = f"{version_info} ({nodeinfo_20_result['software']['version']})"
    echo(f"{db_domain}: {version_info}", "green", use_tqdm=True)


async def process_domain(domain, nightly_version_ranges, user_choice=None):
    """Main processing pipeline for a single domain.

    Args:
        domain: The domain to process (will be normalized to lowercase)
        nightly_version_ranges: Version ranges for nightly builds
        user_choice: The user's menu choice (selects which domains to load)
    """
    # Normalize domain once at entry point - all downstream functions assume lowercase
    domain = domain.lower()

    if not await check_robots_txt(domain):
        return

    # Try nodeinfo at the original domain first (suppress errors since this is a
    # probe - we'll try backend discovery next if this fails, and don't want to
    # accumulate errors from the probe attempt)
    backend_domain = domain
    nodeinfo_probe_error = None
    nodeinfo_result = await check_nodeinfo(
        domain, domain, suppress_errors=True
    )
    if nodeinfo_result is False:
        return

    # Capture suppressed error from the probe for use if backend discovery also fails
    if isinstance(nodeinfo_result, dict) and "suppressed_error" in nodeinfo_result:
        nodeinfo_probe_error = nodeinfo_result
        nodeinfo_result = None

    # Nodeinfo failed at original domain; discover backend via host-meta/webfinger
    if not nodeinfo_result:
        backend_domain, discovery_method = await discover_backend_domain_parallel(
            domain
        )

        if discovery_method == "fallback":
            # Both host-meta and webfinger failed; log the original nodeinfo error
            if nodeinfo_probe_error:
                error = nodeinfo_probe_error["suppressed_error"]
                error_type = nodeinfo_probe_error["suppressed_error_type"]
                target = "nodeinfo"
                if error_type in {"tcp", "dns", "ssl", "file"}:
                    await asyncio.to_thread(
                        _handle_tcp_exception,
                        domain,
                        target,
                        error,
                    )
                elif error_type == "http":
                    await asyncio.to_thread(
                        _handle_http_status_code,
                        domain,
                        target,
                        error,
                    )
                elif error_type == "type":
                    await asyncio.to_thread(
                        _handle_incorrect_file_type,
                        domain,
                        target,
                        error,
                    )
                else:
                    await asyncio.to_thread(
                        _handle_json_exception,
                        domain,
                        target,
                        error,
                    )
            else:
                error_to_print = "Both host-meta and webfinger failed"
                echo(
                    f"{domain}: {error_to_print}",
                    "yellow",
                    use_tqdm=True,
                )
                await asyncio.to_thread(log_error, domain, error_to_print)
                await asyncio.to_thread(
                    increment_domain_error,
                    domain,
                    "TCP+nodeinfo",
                )
            return
        else:
            echo(
                f"{domain}: Found backend via {discovery_method}: {backend_domain}",
                "white",
                use_tqdm=True,
            )

        # Retry nodeinfo at the discovered backend domain
        nodeinfo_result = await check_nodeinfo(domain, backend_domain)
        if nodeinfo_result is False:
            return
        if not nodeinfo_result:
            return

    # Check if nodeinfo data was returned directly from the well-known endpoint
    if "nodeinfo_20_data" in nodeinfo_result:
        # Use the data that was already returned
        nodeinfo_20_result = nodeinfo_result["nodeinfo_20_data"]
    else:
        # Normal flow: fetch from the nodeinfo_20_url
        nodeinfo_20_url = nodeinfo_result["nodeinfo_20_url"]

        # The nodeinfo URL may point to a different backend domain (e.g. vivaldi.net
        # proxies nodeinfo but the instance API lives on the actual backend).
        # Extract the backend from the URL so get_instance_uri hits the right host.
        nodeinfo_host = urlparse(nodeinfo_20_url).hostname
        if nodeinfo_host and nodeinfo_host != backend_domain:
            backend_domain = nodeinfo_host

        nodeinfo_20_result = await check_nodeinfo_20(
            domain,
            nodeinfo_20_url,
        )
        if nodeinfo_20_result is False:
            return
        if not nodeinfo_20_result:
            return

    if _is_mastodon_instance(nodeinfo_20_result):
        # Get the actual domain from the instance API
        instance_uri, is_401, is_hardfail = await get_instance_uri(
            backend_domain, domain
        )

        if is_hardfail:
            # Instance API returned a hard-fail code (410/418/451/999);
            # _handle_http_failed already recorded the error.
            return

        if is_401:
            # Instance API requires authentication (401 Unauthorized)
            error_to_print = "Instance API requires authentication"
            echo(f"{domain}: {error_to_print}", "yellow", use_tqdm=True)
            await asyncio.to_thread(log_error, domain, error_to_print)
            await asyncio.to_thread(
                increment_domain_error, domain, "API+instance_api"
            )
            return

        if instance_uri is None:
            # Instance API endpoint is required for Mastodon instances
            error_to_print = "could not retrieve instance URI"
            echo(f"{domain}: {error_to_print}", "yellow", use_tqdm=True)
            await asyncio.to_thread(log_error, domain, error_to_print)
            await asyncio.to_thread(
                increment_domain_error,
                domain,
                "API",
            )
            return

        # Save software information from nodeinfo to database
        software_data = nodeinfo_20_result.get("software")
        if software_data and isinstance(software_data, dict):
            await asyncio.to_thread(save_nodeinfo_software, domain, software_data)

        await asyncio.to_thread(
            process_mastodon_instance,
            domain,
            nodeinfo_20_result,
            nightly_version_ranges,
            instance_uri,
        )
    else:
        # Save software information for non-Mastodon platforms unconditionally
        software_data = nodeinfo_20_result.get("software")
        if software_data and isinstance(software_data, dict):
            await asyncio.to_thread(save_nodeinfo_software, domain, software_data)

        software_name = (
            nodeinfo_20_result.get("software", {}).get("name")
            if isinstance(nodeinfo_20_result.get("software"), dict)
            else None
        )
        await asyncio.to_thread(mark_as_non_mastodon, domain, software_name)


# =============================================================================
# DOMAIN PROCESSING - Batch Processing
# =============================================================================


async def check_and_record_domains(
    domain_list,
    not_masto_domains,
    user_choice,
    dni_domains,
    domain_endings,
    nightly_version_ranges,
    reschedule: bool = False,
    bypass_skip_filters: bool = False,
    fetch_peers: bool = False,
):
    """Process a list of domains concurrently with progress tracking.

    When ``reschedule`` is True (durable queue daemon), each worker clears the
    domain's lease and sets its next due time after processing, via
    ``reschedule_domain``. When ``fetch_peers`` is also True, each worker then
    runs inline peer discovery (``maybe_fetch_peers``). See docs/durable-queue.md.

    Uses asyncio worker queues for bounded cross-domain concurrency.
    """
    max_workers = int(os.getenv("VMCRAWL_MAX_THREADS", "2"))
    heartbeat_seconds = int(os.getenv("VMCRAWL_PROGRESS_HEARTBEAT_SECONDS", "5"))
    log_all_domain_timings = os.getenv(
        "VMCRAWL_LOG_ALL_DOMAIN_TIMINGS", "false"
    ).strip().lower() in {"1", "true", "yes", "on"}
    shutdown_event = asyncio.Event()
    queue: asyncio.Queue[str | None] = asyncio.Queue()
    active_domains: set[str] = set()
    completed_domains = 0

    # Create progress bar. In queue mode the daemon runs unattended (often under
    # a service manager / log aggregator), so the live bar is just noise; disable
    # it. tqdm.write (echo use_tqdm=True) still works when the bar is disabled.
    pbar = tqdm(
        total=len(domain_list), desc="Crawling", unit="d", disable=queue_mode
    )

    def _refresh_progress_postfix() -> None:
        active_count = len(active_domains)
        remaining = max(0, len(domain_list) - completed_domains)
        pbar.set_postfix_str(
            f"inflight={active_count} done={completed_domains}/{len(domain_list)} left={remaining}",
        )
        pbar.refresh()

    async def progress_heartbeat() -> None:
        if heartbeat_seconds <= 0:
            return
        while not shutdown_event.is_set():
            await asyncio.sleep(heartbeat_seconds)
            if shutdown_event.is_set():
                break
            _refresh_progress_postfix()

    async def process_worker():
        nonlocal completed_domains
        while True:
            domain = await queue.get()
            if domain is None:
                queue.task_done()
                break

            started_at = time.monotonic()
            try:
                if shutdown_event.is_set():
                    continue

                active_domains.add(domain)
                _set_domain_start_time(domain)
                _refresh_progress_postfix()

                # Use fixed-width display to prevent bar from jumping (truncate long domains)
                domain_display = domain[:25].ljust(25)
                pbar.set_postfix_str(domain_display)
                pbar.refresh()

                if _should_skip_domain(
                    domain,
                    not_masto_domains,
                    user_choice,
                    bypass_skip_filters,
                ):
                    continue

                if _is_dni_or_invalid_tld(
                    domain,
                    dni_domains,
                    domain_endings,
                ):
                    continue

                try:
                    async with asyncio.timeout(domain_timeout):
                        await process_domain(domain, nightly_version_ranges, user_choice)
                except TimeoutError:
                    if not shutdown_event.is_set():
                        await asyncio.to_thread(
                            _handle_tcp_exception,
                            domain,
                            "timeout",
                            TimeoutError(f"Domain processing timed out after {domain_timeout}s"),
                        )
                except httpx.CloseError:
                    pass
                except Exception as exception:
                    if not shutdown_event.is_set():
                        target = "shutdown"
                        await asyncio.to_thread(
                            _handle_tcp_exception,
                            domain,
                            target,
                            exception,
                        )
            finally:
                active_domains.discard(domain)
                _clear_domain_start_time(domain)
                completed_domains += 1
                _ = pbar.update(1)
                _refresh_progress_postfix()
                elapsed_seconds = time.monotonic() - started_at
                if log_all_domain_timings:
                    echo(
                        f"{domain}: Elapsed {elapsed_seconds:.2f}s",
                        "orange",
                        use_tqdm=True,
                    )
                # Durable queue: clear the lease and set the next due time from
                # the row's resulting state. On shutdown we deliberately skip
                # this so the domain isn't pushed forward without being crawled;
                # its lease simply expires and is reclaimed.
                if reschedule and not shutdown_event.is_set():
                    await asyncio.to_thread(reschedule_domain, domain)
                # Self-feeding discovery: pull this instance's peers and import
                # new domains. Gated to healthy, active instances inside
                # maybe_fetch_peers; skipped on shutdown to avoid a late fetch.
                if fetch_peers and not shutdown_event.is_set():
                    await maybe_fetch_peers(domain, domain_endings, dni_domains)
                queue.task_done()

    try:
        worker_count = max(1, min(max_workers, len(domain_list)))
        workers = [asyncio.create_task(process_worker()) for _ in range(worker_count)]
        heartbeat_task = asyncio.create_task(progress_heartbeat())
        for domain in domain_list:
            queue.put_nowait(domain)
        for _ in range(worker_count):
            queue.put_nowait(None)

        try:
            # Wait for all workers to complete
            results = await asyncio.gather(*workers, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception) and not shutdown_event.is_set():
                    echo(f"Worker failed: {result}", "orange", use_tqdm=True)

        except asyncio.CancelledError:
            shutdown_event.set()
            for worker in workers:
                _ = worker.cancel()
            raise KeyboardInterrupt
        finally:
            shutdown_event.set()
            _ = heartbeat_task.cancel()
            _ = await asyncio.gather(heartbeat_task, return_exceptions=True)
    except KeyboardInterrupt:
        shutdown_event.set()
        raise
    finally:
        pbar.close()


async def run_queue_daemon() -> int:
    """Durable crawl queue daemon (see docs/durable-queue.md).

    Replaces the headless whole-batch re-select with a claim -> process ->
    reschedule loop over ``raw_domains`` as a Postgres lease queue. Each round
    claims a batch of due, unclaimed domains, runs them through the existing
    ``check_and_record_domains`` worker pool (which reschedules each on
    completion), and sleeps when nothing is due. Crash-safe via lease expiry.
    """
    echo(f"{appname} v{appversion} ({current_filename})", "bold")
    echo(
        f"Durable queue daemon: batch={queue_batch} lease={queue_lease_seconds}s "
        f"poll={queue_poll_seconds}s worker={_worker_id()}",
        "cyan",
    )
    if queue_peers_enabled:
        echo(
            f"Inline peer discovery: on (instances with >{peers_min_active} active users)",
            "cyan",
        )
        # The peers flag throttles failed endpoints; ensure the column exists.
        _ = await asyncio.to_thread(ensure_mastodon_peers_column)

    # Release leases left behind by a previously crashed process so their
    # domains don't show as claimed until the lease ages out.
    reclaimed = await asyncio.to_thread(reclaim_stale_leases, queue_lease_seconds)
    if reclaimed:
        echo(f"Reclaimed {reclaimed} stale lease(s) from a prior run", "yellow")

    filter_cache_ttl = int(os.getenv("VMCRAWL_FILTER_CACHE_SECONDS", "300"))
    maintenance_interval = max(
        60, int(os.getenv("VMCRAWL_QUEUE_MAINTENANCE_SECONDS", "3600"))
    )
    filter_data_cache: dict[str, Any] | None = None
    filter_data_loaded_at = 0.0
    last_maintenance = 0.0

    # Teardown is handled by async_main's cleanup_connections().
    while True:
        try:
            # Pick up version changes made by other instances each cycle.
            if _version_last_refresh is not None:
                _ = load_versions_from_db()
            else:
                await maybe_refresh_versions()

            now = time.monotonic()
            if (
                filter_data_cache is None
                or (now - filter_data_loaded_at) >= filter_cache_ttl
            ):
                filter_data_cache = await load_domain_filter_data()
                filter_data_loaded_at = now
            filter_data = filter_data_cache
            domain_endings = await get_domain_endings()

            domain_list = await asyncio.to_thread(
                claim_due_domains,
                queue_batch,
                queue_lease_seconds,
                _worker_id(),
            )

            if not domain_list:
                # Nothing due: run periodic maintenance, then back off
                # instead of hammering the table.
                if (now - last_maintenance) >= maintenance_interval:
                    cleanup_old_domains()
                    save_statistics()
                    last_maintenance = now
                await asyncio.sleep(queue_poll_seconds)
                continue

            await check_and_record_domains(
                domain_list,
                filter_data["not_masto_domains"],
                "1",
                filter_data["dni_domains"],
                domain_endings,
                filter_data["nightly_version_ranges"],
                reschedule=True,
                bypass_skip_filters=True,
                fetch_peers=queue_peers_enabled,
            )

            if (now - last_maintenance) >= maintenance_interval:
                cleanup_old_domains()
                save_statistics()
                last_maintenance = now

        except KeyboardInterrupt:
            echo(f"\n{appname} interrupted by user", "yellow")
            return EXIT_INTERRUPTED
        except psycopg.Error as exception:
            # DB became unreachable mid-cycle (pool exhausted, dropped SSH
            # tunnel, etc.). Don't crash; back off and retry.
            echo(f"Database connection error: {exception}", "red")
            echo("Waiting 30s before retrying queue cycle...", "yellow")
            try:
                await asyncio.sleep(30)
            except KeyboardInterrupt:
                return EXIT_INTERRUPTED


# =============================================================================
# STATISTICS FUNCTIONS - Mastodon Domain Counts
# =============================================================================


def get_mastodon_domains():
    """Get total count of known Mastodon domains."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cursor:
            _ = cursor.execute("SELECT COUNT(domain) AS domains FROM mastodon_domains;")
            result = cursor.fetchone()
            return result[0] if result is not None else 0
    except Exception as e:
        echo(f"Failed to obtain total Mastodon domains: {e}", "white")
        return 0


def get_unique_versions():
    """Get count of unique software versions."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cursor:
            _ = cursor.execute(
                "SELECT COUNT(DISTINCT software_version) "
                + "AS unique_software_versions FROM mastodon_domains;",
            )
            result = cursor.fetchone()
            return result[0] if result is not None else 0
    except Exception as e:
        echo(f"Failed to obtain unique versions: {e}", "white")
        return 0


# =============================================================================
# STATISTICS FUNCTIONS - User Counts
# =============================================================================


def get_mau():
    """Get total monthly active user count across all instances."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cursor:
            _ = cursor.execute(
                "SELECT SUM(active_users_monthly) AS mau FROM mastodon_domains;"
            )
            result = cursor.fetchone()
            return result[0] if result is not None else 0
    except Exception as e:
        echo(f"Failed to obtain active users: {e}", "white")
        return 0


# =============================================================================
# STATISTICS FUNCTIONS - Branch Instance Counts
# =============================================================================


def get_main_branch_instances():
    """Get count of instances on main branch."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cursor:
            _ = cursor.execute(
                """
                SELECT COUNT(DISTINCT domain) as "Main Total"
                FROM mastodon_domains
                WHERE software_version LIKE (
                    SELECT branch || '.%'
                    FROM release_versions
                    WHERE n_level = -1
                );
            """,
            )
            result = cursor.fetchone()
            return result[0] if result is not None else 0
    except Exception as e:
        echo(f"Failed to obtain total main instances: {e}", "white")
        return 0


def get_latest_branch_instances():
    """Get count of instances on latest branch."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cursor:
            _ = cursor.execute(
                """
                SELECT COUNT(DISTINCT domain) as "Latest Total"
                FROM mastodon_domains
                WHERE software_version LIKE (
                    SELECT branch || '.%'
                    FROM release_versions
                    WHERE n_level = 0
                );
            """,
            )
            result = cursor.fetchone()
            return result[0] if result is not None else 0
    except Exception as e:
        echo(f"Failed to obtain total latest instances: {e}", "white")
        return 0


def get_previous_branch_instances():
    """Get count of instances on previous release branch."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cursor:
            _ = cursor.execute(
                """
                SELECT COUNT(DISTINCT domain) as "Latest Total"
                FROM mastodon_domains
                WHERE software_version LIKE (
                    SELECT branch || '.%'
                    FROM release_versions
                    WHERE n_level = 1
                );
            """,
            )
            result = cursor.fetchone()
            return result[0] if result is not None else 0
    except Exception as e:
        echo(f"Failed to obtain total previous instances: {e}", "white")
        return 0


def get_deprecated_branch_instances():
    """Get count of instances on deprecated branches."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cursor:
            _ = cursor.execute(
                """
                SELECT COUNT(DISTINCT domain) as "Latest Total"
                FROM mastodon_domains
                WHERE EXISTS (
                    SELECT 1
                    FROM release_versions
                    WHERE status = 'release'
                      AND n_level >= 2
                      AND mastodon_domains.software_version LIKE
                          release_versions.branch || '.%'
                );
            """,
            )
            result = cursor.fetchone()
            return result[0] if result is not None else 0
    except Exception as e:
        echo(f"Failed to obtain total deprecated instances: {e}", "white")
        return 0


def get_eol_branch_instances():
    """Get count of instances on EOL branches."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cursor:
            _ = cursor.execute(
                """
                SELECT COUNT(DISTINCT mastodon_domains.domain) as "Latest Total"
                FROM mastodon_domains
                WHERE EXISTS (
                    SELECT 1
                    FROM release_versions
                    WHERE status = 'eol'
                      AND mastodon_domains.software_version LIKE
                        release_versions.branch || '.%'
                );
            """,
            )
            result = cursor.fetchone()
            return result[0] if result is not None else 0
    except Exception as e:
        echo(f"Failed to obtain total EOL instances: {e}", "white")
        return 0


# =============================================================================
# STATISTICS FUNCTIONS - Patched Instance Counts
# =============================================================================


def get_main_patched_instances():
    """Get count of instances on latest main version."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cursor:
            _ = cursor.execute(
                """
                SELECT COUNT(DISTINCT domain) as "Main Patched"
                FROM mastodon_domains
                WHERE software_version LIKE (
                    SELECT latest
                    FROM release_versions
                    WHERE status = 'main'
                ) || '%';
            """,
            )
            result = cursor.fetchone()
            return result[0] if result is not None else 0
    except Exception as e:
        echo(f"Failed to obtain main patched instances: {e}", "white")
        return 0


def get_latest_patched_instances():
    """Get count of instances on latest release version."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cursor:
            _ = cursor.execute(
                """
                SELECT COUNT(DISTINCT domain) as "Latest Patched"
                FROM mastodon_domains
                WHERE software_version LIKE (
                    SELECT latest
                    FROM release_versions
                    WHERE n_level = 0
                ) || '%';
            """,
            )
            result = cursor.fetchone()
            return result[0] if result is not None else 0
    except Exception as e:
        echo(f"Failed to obtain release patched instances: {e}", "white")
        return 0


def get_previous_patched_instances():
    """Get count of instances on latest previous branch version."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cursor:
            _ = cursor.execute(
                """
                SELECT COUNT(DISTINCT domain) as "Previous Patched"
                FROM mastodon_domains
                WHERE software_version LIKE (
                    SELECT latest
                    FROM release_versions
                    WHERE n_level = 1
                ) || '%';
            """,
            )
            result = cursor.fetchone()
            return result[0] if result is not None else 0
    except Exception as e:
        echo(f"Failed to obtain previous patched instances: {e}", "white")
        return 0


def get_deprecated_patched_instances():
    """Get count of instances on latest deprecated branch versions."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cursor:
            _ = cursor.execute(
                """
                SELECT COUNT(DISTINCT domain) as "Deprecated Patched"
                FROM mastodon_domains
                WHERE EXISTS (
                    SELECT 1
                    FROM release_versions
                    WHERE status = 'release'
                      AND n_level >= 2
                      AND mastodon_domains.software_version LIKE
                          release_versions.latest || '%'
                );
            """,
            )
            result = cursor.fetchone()
            return result[0] if result is not None else 0
    except Exception as e:
        echo(f"Failed to obtain deprecated patched instances: {e}", "white")
        return 0


# =============================================================================
# STATISTICS FUNCTIONS - Branch User Counts (Active)
# =============================================================================


def get_main_branch_mau():
    """Get active users on main branch instances."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cursor:
            _ = cursor.execute(
                """
                SELECT SUM(active_users_monthly) as "Main Total"
                FROM mastodon_domains
                WHERE software_version LIKE (
                    SELECT branch || '.%'
                    FROM release_versions
                    WHERE n_level = -1
                );
            """,
            )
            result = cursor.fetchone()
            return result[0] if result is not None else 0
    except Exception as e:
        echo(f"Failed to obtain active main instances users: {e}", "white")
        return 0


def get_latest_branch_mau():
    """Get active users on latest branch instances."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cursor:
            _ = cursor.execute(
                """
                SELECT SUM(active_users_monthly) as "Latest Total"
                FROM mastodon_domains
                WHERE software_version LIKE (
                    SELECT branch || '.%'
                    FROM release_versions
                    WHERE n_level = 0
                );
            """,
            )
            result = cursor.fetchone()
            return result[0] if result is not None else 0
    except Exception as e:
        echo(f"Failed to obtain active latest instances users: {e}", "white")
        return 0


def get_previous_branch_mau():
    """Get active users on previous release branch instances."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cursor:
            _ = cursor.execute(
                """
                SELECT SUM(active_users_monthly) as "Latest Total"
                FROM mastodon_domains
                WHERE software_version LIKE (
                    SELECT branch || '.%'
                    FROM release_versions
                    WHERE n_level = 1
                );
            """,
            )
            result = cursor.fetchone()
            return result[0] if result is not None else 0
    except Exception as e:
        echo(f"Failed to obtain active previous instances users: {e}", "white")
        return 0


def get_deprecated_branch_mau():
    """Get active users on deprecated branch instances."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cursor:
            _ = cursor.execute(
                """
                SELECT SUM(active_users_monthly) as "Latest Total"
                FROM mastodon_domains
                WHERE EXISTS (
                    SELECT 1
                    FROM release_versions
                    WHERE status = 'release'
                      AND n_level >= 2
                      AND mastodon_domains.software_version LIKE
                          release_versions.branch || '.%'
                );
            """,
            )
            result = cursor.fetchone()
            return result[0] if result is not None else 0
    except Exception as e:
        echo(f"Failed to obtain active deprecated instances users: {e}", "white")
        return 0


def get_eol_branch_mau():
    """Get active users on EOL branch instances."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cursor:
            _ = cursor.execute(
                """
                SELECT SUM(mastodon_domains.active_users_monthly) as "Latest Total"
                FROM mastodon_domains
                WHERE EXISTS (
                    SELECT 1
                    FROM release_versions
                    WHERE status = 'eol'
                      AND mastodon_domains.software_version LIKE
                        release_versions.branch || '.%'
                );
            """,
            )
            result = cursor.fetchone()
            return result[0] if result is not None else 0
    except Exception as e:
        echo(f"Failed to obtain active EOL instances users: {e}", "white")
        return 0


# =============================================================================
# STATISTICS FUNCTIONS - Patched User Counts (Active)
# =============================================================================


def get_main_patched_mau():
    """Get active users on latest main version instances."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cursor:
            _ = cursor.execute(
                """
                SELECT SUM(active_users_monthly) as "Main Patched"
                FROM mastodon_domains
                WHERE software_version LIKE (
                    SELECT latest
                    FROM release_versions
                    WHERE status = 'main'
                ) || '%';
            """,
            )
            result = cursor.fetchone()
            return result[0] if result is not None else 0
    except Exception as e:
        echo(f"Failed to obtain active main patched instances users: {e}", "white")
        return 0


def get_latest_patched_mau():
    """Get active users on latest release version instances."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cursor:
            _ = cursor.execute(
                """
                SELECT SUM(active_users_monthly) as "Latest Patched"
                FROM mastodon_domains
                WHERE software_version LIKE (
                    SELECT latest
                    FROM release_versions
                    WHERE n_level = 0
                ) || '%';
            """,
            )
            result = cursor.fetchone()
            return result[0] if result is not None else 0
    except Exception as e:
        echo(f"Failed to obtain active release patched instances users: {e}", "white")
        return 0


def get_previous_patched_mau():
    """Get active users on latest previous branch version instances."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cursor:
            _ = cursor.execute(
                """
                SELECT SUM(active_users_monthly) as "Previous Patched"
                FROM mastodon_domains
                WHERE software_version LIKE (
                    SELECT latest
                    FROM release_versions
                    WHERE n_level = 1
                ) || '%';
            """,
            )
            result = cursor.fetchone()
            return result[0] if result is not None else 0
    except Exception as e:
        echo(f"Failed to obtain active previous patched instances users: {e}", "white")
        return 0


def get_deprecated_patched_mau():
    """Get active users on latest deprecated branch version instances."""
    try:
        with db_pool.connection() as conn, conn.cursor() as cursor:
            _ = cursor.execute(
                """
                SELECT SUM(active_users_monthly) as "Deprecated Patched"
                FROM mastodon_domains
                WHERE EXISTS (
                    SELECT 1
                    FROM release_versions
                    WHERE status = 'release'
                      AND n_level >= 2
                      AND mastodon_domains.software_version LIKE
                          release_versions.latest || '%'
                );
            """,
            )
            result = cursor.fetchone()
            return result[0] if result is not None else 0
    except Exception as e:
        echo(
            f"Failed to obtain active deprecated patched instances users: {e}", "white"
        )
        return 0


# =============================================================================
# STATISTICS CONFIGURATION
# =============================================================================

# Define all statistics to collect
STATS_CONFIG = [
    ("mau", get_mau, "Total active users"),
    ("unique_versions", get_unique_versions, "Total unique versions"),
    (
        "main_instances",
        get_main_branch_instances,
        "Total main branch instances",
    ),
    (
        "latest_instances",
        get_latest_branch_instances,
        "Total release branch instances",
    ),
    (
        "previous_instances",
        get_previous_branch_instances,
        "Total previous branch instances",
    ),
    (
        "deprecated_instances",
        get_deprecated_branch_instances,
        "Total deprecated branch instances",
    ),
    (
        "eol_instances",
        get_eol_branch_instances,
        "Total EOL branch instances",
    ),
    (
        "main_patched_instances",
        get_main_patched_instances,
        "Total main patched instances",
    ),
    (
        "latest_patched_instances",
        get_latest_patched_instances,
        "Total release patched instances",
    ),
    (
        "previous_patched_instances",
        get_previous_patched_instances,
        "Total previous patched instances",
    ),
    (
        "deprecated_patched_instances",
        get_deprecated_patched_instances,
        "Total deprecated patched instances",
    ),
    ("main_branch_mau", get_main_branch_mau, "Total main branch users"),
    (
        "latest_branch_mau",
        get_latest_branch_mau,
        "Total release branch users",
    ),
    (
        "previous_branch_mau",
        get_previous_branch_mau,
        "Total previous branch users",
    ),
    (
        "deprecated_branch_mau",
        get_deprecated_branch_mau,
        "Total deprecated branch users",
    ),
    ("eol_branch_mau", get_eol_branch_mau, "Total EOL branch users"),
    (
        "main_patched_mau",
        get_main_patched_mau,
        "Total main patched users",
    ),
    (
        "latest_patched_mau",
        get_latest_patched_mau,
        "Total release patched users",
    ),
    (
        "previous_patched_mau",
        get_previous_patched_mau,
        "Total previous patched users",
    ),
    (
        "deprecated_patched_mau",
        get_deprecated_patched_mau,
        "Total deprecated patched users",
    ),
]


# =============================================================================
# STATISTICS DATABASE FUNCTIONS - Write Statistics
# =============================================================================


def save_statistics():
    # Initialize statistics dictionary
    stats_data = {}

    # Collect all statistics
    for name, fn, label in STATS_CONFIG:
        value = fn()
        stats_data[name] = value if value is not None else 0

    # Prepare values tuple in correct order
    stats_values = tuple(stats_data[name] for name, _, _ in STATS_CONFIG)

    # Write to database
    write_statistics_to_database(stats_values)


def write_statistics_to_database(stats_values):
    """Write collected statistics to the database."""
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            _ = cursor.execute(
                """
        INSERT INTO statistics (
        date, updated_at, mau, unique_versions, main_instances,
        latest_instances, previous_instances, deprecated_instances,
        eol_instances, main_patched_instances,
        latest_patched_instances, previous_patched_instances,
        deprecated_patched_instances, main_branch_mau,
        latest_branch_mau, previous_branch_mau,
        deprecated_branch_mau, eol_branch_mau,
        main_patched_mau, latest_patched_mau,
        previous_patched_mau, deprecated_patched_mau
        )
        VALUES (
        (SELECT CURRENT_DATE AT TIME ZONE 'UTC'),
        NOW() AT TIME ZONE 'UTC',
        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
        )
        ON CONFLICT (date) DO UPDATE SET
        updated_at = NOW() AT TIME ZONE 'UTC',
        mau = EXCLUDED.mau,
        unique_versions = EXCLUDED.unique_versions,
        main_instances = EXCLUDED.main_instances,
        latest_instances = EXCLUDED.latest_instances,
        previous_instances = EXCLUDED.previous_instances,
        deprecated_instances = EXCLUDED.deprecated_instances,
        eol_instances = EXCLUDED.eol_instances,
        main_patched_instances = EXCLUDED.main_patched_instances,
        latest_patched_instances = EXCLUDED.latest_patched_instances,
        previous_patched_instances = EXCLUDED.previous_patched_instances,
        deprecated_patched_instances = EXCLUDED.deprecated_patched_instances,
        main_branch_mau = EXCLUDED.main_branch_mau,
        latest_branch_mau = EXCLUDED.latest_branch_mau,
        previous_branch_mau = EXCLUDED.previous_branch_mau,
        deprecated_branch_mau = EXCLUDED.deprecated_branch_mau,
        eol_branch_mau = EXCLUDED.eol_branch_mau,
        main_patched_mau = EXCLUDED.main_patched_mau,
        latest_patched_mau = EXCLUDED.latest_patched_mau,
        previous_patched_mau = EXCLUDED.previous_patched_mau,
        deprecated_patched_mau = EXCLUDED.deprecated_patched_mau
        """,
                stats_values,
            )
            conn.commit()
        except Exception as e:
            echo(f"Failed to insert/update statistics: {e}", "white")
            conn.rollback()


# =============================================================================
# DATA LOADING FUNCTIONS
# =============================================================================


def claim_due_domains(batch: int, lease_seconds: int, worker: str) -> list[str]:
    """Atomically lease a batch of due, unclaimed, non-alias domains.

    Uses SELECT ... FOR UPDATE SKIP LOCKED so concurrent workers never claim the
    same row. The lease-expiry clause makes this self-healing: a crashed worker's
    domains become re-claimable once their lease ages past ``lease_seconds``.

    Known non-Mastodon domains are still claimed on their long recrawl cadence
    (see ``reschedule_domain``) so that a domain migrating to Mastodon from other
    software is eventually re-detected.

    Known failure domains are NOT excluded in queue mode: there are no terminal
    failure flags. Every failed domain is claimed once due and re-attempted on a
    per-type cadence derived from ``reason`` (see ``reschedule_domain``) — a 5xx
    in hours, a DNS failure backing off toward 30d, a gone/disallowed domain on a
    long flat interval — so revived servers are eventually re-counted rather than
    hammered. The only permanent exclusions are aliases and hard-DNI.

    Hard-DNI domains (dni.force = 'hard') are never claimed. The NOT EXISTS
    clause mirrors the worker-side label-boundary match in ``_is_dni_domain``,
    so a hard-DNI entry excludes the domain itself and any subdomain of it, but
    not an unrelated domain that merely contains the string. See
    docs/durable-queue.md.
    """
    query = (
        "WITH due AS ("
        "  SELECT domain FROM raw_domains"
        "  WHERE (next_crawl_at IS NULL OR next_crawl_at <= now())"
        "    AND (claimed_at IS NULL"
        "         OR claimed_at <= now() - make_interval(secs => %(lease)s))"
        "    AND (alias IS NULL OR alias = FALSE)"
        "    AND NOT EXISTS ("
        "      SELECT 1 FROM dni d"
        "      WHERE d.force = 'hard'"
        "        AND (raw_domains.domain = d.domain"
        "             OR right(raw_domains.domain, char_length(d.domain) + 1)"
        "                = '.' || d.domain)"
        "    )"
        "  ORDER BY next_crawl_at ASC NULLS FIRST"
        "  LIMIT %(batch)s"
        "  FOR UPDATE SKIP LOCKED"
        ") "
        "UPDATE raw_domains r SET claimed_at = now(), claimed_by = %(worker)s "
        "FROM due WHERE r.domain = due.domain "
        "RETURNING r.domain"
    )
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            _ = cursor.execute(
                query,
                {"lease": lease_seconds, "batch": batch, "worker": worker},
            )
            rows = cursor.fetchall()
            conn.commit()
            return [row[0] for row in rows if row[0]]
        except Exception as exception:
            echo(f"Failed to claim due domains: {exception}", "red", use_tqdm=True)
            conn.rollback()
            return []


def reschedule_domain(domain: str) -> None:
    """Clear a domain's lease and set its next due time from its resulting state.

    Deriving the interval from the row's own columns (rather than from the Python
    code path that processed it) keeps scheduling correct regardless of which
    branch recorded the result:
      * a recorded failure (reason set) -> per-type base * 2**attempts, ceilinged
        at greatest(base, cap). Transient types (DNS/SSL/TCP/HTTP/content) back
        off up to the cap (default 30d); ROBOT/HARD bases already exceed the cap
        so they stay flat at their long interval (default 30d / 90d).
      * known non-Mastodon software     -> long non-Mastodon cadence (default 7d)
      * healthy                         -> normal recrawl cadence (default 1h)
    The per-type base is selected from ``reason`` by ``_REASON_BASE_HOURS_CASE``.
    Using greatest(base, cap) as the ceiling means a long flat type is unaffected
    by backoff while a short transient type still climbs toward the cap.
    ``attempts`` is incremented on a failure and reset to 0 on success; the SET
    expressions read the pre-update row, so backoff uses the old count.
    """
    query = sql.SQL(
        "UPDATE raw_domains SET "
        "claimed_at = NULL, claimed_by = NULL, "
        "attempts = CASE WHEN reason IS NOT NULL THEN attempts + 1 ELSE 0 END, "
        "next_crawl_at = now() + (CASE "
        "  WHEN reason IS NOT NULL "
        "    THEN least(({base}) * power(2, attempts), greatest(({base}), %(cap)s)) "
        "         * (0.9 + random() * 0.2) * INTERVAL '1 hour' "
        "  WHEN nodeinfo IS NOT NULL AND nodeinfo NOT IN {masto} "
        "    THEN %(nonmasto)s * (0.9 + random() * 0.2) * INTERVAL '1 hour' "
        "  ELSE %(recrawl)s * (0.9 + random() * 0.2) * INTERVAL '1 hour' "
        "END) "
        "WHERE domain = %(domain)s"
    ).format(base=_REASON_BASE_HOURS_CASE, masto=_MASTODON_COMPATIBLE_IN_CLAUSE)
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            _ = cursor.execute(
                query,
                {
                    "cap": retry_cap_hours,
                    "nonmasto": recrawl_nonmasto_hours,
                    "recrawl": recrawl_hours,
                    "domain": domain,
                },
            )
            conn.commit()
        except Exception as exception:
            echo(
                f"{domain}: Failed to reschedule {exception}",
                "red",
                use_tqdm=True,
            )
            conn.rollback()


def reclaim_stale_leases(lease_seconds: int) -> int:
    """Clear leases left behind by a crashed process; returns rows reclaimed.

    The claim query already self-heals via lease expiry; this is startup/periodic
    housekeeping so stale claimed_by values don't linger in the table.
    """
    query = (
        "UPDATE raw_domains SET claimed_at = NULL, claimed_by = NULL "
        "WHERE claimed_at IS NOT NULL "
        "  AND claimed_at <= now() - make_interval(secs => %(lease)s)"
    )
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            _ = cursor.execute(query, {"lease": lease_seconds})
            count = cursor.rowcount
            conn.commit()
            return count if count and count > 0 else 0
        except Exception as exception:
            echo(f"Failed to reclaim stale leases: {exception}", "red", use_tqdm=True)
            conn.rollback()
            return 0


def load_from_database(user_choice):
    """Load domain list from database based on user menu selection."""
    # Common filter to exclude alias domains from all raw_domains queries
    no_alias = "AND (alias IS NULL OR alias = FALSE) "

    query_map = {
        # --new one-shot flag: brand-new, never-crawled domains.
        "0": (
            "SELECT domain FROM raw_domains "
            "WHERE reason IS NULL AND nodeinfo IS NULL "
            + no_alias
            + "ORDER BY LENGTH(DOMAIN)"
        ),
        "50": (
            "SELECT domain FROM mastodon_domains WHERE "
            "software_version != ALL(%(versions)s::text[]) "
            "ORDER BY active_users_monthly DESC"
        ),
        "51": (
            "SELECT domain FROM mastodon_domains WHERE software_version LIKE %s "
            "ORDER BY active_users_monthly DESC"
        ),
        "52": (
            "SELECT domain FROM mastodon_domains ORDER BY active_users_monthly DESC"
        ),
        "53": sql.SQL(
            "SELECT domain FROM raw_domains "
            "WHERE nodeinfo IN {masto_clause} "
            "AND (alias IS NULL OR alias = FALSE) "
            "ORDER BY domain"
        ).format(masto_clause=_MASTODON_COMPATIBLE_IN_CLAUSE),
    }

    params = None
    query = query_map.get(user_choice)

    if user_choice == "50":
        patched_versions = all_patched_versions or []
        params = {"versions": patched_versions}
        echo("Excluding versions:", "cyan")
        for ver in patched_versions:
            echo(f" - {ver}", "cyan")
    elif user_choice == "51":
        params = [f"{version_main_branch or ''}%"]

    if not query:
        echo(f"Choice {user_choice} is invalid, using default query", "yellow")
        query = query_map["53"]

    # Use server-side cursor for large result sets to avoid loading all into memory
    with db_pool.connection() as conn, conn.cursor(name="domain_loader") as cursor:
        cursor.itersize = 1000  # Fetch 1000 rows at a time
        try:
            if params:
                _ = cursor.execute(query, params)  # pyright: ignore[reportCallIssue,reportArgumentType]
            else:
                _ = cursor.execute(query)  # pyright: ignore[reportCallIssue,reportArgumentType]
            domain_list = [
                row[0].strip() for row in cursor if row[0] and row[0].strip()
            ]
            conn.commit()
        except Exception as exception:
            echo(f"Failed to obtain selected domain list: {exception}", "red")
            conn.rollback()
            domain_list = []

    return domain_list


def load_from_file(file_name):
    """Load domain list from a file and add new domains to database."""
    domain_list = []
    with (
        db_pool.connection() as conn,
        conn.cursor() as cursor,
        open(os.path.expanduser(file_name)) as file,
    ):
        for line in file:
            domain = line.strip().lower()
            if not domain:
                continue

            domain_list.append(domain)
            _ = cursor.execute(
                "SELECT COUNT(*) FROM raw_domains WHERE domain = %s",
                (domain,),
            )
            result = cursor.fetchone()
            exists = result is not None and result[0] > 0

            if not exists:
                _ = cursor.execute(
                    "INSERT INTO raw_domains (domain) VALUES (%s)",
                    (domain,),
                )
            conn.commit()
    return domain_list


# =============================================================================
# MENU AND CLI FUNCTIONS
# =============================================================================


def get_menu_options() -> dict[str, dict[str, str]]:
    """Return the menu options dictionary.

    The per-domain raw_domains workloads (uncrawled, errors-by-type, fatal,
    offline/issues) are now handled automatically by the durable queue daemon, so
    the interactive launcher only offers targeted re-scans of known instances plus
    entry points to join the queue or open manage mode.
    """
    return {
        "Retry known instances": {
            "50": "Unpatched",
            "51": f"{version_main_branch}",
            "52": "Active",
            "53": "All",
        },
        "Daemon": {
            "90": "Join crawl queue",
            "91": "Manage DNI / versions",
        },
    }


def print_menu(menu_options: dict[str, dict[str, str]] | None = None) -> None:
    """Print the text-based menu to stdout."""
    if menu_options is None:
        menu_options = get_menu_options()

    for category, options in menu_options.items():
        options_str = " ".join(f"({key}) {value}" for key, value in options.items())
        echo(f"{category}: ", "cyan", end="")
        echo(options_str, "")
    echo("Enter your choice (1, 2, 3, etc):", "bold", end=" ")
    _ = sys.stdout.flush()


def interactive_select_menu(menu_options: dict[str, dict[str, str]]) -> str | None:
    """Interactive menu picker using arrow keys (TTY only)."""
    if _is_running_headless():
        return None

    try:
        import curses
    except Exception:
        return None

    rows = []
    selectable_indices = []
    for category, options in menu_options.items():
        rows.append({"type": "header", "label": category})
        for key, value in options.items():
            rows.append({"type": "option", "key": key, "label": f"({key}) {value}"})
            selectable_indices.append(len(rows) - 1)

    if not selectable_indices:
        return None

    def _menu(stdscr):
        if curses.has_colors():
            curses.start_color()
            try:
                curses.use_default_colors()
            except curses.error:
                pass

        # Keep the launcher tied to the terminal's default background instead
        # of painting its own background color.
        stdscr.bkgd(" ", curses.A_NORMAL)
        _ = curses.curs_set(0)
        stdscr.nodelay(False)
        stdscr.keypad(True)
        selected_row_idx = selectable_indices[0]

        while True:
            stdscr.erase()
            stdscr.addstr(0, 0, "Use ↑/↓ or j/k, Enter to select, q to quit")
            line = 2
            for i, row in enumerate(rows):
                if row["type"] == "header":
                    stdscr.addstr(line, 0, row["label"], curses.A_BOLD)
                else:
                    prefix = "> " if i == selected_row_idx else "  "
                    stdscr.addstr(line, 0, f"{prefix}{row['label']}")
                line += 1
            stdscr.refresh()

            ch = stdscr.getch()
            if ch in (curses.KEY_UP, ord("k")):
                current_idx = selectable_indices.index(selected_row_idx)
                selected_row_idx = selectable_indices[
                    (current_idx - 1) % len(selectable_indices)
                ]
            elif ch in (curses.KEY_DOWN, ord("j")):
                current_idx = selectable_indices.index(selected_row_idx)
                selected_row_idx = selectable_indices[
                    (current_idx + 1) % len(selectable_indices)
                ]
            elif ch in (curses.KEY_ENTER, 10, 13):
                return rows[selected_row_idx]["key"]
            elif ch in (ord("q"), 27):
                return "__quit__"

    try:
        return curses.wrapper(_menu)
    except Exception:
        return None


def get_user_choice() -> str:
    """Read user menu choice from stdin."""
    value = sys.stdin.readline()
    if value == "":
        raise KeyboardInterrupt
    user_choice = value.strip().lower()
    if user_choice in {"q", "quit", "exit"}:
        raise KeyboardInterrupt
    return user_choice


# =============================================================================
# MODULE-LEVEL INITIALIZATION
# =============================================================================

# Version information (initialized lazily in async context)
version_main_branch: str | None = None
version_main_release: str | None = None
version_latest_release: str | None = None
version_backport_releases: list[str] | None = None
all_patched_versions: list[str] | None = None

# Track last version refresh time for periodic updates
_version_last_refresh: float | None = None
# Refresh interval in seconds (default: 1 hour, configurable via environment)
VERSION_REFRESH_INTERVAL = int(os.getenv("VMCRAWL_VERSION_REFRESH_INTERVAL", "3600"))


def load_versions_from_db():
    """Load version information from database into global variables.

    Returns True if versions were loaded successfully, False otherwise.
    """
    global version_main_branch, version_main_release, version_latest_release
    global version_backport_releases, all_patched_versions

    db_versions = get_release_versions_from_db()

    if not db_versions:
        return False

    version_main_branch = db_versions.get("main_branch")
    version_main_release = db_versions.get("main_release")
    version_latest_release = db_versions.get("latest_stable")
    version_backport_releases = db_versions.get("backport_releases")
    all_patched_versions = db_versions.get("all_patched")

    return True


async def initialize_versions():
    """Initialize version information by fetching latest versions from GitHub.

    Note: Branch management is now done manually through the manage menu.
    This only updates the 'latest' column for existing branches in the database.
    """
    global version_main_branch, version_main_release, version_latest_release
    global version_backport_releases, all_patched_versions, _version_last_refresh

    # Fetch latest versions for all tracked branches
    main_release = await get_main_version_release()
    tracked_versions = await get_all_tracked_mastodon_versions()

    # Update database with latest versions (only updates existing branches)
    with db_pool.connection() as conn, conn.cursor() as cur:
        # Update main branch (n_level = -1)
        _ = cur.execute(
            "UPDATE release_versions SET latest = %s WHERE n_level = -1",
            (main_release,),
        )

        # Update release and EOL branches (only existing ones)
        for branch, version_str in tracked_versions.items():
            _ = cur.execute(
                "UPDATE release_versions SET latest = %s WHERE branch = %s AND status IN ('release', 'eol')",
                (version_str, branch),
            )

        conn.commit()

    # Reload global variables from database
    load_versions_from_db()

    # Record refresh timestamp
    _version_last_refresh = time.time()


async def maybe_refresh_versions():
    """Refresh version info if it's been too long since last refresh.

    Checks if VERSION_REFRESH_INTERVAL seconds have passed since the last
    refresh and updates version information from GitHub if needed.
    Also initializes versions on first run if not already loaded.

    First attempts to load from database (fast), then falls back to GitHub
    if database is empty or refresh interval has passed.
    """
    global _version_last_refresh

    now = time.time()

    # First run - try to load from database
    if _version_last_refresh is None:
        if load_versions_from_db():
            # Successfully loaded from database (silent - this is expected)
            _version_last_refresh = now
            return
        else:
            # Database empty, fetch from GitHub
            echo("Fetching version information from GitHub...", "cyan")
            await initialize_versions()
            return

    # Refresh if interval has passed
    if (now - _version_last_refresh) >= VERSION_REFRESH_INTERVAL:
        echo("Refreshing version information from GitHub...", "cyan")
        await initialize_versions()


# =============================================================================
# MAIN FUNCTION
# =============================================================================


async def async_main() -> int:
    """Main entry point for the crawler."""
    parser = argparse.ArgumentParser(
        description="Crawl version information from Mastodon instances.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Fetch subcommand
    fetch_parser = subparsers.add_parser(
        "fetch", help="Fetch peer data from Mastodon instances to discover new domains"
    )
    _ = fetch_parser.add_argument(
        "-l",
        "--limit",
        type=int,
        help=(
            f"limit the number of domains requested from database "
            f"(default: {int(os.getenv('VMCRAWL_FETCH_LIMIT', '10'))})"
        ),
    )
    _ = fetch_parser.add_argument(
        "-o",
        "--offset",
        type=int,
        help=(
            f"offset the top of the domains requested from database "
            f"(default: {int(os.getenv('VMCRAWL_FETCH_OFFSET', '0'))})"
        ),
    )
    _ = fetch_parser.add_argument(
        "-r",
        "--random",
        action="store_true",
        help="randomize the order of the domains returned (default: disabled)",
    )
    _ = fetch_parser.add_argument(
        "-t",
        "--target",
        type=str,
        help="target only a specific domain and ignore the database (ex: vmst.io)",
    )

    # Crawl subcommand (default behavior)
    crawl_parser = subparsers.add_parser(
        "crawl", help="Crawl version information from Mastodon instances (default)"
    )
    _ = crawl_parser.add_argument(
        "-f",
        "--file",
        type=str,
        help="bypass database and use a file instead (ex: ~/domains.txt)",
    )
    _ = crawl_parser.add_argument(
        "-r",
        "--new",
        action="store_true",
        help="only process new, never-crawled domains, then exit (one-shot)",
    )
    _ = crawl_parser.add_argument(
        "-t",
        "--target",
        type=str,
        help="target only a specific domain and ignore the database (ex: vmst.io)",
    )
    _ = crawl_parser.add_argument(
        "--db",
        type=str,
        help="show known domain details from raw_domains and mastodon_domains, then exit (ex: vmst.io)",
    )

    # Manage subcommand (unified DNI and nightly management)
    _ = subparsers.add_parser(
        "manage", help="Manage DNI list and nightly versions (menu-driven interface)"
    )

    # Also add crawl arguments to main parser for backwards compatibility
    _ = parser.add_argument(
        "-f",
        "--file",
        type=str,
        help="bypass database and use a file instead (ex: ~/domains.txt)",
    )
    _ = parser.add_argument(
        "-r",
        "--new",
        action="store_true",
        help="only process new, never-crawled domains, then exit (one-shot)",
    )
    _ = parser.add_argument(
        "-t",
        "--target",
        type=str,
        help="target only a specific domain and ignore the database (ex: vmst.io)",
    )
    _ = parser.add_argument(
        "--db",
        type=str,
        help="show known domain details from raw_domains and mastodon_domains, then exit (ex: vmst.io)",
    )

    args = parser.parse_args()

    # Helper function for cleanup
    async def cleanup_connections():
        try:
            await close_http_client()
        except Exception:
            pass
        try:
            db_pool.close(timeout=5)
        except Exception:
            pass
        if _ssh_transport is not None:
            try:
                _ssh_transport.close()
            except Exception:
                pass
        _ = gc.collect()

    try:
        # Handle fetch subcommand
        if args.command == "fetch":
            try:
                return await run_fetch_mode(args)
            except KeyboardInterrupt:
                echo(f"\n{appname} interrupted by user", "yellow")
                return EXIT_INTERRUPTED

        # Handle manage subcommand (unified DNI and nightly management)
        if args.command == "manage":
            try:
                return await run_manage_mode(args)
            except KeyboardInterrupt:
                echo(f"\n{appname} interrupted by user", "yellow")
                return EXIT_INTERRUPTED

        # Default crawl behavior (no subcommand or 'crawl' subcommand)
        if args.command == "crawl" or args.command is None:
            if args.db:
                if args.file or args.target or args.new:
                    echo(
                        "You cannot combine --db with --file, --target, or --new",
                        "red",
                    )
                    return EXIT_FAILURE
                display_domain_search(args.db)
                return EXIT_SUCCESS

            if (
                hasattr(args, "file")
                and hasattr(args, "target")
                and args.file
                and args.target
            ):
                echo("You cannot set both file and target arguments", "red")
                return EXIT_FAILURE

            # Durable crawl queue daemon. Headless runs always join the queue;
            # interactive runs can also opt in via VMCRAWL_QUEUE_MODE (or the
            # menu's "Join crawl queue" option below). One-shot --file/--target/
            # --new runs keep the whole-batch behavior. See docs/durable-queue.md.
            if (queue_mode or _is_running_headless()) and not (
                args.file or args.target or args.new
            ):
                try:
                    return await run_queue_daemon()
                except KeyboardInterrupt:
                    echo(f"\n{appname} interrupted by user", "yellow")
                    return EXIT_INTERRUPTED

        # Main crawl loop - runs continuously in headless mode, once in interactive mode
        echo(f"{appname} v{appversion} ({current_filename})", "bold")
        if _is_running_headless():
            echo("Running in headless mode", "cyan")

        # Determine if we should loop (headless without one-shot flags)
        should_loop = _is_running_headless() and not (
            args.file or args.target or args.new
        )
        filter_cache_ttl = int(os.getenv("VMCRAWL_FILTER_CACHE_SECONDS", "300"))
        filter_data_cache: dict[str, Any] | None = None
        filter_data_loaded_at = 0.0

        while True:
            try:
                # Reload version info from database on each loop iteration
                # This ensures we pick up changes made by other instances
                if should_loop and _version_last_refresh is not None:
                    # In continuous mode, reload from database each cycle
                    _ = load_versions_from_db()
                else:
                    # First run or single-shot mode: use normal refresh logic
                    await maybe_refresh_versions()

                domain_list_file = args.file if args.file is not None else None
                single_domain_target = args.target if args.target is not None else None
                try:
                    if domain_list_file:
                        user_choice = "1"
                        domain_list = load_from_file(domain_list_file)
                        echo("Crawling domains from provided file", "cyan")
                    elif single_domain_target:
                        user_choice = "1"
                        domain_list = single_domain_target.replace(" ", "").split(",")
                        domain_word = "s" if len(domain_list) > 1 else ""
                        echo(
                            f"Crawling domain{domain_word} from target argument",
                            "cyan",
                        )
                    else:
                        # Headless always joins the queue daemon above, so this
                        # branch is interactive (or the explicit --new one-shot).
                        if args.new:
                            user_choice = "0"
                        else:
                            menu_options = get_menu_options()
                            selection = interactive_select_menu(menu_options)
                            if selection == "__quit__":
                                raise KeyboardInterrupt
                            if selection is None:
                                print_menu(menu_options)
                                user_choice = get_user_choice()
                            else:
                                user_choice = selection

                        # Daemon menu entries: join the queue or open manage mode.
                        if user_choice == "90":
                            return await run_queue_daemon()
                        if user_choice == "91":
                            return await run_manage_mode(args)

                        echo(
                            f"Crawling domains from database choice {user_choice}",
                            "cyan",
                        )
                        domain_list = load_from_database(user_choice)

                except FileNotFoundError:
                    echo(f"File not found: {domain_list_file}", "red")
                    return EXIT_FAILURE
                except psycopg.Error as exception:
                    echo(f"Database error: {exception}", "red")
                    return EXIT_FAILURE

                now = time.monotonic()
                if (
                    filter_data_cache is None
                    or (now - filter_data_loaded_at) >= filter_cache_ttl
                ):
                    filter_data_cache = await load_domain_filter_data()
                    filter_data_loaded_at = now
                filter_data = filter_data_cache
                domain_endings = await get_domain_endings()

                await check_and_record_domains(
                    domain_list,
                    filter_data["not_masto_domains"],
                    user_choice,
                    filter_data["dni_domains"],
                    domain_endings,
                    filter_data["nightly_version_ranges"],
                )

                cleanup_old_domains()
                save_statistics()

                # Exit loop if not in continuous headless mode
                if not should_loop:
                    return EXIT_SUCCESS

                # Brief pause before next cycle to avoid tight loop
                echo("Restarting crawl cycle...", "cyan")
                await asyncio.sleep(1)

            except KeyboardInterrupt:
                echo(f"\n{appname} interrupted by user", "yellow")
                return EXIT_INTERRUPTED

            except psycopg.Error as exception:
                # Database became unreachable mid-cycle (pool exhausted, backend
                # closed the connection, dropped SSH tunnel, etc.). Don't crash
                # with a traceback. Retry after a backoff in continuous mode;
                # exit cleanly with a failure code for one-shot runs.
                echo(f"Database connection error: {exception}", "red")
                if not should_loop:
                    return EXIT_FAILURE
                echo("Waiting 30s before retrying crawl cycle...", "yellow")
                try:
                    await asyncio.sleep(30)
                except KeyboardInterrupt:
                    return EXIT_INTERRUPTED

    finally:
        await cleanup_connections()


# =============================================================================
# ENTRY POINT
# =============================================================================


def main():
    """Sync entry point that runs the async main function."""
    try:
        raise SystemExit(asyncio.run(async_main()))
    except KeyboardInterrupt:
        # Handles interrupts that occur during asyncio shutdown.
        raise SystemExit(EXIT_INTERRUPTED)


if __name__ == "__main__":
    main()
