#!/usr/bin/env python3

# =============================================================================
# IMPORTS
# =============================================================================
from datetime import UTC

try:
    import argparse
    import atexit
    import gc
    import hashlib
    import json
    import mimetypes
    import os
    import random
    import re
    import ssl
    import sys
    import threading
    import time
    import unicodedata
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from datetime import datetime, timedelta
    from typing import Any
    from urllib.parse import urlparse

    import httpx
    import psycopg
    import toml
    from dotenv import load_dotenv
    from packaging import version
    from psycopg_pool import ConnectionPool
    from tqdm import tqdm
except ImportError as exception:
    print(f"Error importing module: {exception}")
    sys.exit(1)

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
    appname: str = project_info["project"]["name"]
    appversion: str = project_info["project"]["version"]
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
    "green": "\033[92m",
    "magenta": "\033[95m",
    "orange": "\033[38;5;208m",
    "pink": "\033[38;5;198m",
    "purple": "\033[94m",
    "red": "\033[91m",
    "yellow": "\033[93m",
    "white": "\033[0m",
}

# HTTP status codes for special handling
http_codes_to_hardfail = [999, 451, 418, 410]  # gone

# Define maintained branches (adjust as needed)
backport_branches = ["4.5", "4.4", "4.3"]

# =============================================================================
# DATABASE CONNECTION
# =============================================================================

conn_string = (
    f"postgresql://{os.getenv('VMCRAWL_POSTGRES_USER')}:"
    f"{os.getenv('VMCRAWL_POSTGRES_PASS')}@"
    f"{os.getenv('VMCRAWL_POSTGRES_HOST', 'localhost')}:"
    f"{os.getenv('VMCRAWL_POSTGRES_PORT', '5432')}/"
    f"{os.getenv('VMCRAWL_POSTGRES_DATA')}"
)

# Create connection pool for thread-safe database access
# Scale connection pool size with number of worker threads
# With PgBouncer: Connection multiplexing allows more application connections
# Without PgBouncer: May need to adjust based on database server capacity
max_workers = int(os.getenv("VMCRAWL_MAX_THREADS", "2"))
max_db_connections = max_workers  # One connection per worker thread

try:
    db_pool = ConnectionPool(
        conn_string,
        min_size=2,  # Keep 2 warm connections
        max_size=max_db_connections,
        timeout=30,
        max_waiting=max_workers,  # Allow worker threads to queue
    )
    # Maintain single connection for backwards compatibility
    conn = psycopg.connect(conn_string)

    # Register cleanup handler to prevent threading errors on early exit
    def cleanup_db_connections():
        try:
            conn.close()
        except Exception:
            pass
        try:
            db_pool.close(timeout=5)
        except Exception:
            pass

    _ = atexit.register(cleanup_db_connections)
except psycopg.Error as exception:
    print(f"Error connecting to PostgreSQL database: {exception}")
    sys.exit(1)

# =============================================================================
# HTTP CLIENT CONFIGURATION
# =============================================================================

http_timeout = int(os.getenv("VMCRAWL_HTTP_TIMEOUT", "5"))
http_redirect = int(os.getenv("VMCRAWL_HTTP_REDIRECT", "1"))
http_custom_user_agent = f"{appname}/{appversion} (https://docs.vmst.io/{appname})"
http_custom_headers = {"User-Agent": http_custom_user_agent}

# Memory protection: limit response sizes to prevent memory bombs
# Max response size: 10MB (should be plenty for any legitimate Mastodon API response)
max_response_size = int(os.getenv("VMCRAWL_MAX_RESPONSE_SIZE", str(10 * 1024 * 1024)))

# Create limits object for httpx
# Scale connection limits with number of worker threads
# Each thread may need multiple connections (robots.txt, host-meta, nodeinfo, etc.)
limits = httpx.Limits(
    max_keepalive_connections=max_workers * 5,
    max_connections=max_workers * 10,
    keepalive_expiry=30.0,
)

# Create SSL context with TLS 1.2+ and disable post-quantum key exchange
# Some servers reject MLKEM (post-quantum crypto) with "tlsv1 alert internal error"
# This is a known issue with OpenSSL 3.6.0+ and certain server configurations
ssl_context = ssl.create_default_context()
ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
# Disable MLKEM post-quantum key exchange (SSL_OP_NO_MLKEM)
ssl_context.options |= 0x800000

http_client = httpx.Client(
    http2=False,
    follow_redirects=True,
    headers=http_custom_headers,
    timeout=http_timeout,
    limits=limits,
    max_redirects=http_redirect,
    verify=ssl_context,
)

# =============================================================================
# UTILITY FUNCTIONS - Output and Environment
# =============================================================================


def vmc_output(text: str, color: str, use_tqdm: bool = False, **kwargs: Any) -> None:
    """Print colored output, optionally using tqdm.write."""
    if use_tqdm:
        text = text.lower()

    if ":" in text:
        before_colon, after_colon = text.split(":", 1)
        colored_text = (
            f"{before_colon}:{colors.get(color, '')}{after_colon}{colors['reset']}"
        )
    else:
        colored_text = f"{colors.get(color, '')}{text}{colors['reset']}"

    if use_tqdm:
        tqdm.write(colored_text, **kwargs)
    else:
        print(colored_text, **kwargs)


def is_running_headless():
    """Check if running without a TTY (headless mode)."""
    return not os.isatty(sys.stdout.fileno())


# =============================================================================
# UTILITY FUNCTIONS - Caching
# =============================================================================


def get_cache_file_path(url: str) -> str:
    """Create a unique cache file path based on the URL hash."""
    url_hash = hashlib.md5(url.encode()).hexdigest()
    cache_dir = "/tmp/vmcrawl_cache"
    os.makedirs(cache_dir, exist_ok=True)
    return os.path.join(cache_dir, f"{url_hash}.cache")


def is_cache_valid(cache_file_path: str, max_age_seconds: int) -> bool:
    """Check if a cache file exists and is still valid."""
    if not os.path.exists(cache_file_path):
        return False
    cache_age = time.time() - os.path.getmtime(cache_file_path)
    return cache_age < max_age_seconds


# =============================================================================
# UTILITY FUNCTIONS - Validation
# =============================================================================


def is_alias_domain(domain: str, backend_domain: str) -> bool:
    """Check if domain is an alias that should not be stored in the database.

    Only the authoritative/canonical domain (from backend_domain or instance API)
    should be stored. Any domain that differs from the authoritative domain is an alias.

    Args:
        domain: The original domain being crawled
        backend_domain: The authoritative domain (from host-meta/webfinger/instance API)

    Returns:
        True if domain is different from backend_domain (is an alias)
        False if domain equals backend_domain (is authoritative)

    Examples:
        is_alias_domain("example.com", "example.com") -> False (same, not alias)
        is_alias_domain("example.com", "social.example.com") -> True (different, is alias)
        is_alias_domain("social.example.com", "example.com") -> True (different, is alias)
        is_alias_domain("example.com", "other.com") -> True (different, is alias)
    """
    # Normalize domains to lowercase
    domain = domain.lower()
    backend_domain = backend_domain.lower()

    # Only exact match means not an alias
    # Any difference means this domain is an alias of the authoritative domain
    return domain != backend_domain


def parse_json_with_fallback(
    response: httpx.Response,
    domain: str,
    target: str,
    preserve_ignore: bool = False,
    preserve_nxdomain: bool = False,
) -> Any | bool:
    """Parse JSON from response with fallback decoder for malformed JSON.

    Args:
        response: httpx Response object
        domain: Domain being processed (for error reporting)
        target: Target endpoint name (for error reporting)
        preserve_ignore: If True, preserve the ignore flag when recording errors
        preserve_nxdomain: If True, preserve the nxdomain flag when recording errors

    Returns:
        Parsed JSON data or False on error
    """
    try:
        return response.json()
    except json.JSONDecodeError:
        try:
            decoder = json.JSONDecoder()
            data, _ = decoder.raw_decode(response.text, 0)
            return data
        except json.JSONDecodeError as exception:
            handle_json_exception(
                domain, target, exception, preserve_ignore, preserve_nxdomain
            )
            return False


def has_emoji_chars(domain: str) -> bool:
    """Check if a domain contains emoji or invalid characters."""
    if domain.startswith("xn--"):
        try:
            domain = domain.encode("ascii").decode("idna")
        except Exception:
            return True
    try:
        for char in domain:
            if unicodedata.category(char) in ["So", "Cf"] or ord(char) >= 0x1F300:
                return True
            if not (char.isalnum() or char in "-_."):
                return True
    except Exception:
        return True
    return False


# =============================================================================
# HTTP FUNCTIONS
# =============================================================================


def get_httpx(url: str, http_client: httpx.Client) -> httpx.Response:
    """Make HTTP GET request with size limits."""

    def stream_with_size_limit(client: httpx.Client, url: str) -> httpx.Response:
        """Stream response and enforce size limit during download."""
        # Get the stream context manager and enter it manually
        stream_ctx = client.stream("GET", url)
        response = stream_ctx.__enter__()

        try:
            # Check Content-Length header first if available
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > max_response_size:
                _ = stream_ctx.__exit__(None, None, None)
                msg = (
                    f"Response too large: {content_length} bytes "
                    f"(max: {max_response_size})"
                )
                raise ValueError(msg)

            # Stream the response and check size as we download
            chunks = []
            total_size = 0

            for chunk in response.iter_bytes(chunk_size=8192):
                chunks.append(chunk)
                total_size += len(chunk)

                if total_size > max_response_size:
                    _ = stream_ctx.__exit__(None, None, None)
                    msg = (
                        f"Response too large: {total_size} bytes "
                        f"(max: {max_response_size})"
                    )
                    raise ValueError(msg)

            # All data received within size limit - construct final response
            # We need to manually build a Response object with our collected data
            final_response = httpx.Response(
                status_code=response.status_code,
                headers=response.headers,
                request=response.request,
            )
            # Directly set the content to bypass decompression
            final_response._content = b"".join(chunks)

            _ = stream_ctx.__exit__(None, None, None)
            return final_response

        except Exception:
            _ = stream_ctx.__exit__(None, None, None)
            raise

    return stream_with_size_limit(http_client, url)


def get_domain_endings() -> set[str]:
    """Fetch and cache the set of valid TLDs from IANA."""
    url = "http://data.iana.org/TLD/tlds-alpha-by-domain.txt"
    cache_file_path = get_cache_file_path(url)
    max_cache_age = 86400  # 1 day in seconds

    if is_cache_valid(cache_file_path, max_cache_age):
        with open(cache_file_path) as cache_file:
            # Use set for O(1) lookup
            return {line.strip().lower() for line in cache_file if line.strip()}

    domain_endings_response = get_httpx(url, http_client)
    if domain_endings_response.status_code in [200]:
        # Use set for O(1) lookup
        domain_endings = {
            line.strip().lower()
            for line in domain_endings_response.text.splitlines()
            if line.strip() and not line.startswith("#")
        }
        with open(cache_file_path, "w") as cache_file:
            _ = cache_file.write("\n".join(sorted(domain_endings)))
        return domain_endings

    msg = (
        f"Failed to fetch domain endings. "
        f"HTTP Status Code: {domain_endings_response.status_code}"
    )
    raise Exception(msg)


# =============================================================================
# VERSION FUNCTIONS - Mastodon Version Retrieval
# =============================================================================


def read_main_version_info(url: str) -> dict[str, str] | None:
    """Parse Mastodon version.rb file to extract version information."""
    version_info: dict[str, str] = {}
    try:
        response = get_httpx(url, http_client)
        _ = response.raise_for_status()
        lines = response.text.splitlines()

        for i, line in enumerate(lines):
            match = re.search(r"def (\w+)", line)
            if match:
                key = match.group(1)
                if key in ["major", "minor", "patch", "default_prerelease"]:
                    value = lines[i + 1].strip()
                    if value.isnumeric() or re.match(r"'[^']+'", value):
                        version_info[key] = value.replace("'", "")
    except httpx.HTTPError as exception:
        vmc_output(f"Failed to retrieve Mastodon main version: {exception}", "red")
        return None

    return version_info


def get_highest_mastodon_version() -> str | None:
    """Get the highest stable Mastodon release version from GitHub."""
    highest_version: str | None = None
    try:
        release_url = "https://api.github.com/repos/mastodon/mastodon/releases"
        response = get_httpx(release_url, http_client)
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
    except httpx.HTTPError as exception:
        vmc_output(f"Failed to retrieve Mastodon release version: {exception}", "red")
        return None

    return highest_version


def get_backport_mastodon_versions():
    """Get the latest version for each backport branch from GitHub."""
    url = "https://api.github.com/repos/mastodon/mastodon/releases"

    backport_versions = dict.fromkeys(backport_branches, "")

    response = get_httpx(url, http_client)
    _ = response.raise_for_status()
    releases = response.json()

    for release in releases:
        release_version = release["tag_name"].lstrip("v")

        for branch in backport_branches:
            if release_version.startswith(branch):
                if backport_versions[branch] is None or (
                    release_version
                    and version.parse(release_version)
                    > version.parse(backport_versions[branch] or "0.0.0")
                ):
                    backport_versions[branch] = release_version

    for branch in backport_versions:
        if backport_versions[branch] is None:
            backport_versions[branch] = f"{branch}.0"

    return list(backport_versions.values())


def get_main_version_release():
    """Get the current main branch version string."""
    url = "https://raw.githubusercontent.com/mastodon/mastodon/refs/heads/main/lib/mastodon/version.rb"
    version_info = read_main_version_info(url)
    if not version_info:
        return "0.0.0-alpha.0"

    major = version_info.get("major", "0")
    minor = version_info.get("minor", "0")
    patch = version_info.get("patch", "0")
    pre = version_info.get("default_prerelease", "alpha.0")

    obtained_main_version = f"{major}.{minor}.{patch}-{pre}"
    return obtained_main_version


def get_main_version_branch():
    """Get the current main branch number (e.g., '4.3')."""
    url = "https://raw.githubusercontent.com/mastodon/mastodon/refs/heads/main/lib/mastodon/version.rb"
    version_info = read_main_version_info(url)
    if not version_info:
        return "0.0"

    major = version_info.get("major", "0")
    minor = version_info.get("minor", "0")

    obtained_main_branch = f"{major}.{minor}"
    return obtained_main_branch


def get_nightly_version_ranges() -> list[tuple[str, datetime, datetime | None]]:
    """Get nightly version ranges from the database."""
    with conn.cursor() as cur:
        _ = cur.execute(
            """
            SELECT version, start_date, end_date
            FROM nightly_versions
            ORDER BY start_date DESC
        """,
        )
        nightly_version_ranges = [(row[0], row[1], row[2]) for row in cur.fetchall()]
        nightly_version_ranges = [
            (
                version,
                (
                    start_date
                    if isinstance(start_date, datetime)
                    else datetime.fromisoformat(str(start_date))
                ),
                (
                    end_date
                    if isinstance(end_date, datetime)
                    else datetime.fromisoformat(str(end_date))
                    if end_date
                    else None
                ),
            )
            for version, start_date, end_date in nightly_version_ranges
        ]
    return nightly_version_ranges


# =============================================================================
# VERSION FUNCTIONS - Version String Cleaning
# =============================================================================


def clean_version(
    software_version_full: str,
    nightly_version_ranges: list[tuple[str, datetime, datetime | None]],
) -> str:
    """Apply all version cleaning transformations."""
    software_version = clean_version_suffix(software_version_full)
    software_version = clean_version_strings(software_version)
    software_version = clean_version_date(software_version)
    software_version = clean_version_suffix_more(software_version)
    software_version = clean_version_development(software_version)
    software_version = clean_version_wrongpatch(software_version)
    software_version = clean_version_doubledash(software_version)
    software_version = clean_version_nightly(software_version, nightly_version_ranges)
    software_version = clean_version_main_missing_prerelease(software_version)
    software_version = clean_version_release_with_prerelease(software_version)
    software_version = clean_version_strip_incorrect_prerelease(software_version)
    return software_version


def clean_version_suffix(software_version_full: str) -> str:
    """Remove unwanted or invalid suffixes from version string."""
    software_version = (
        software_version_full.split("+")[0]
        .split("~")[0]
        .split("_")[0]
        .split(" ")[0]
        .split("/")[0]
        .split("@")[0]
        .split("&")[0]
        .split("patch")[0]
    )
    return software_version


def clean_version_suffix_more(software_version: str) -> str:
    """Remove additional suffixes unless they are valid prerelease identifiers."""
    if (
        "alpha" not in software_version
        and "beta" not in software_version
        and "rc" not in software_version
        and "nightly" not in software_version
    ):
        software_version = re.split(r"-[a-zA-Z]", software_version)[0]
    if "nightly" not in software_version:
        software_version = re.split(r"-\d", software_version)[0]
    return software_version


def clean_version_strings(software_version: str) -> str:
    """Remove unwanted strings and fix typos in version strings."""
    # Remove unwanted suffixes (including everything after -pre)
    software_version = re.sub(r"-pre.*", "", software_version)

    # Remove other unwanted strings
    unwanted_strings = ["-theconnector", "-theatlsocial"]
    for unwanted_string in unwanted_strings:
        software_version = software_version.replace(unwanted_string, "")

    # Fix known typos
    if "mastau" in software_version:
        software_version = software_version.replace("mastau", "alpha")

    return software_version


def clean_version_date(software_version: str) -> str:
    """Convert date-based suffixes to nightly format."""
    match = re.search(r"-(\d{2})(\d{2})(\d{2})$", software_version)
    if match:
        yy, mm, dd = match.groups()
        formatted_date = f"-nightly.20{yy}-{mm}-{dd}"
        return re.sub(r"-(\d{6})$", formatted_date, software_version)
    return software_version


def clean_version_development(software_version: str) -> str:
    """Normalize development version formats (rc, beta)."""
    patterns = {r"rc(\d+)": r"-rc.\1", r"beta(\d+)": r"-beta.\1"}
    for pattern, replacement in patterns.items():
        software_version = re.sub(pattern, replacement, software_version)
    return software_version


def clean_version_doubledash(software_version: str) -> str:
    """Fix double dashes and trailing dashes in version strings."""
    if "--" in software_version:
        software_version = software_version.replace("--", "-")
    software_version = software_version.removesuffix("-")
    return software_version


def clean_version_wrongpatch(software_version: str) -> str:
    """Correct patch versions that exceed the latest release."""
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)(-.+)?$", software_version)

    if match:
        if version_latest_release:
            a, b, c = (
                int(version_latest_release.split(".")[0]),
                int(version_latest_release.split(".")[1]),
                int(version_latest_release.split(".")[2]),
            )
        else:
            a, b, c = (0, 0, 0)
        m = int(version_main_branch.split(".")[1])
        x, y, z = int(match.group(1)), int(match.group(2)), int(match.group(3))
        additional_data = match.group(4)

        if x == a:
            if y == b:
                if z > c:
                    z = 0
                    return f"{x}.{y}.{z}{additional_data or ''}"
                return software_version
            if y == m:
                if z != 0:
                    z = 0
                    return f"{x}.{y}.{z}{additional_data or ''}"
                return software_version
            return software_version
        return software_version
    return software_version


def clean_version_nightly(
    software_version: str,
    nightly_version_ranges: list[tuple[str, datetime, datetime | None]],
) -> str:
    """Map nightly versions to their corresponding release versions."""
    software_version = re.sub(r"-nightly-\d{8}", "", software_version)

    match = re.match(
        r"4\.[3456]\.0-nightly\.(\d{4}-\d{2}-\d{2})(-security)?",
        software_version,
    )
    if match:
        nightly_date_str, is_security = match.groups()
        nightly_date = datetime.strptime(nightly_date_str, "%Y-%m-%d")

        if is_security:
            nightly_date += timedelta(days=1)

        for version, start_date, end_date in nightly_version_ranges:
            if (
                start_date is not None
                and end_date is not None
                and start_date <= nightly_date <= end_date
            ):
                return version

    return software_version


def clean_version_main_missing_prerelease(software_version: str) -> str:
    """Add missing prerelease suffix to main branch versions."""
    if software_version.startswith(version_main_branch) and "-" not in software_version:
        software_version = f"{software_version}-alpha.1"
    return software_version


def clean_version_release_with_prerelease(software_version: str) -> str:
    """Strip prerelease suffix from stable release versions."""
    if (
        version_latest_release
        and software_version.startswith(version_latest_release)
        and "-" in software_version
        and not version_latest_release.endswith(".0")
    ):
        software_version = software_version.split("-")[0]
    return software_version


def clean_version_strip_incorrect_prerelease(software_version: str) -> str:
    """Remove prerelease suffix from non-zero patch versions."""
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)(-.+)?$", software_version)
    if match:
        x, y, z, prerelease = match.groups()
        if int(z) != 0 and prerelease:
            return f"{x}.{y}.{z}"
    return software_version


# =============================================================================
# DATABASE FUNCTIONS - Patch Versions
# =============================================================================


def update_patch_versions():
    """Update the patch versions in the database."""
    with conn.cursor() as cur:
        n_level = -1
        cur.execute(
            """
            INSERT INTO patch_versions (software_version, main, n_level, branch)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (n_level) DO UPDATE
            SET software_version = EXCLUDED.software_version,
                branch = EXCLUDED.branch
        """,
            (version_main_release, True, n_level, version_main_branch),
        )
        conn.commit()

    with conn.cursor() as cur:
        n_level = 0
        for n_level, (version, branch) in enumerate(
            zip(version_backport_releases, backport_branches),
        ):
            cur.execute(
                """
                INSERT INTO patch_versions (software_version, release, n_level, branch)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (n_level) DO UPDATE
                SET software_version = EXCLUDED.software_version,
                    branch = EXCLUDED.branch
            """,
                (version, True, n_level, branch),
            )
            n_level += 1
        conn.commit()


def delete_old_patch_versions():
    """Delete rows from patch_versions not in current patched versions list."""
    with conn.cursor() as cur:
        cur.execute(
            """
            DELETE FROM patch_versions
            WHERE software_version != ALL(%s::text[])
        """,
            (all_patched_versions,),
        )
        conn.commit()


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
            vmc_output(
                f"{domain}: Failed to log error {exception}",
                "red",
                use_tqdm=True,
            )
            conn.rollback()


def increment_domain_error(
    domain: str,
    error_reason: str,
    preserve_ignore: bool = False,
    preserve_nxdomain: bool = False,
) -> None:
    """Increment error count for a domain and record the error reason.

    Only increments error count if the previous error reason started with
    DNS, SSL, TCP, TYPE, FILE, API, JSON, or HTTP 2xx/3xx/4xx/5xx, AND the domain's nodeinfo
    is NOT set to 'mastodon'. For other error types, the count is set to null
    while still recording the error reason. Counter resets to 1 when switching
    between error types.

    DNS errors: After ERROR_THRESHOLD consecutive errors, mark as NXDOMAIN.
    SSL errors: After ERROR_THRESHOLD consecutive errors, mark as ignored.
    TCP errors: After ERROR_THRESHOLD consecutive errors, mark as ignored.
    TYPE errors: After ERROR_THRESHOLD consecutive errors, mark as ignored.
    FILE errors: After ERROR_THRESHOLD consecutive errors, mark as ignored.
    API errors: After ERROR_THRESHOLD consecutive errors, mark as ignored.
    JSON errors: After ERROR_THRESHOLD consecutive errors, mark as ignored.
    HTTP 2xx errors: After ERROR_THRESHOLD consecutive errors, mark as ignored.
    HTTP 3xx errors: After ERROR_THRESHOLD consecutive errors, mark as ignored.
    HTTP 4xx errors: After ERROR_THRESHOLD consecutive errors, mark as ignored.
    HTTP 5xx errors: After ERROR_THRESHOLD consecutive errors, mark as ignored.

    Args:
        domain: The domain to update
        error_reason: The error reason string
        preserve_ignore: If True, preserve the ignore flag when recording errors
        preserve_nxdomain: If True, preserve the nxdomain flag when recording errors
    """
    domain = domain.lower()
    ERROR_THRESHOLD = int(os.getenv("VMCRAWL_ERROR_BUFFER", "8"))
    TRACKED_ERROR_TYPES = ("DNS", "SSL", "TCP", "TYPE", "FILE", "API", "JSON")

    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            # Use SKIP LOCKED to avoid blocking when another crawler has the row locked
            # If locked, we skip and let the other crawler handle it
            cursor.execute(
                "SELECT errors, reason, nodeinfo, ignore, nxdomain FROM raw_domains WHERE domain = %s FOR UPDATE SKIP LOCKED",
                (domain,),
            )
            result = cursor.fetchone()

            # If no result, the row is either locked by another crawler or doesn't exist
            # We'll still try the INSERT...ON CONFLICT which will handle both cases safely
            current_errors = result[0] if result and result[0] is not None else 0
            previous_reason = result[1] if result and result[1] is not None else ""
            nodeinfo = result[2] if result and result[2] is not None else None
            current_ignore = result[3] if result and result[3] is True else False
            current_nxdomain = result[4] if result and result[4] is True else False

            # Determine flag values: preserve if requested, otherwise None
            # When preserving, use True if currently set, otherwise None (to clear it)
            ignore_value = True if (preserve_ignore and current_ignore) else None
            nxdomain_value = True if (preserve_nxdomain and current_nxdomain) else None

            # Skip error counting if:
            # - nodeinfo is set to 'mastodon', OR
            # - we're preserving ignore flag (retrying ignored domains), OR
            # - we're preserving nxdomain flag (retrying NXDOMAIN domains)
            if nodeinfo == "mastodon" or preserve_ignore or preserve_nxdomain:
                # When preserving flags, don't record any error information
                # For mastodon: record reason but clear counter
                # For preserve_ignore/preserve_nxdomain: clear both counter and reason
                if preserve_ignore or preserve_nxdomain:
                    errors_value = None
                    reason_value = None
                else:
                    # mastodon case: record reason but clear counter
                    errors_value = None
                    reason_value = error_reason

                _ = cursor.execute(
                    """
                        INSERT INTO raw_domains
                        (domain, failed, ignore, errors, reason, nxdomain, norobots, noapi, alias)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT(domain) DO UPDATE SET
                        failed = excluded.failed,
                        ignore = excluded.ignore,
                        errors = excluded.errors,
                        reason = excluded.reason,
                        nxdomain = excluded.nxdomain,
                        norobots = excluded.norobots,
                        noapi = excluded.noapi,
                        alias = excluded.alias
                    """,
                    (
                        domain,
                        None,
                        ignore_value,
                        errors_value,
                        reason_value,
                        nxdomain_value,
                        None,
                        None,
                        None,
                    ),
                )
                conn.commit()

                return

            # Get error type prefix (DNS, SSL, TCP, TYPE, HTTP 2xx/3xx/4xx/5xx, or None)
            # Check for HTTP status code errors
            def is_http_2xx(reason: str) -> bool:
                """Check if error reason starts with a 2xx HTTP status code."""
                return len(reason) >= 3 and reason[0] == "2" and reason[1:3].isdigit()

            def is_http_3xx(reason: str) -> bool:
                """Check if error reason starts with a 3xx HTTP status code."""
                return len(reason) >= 3 and reason[0] == "3" and reason[1:3].isdigit()

            def is_http_4xx(reason: str) -> bool:
                """Check if error reason starts with a 4xx HTTP status code."""
                return len(reason) >= 3 and reason[0] == "4" and reason[1:3].isdigit()

            def is_http_5xx(reason: str) -> bool:
                """Check if error reason starts with a 5xx HTTP status code."""
                return len(reason) >= 3 and reason[0] == "5" and reason[1:3].isdigit()

            error_type = None
            if is_http_2xx(error_reason):
                error_type = "HTTP2XX"
            elif is_http_3xx(error_reason):
                error_type = "HTTP3XX"
            elif is_http_4xx(error_reason):
                error_type = "HTTP4XX"
            elif is_http_5xx(error_reason):
                error_type = "HTTP5XX"
            else:
                error_type = next(
                    (t for t in TRACKED_ERROR_TYPES if error_reason.startswith(t)),
                    None,
                )

            previous_type = None
            if is_http_2xx(previous_reason):
                previous_type = "HTTP2XX"
            elif is_http_3xx(previous_reason):
                previous_type = "HTTP3XX"
            elif is_http_4xx(previous_reason):
                previous_type = "HTTP4XX"
            elif is_http_5xx(previous_reason):
                previous_type = "HTTP5XX"
            else:
                previous_type = next(
                    (t for t in TRACKED_ERROR_TYPES if previous_reason.startswith(t)),
                    None,
                )

            # Determine new error count
            if error_type and error_type == previous_type:
                # Same error type - increment
                new_errors = current_errors + 1

                # Check if threshold reached
                if new_errors >= ERROR_THRESHOLD:
                    if error_type == "DNS":
                        status = "nxdomain"
                    else:
                        # SSL, TCP, TYPE, FILE, HTTP2XX, HTTP3XX, HTTP4XX, or HTTP5XX all mark as ignore
                        status = "ignore"
                    mark_domain_status(domain, status)
                    delete_domain_if_known(domain)
                    return
            elif error_type:
                # Different tracked error type or first occurrence - reset to 1
                new_errors = 1
            else:
                # Non-tracked error types - set count to null
                new_errors = None

            _ = cursor.execute(
                """
                    INSERT INTO raw_domains
                    (domain, failed, ignore, errors, reason, nxdomain, norobots, noapi, alias)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT(domain) DO UPDATE SET
                    failed = excluded.failed,
                    ignore = excluded.ignore,
                    errors = excluded.errors,
                    reason = excluded.reason,
                    nxdomain = excluded.nxdomain,
                    norobots = excluded.norobots,
                    noapi = excluded.noapi,
                    alias = excluded.alias
                """,
                (
                    domain,
                    None,
                    ignore_value,
                    new_errors,
                    error_reason,
                    nxdomain_value,
                    None,
                    None,
                    None,
                ),
            )
            conn.commit()
        except Exception as exception:
            vmc_output(
                f"{domain}: Failed to increment domain error {exception}",
                "red",
                use_tqdm=True,
            )
            conn.rollback()


def clear_domain_error(domain: str) -> None:
    """Clear all error flags for a domain."""
    domain = domain.lower()
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            _ = cursor.execute(
                """
                    INSERT INTO raw_domains
                    (domain, failed, ignore, errors, reason, nxdomain, norobots, noapi, alias)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT(domain) DO UPDATE SET
                    failed = excluded.failed,
                    ignore = excluded.ignore,
                    errors = excluded.errors,
                    reason = excluded.reason,
                    nxdomain = excluded.nxdomain,
                    norobots = excluded.norobots,
                    noapi = excluded.noapi,
                    alias = excluded.alias
                """,
                (domain, None, None, None, None, None, None, None, None),
            )
            conn.commit()
        except Exception as exception:
            vmc_output(
                f"{domain}: Failed to clear domain errors {exception}",
                "red",
                use_tqdm=True,
            )
            conn.rollback()


# =============================================================================
# DATABASE FUNCTIONS - Domain Status Marking
# =============================================================================


def mark_domain_status(domain: str, status_type: str) -> None:
    """Mark a domain with a specific status flag.

    Args:
        domain: The domain to mark
        status_type: One of 'ignore', 'failed', 'nxdomain', 'norobots', 'noapi', 'alias'

    """
    domain = domain.lower()
    status_map = {
        "ignore": (None, True, None, None, None, None, None, None, None, "ignored"),
        "failed": (True, None, None, None, None, None, None, None, None, "failed"),
        "nxdomain": (None, None, None, None, True, None, None, None, None, "NXDOMAIN"),
        "norobots": (None, None, None, None, None, True, None, None, None, "NoRobots"),
        "noapi": (None, None, None, None, None, None, True, None, None, "NoAPI"),
        "alias": (None, None, None, None, None, None, None, True, None, "alias"),
    }

    if status_type not in status_map:
        vmc_output(f"Invalid status type: {status_type}", "red")
        return

    (
        failed,
        ignore,
        errors,
        reason,
        nxdomain,
        norobots,
        noapi,
        alias,
        nodeinfo,
        label,
    ) = status_map[status_type]

    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            _ = cursor.execute(
                """
                    INSERT INTO raw_domains
                    (domain, failed, ignore, errors, reason, nxdomain,
                     norobots, noapi, alias, nodeinfo)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT(domain) DO UPDATE SET
                    failed = excluded.failed,
                    ignore = excluded.ignore,
                    errors = excluded.errors,
                    reason = excluded.reason,
                    nxdomain = excluded.nxdomain,
                    norobots = excluded.norobots,
                    noapi = excluded.noapi,
                    alias = excluded.alias,
                    nodeinfo = excluded.nodeinfo
                """,
                (
                    domain,
                    failed,
                    ignore,
                    errors,
                    reason,
                    nxdomain,
                    norobots,
                    noapi,
                    alias,
                    nodeinfo,
                ),
            )
            conn.commit()
        except Exception as exception:
            vmc_output(f"Failed to mark domain {label}: {exception}", "red")
            conn.rollback()


# Convenience wrapper functions for backwards compatibility
def mark_ignore_domain(domain: str) -> None:
    """Mark a domain as ignored (non-Mastodon platform)."""
    mark_domain_status(domain, "ignore")


def mark_failed_domain(domain: str) -> None:
    """Mark a domain as failed (authentication required)."""
    mark_domain_status(domain, "failed")


def mark_nxdomain_domain(domain: str) -> None:
    """Mark a domain as NXDOMAIN (gone/not found)."""
    mark_domain_status(domain, "nxdomain")


def mark_norobots_domain(domain: str) -> None:
    """Mark a domain as norobots (crawling prohibited)."""
    mark_domain_status(domain, "norobots")


def mark_noapi_domain(domain: str) -> None:
    """Mark a domain as noapi (instance API requires authentication)."""
    mark_domain_status(domain, "noapi")


def mark_alias_domain(domain: str) -> None:
    """Mark a domain as an alias (redirect to another instance)."""
    mark_domain_status(domain, "alias")


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
            vmc_output(
                f"{domain}: Failed to delete known domain {exception}",
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
            vmc_output(
                f"{domain}: Failed to delete known domain {exception}",
                "red",
                use_tqdm=True,
            )
            conn.rollback()


def save_nodeinfo_software(domain: str, software_data: dict[str, Any]) -> None:
    """Save software name from nodeinfo to raw_domains.nodeinfo for the domain.

    When nodeinfo is set to anything other than 'mastodon', also clears
    errors and reason since this is not an error condition - it's just a
    different platform.

    Args:
        domain: The domain being processed
        software_data: The 'software' dict from nodeinfo_20_result (contains
            'name')

    """
    domain = domain.lower()
    software_name = software_data.get("name", "unknown").lower().replace(" ", "-")

    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            if software_name != "mastodon":
                # For non-Mastodon platforms, clear errors and reason
                _ = cursor.execute(
                    """
                        INSERT INTO raw_domains
                        (domain, nodeinfo, errors, reason)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT(domain) DO UPDATE SET
                        nodeinfo = excluded.nodeinfo,
                        errors = excluded.errors,
                        reason = excluded.reason
                        """,
                    (domain, software_name, None, None),
                )
            else:
                # For Mastodon, just update nodeinfo
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
            vmc_output(
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
        vmc_output("Attempted to insert empty domain, skipping", "red", use_tqdm=True)
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
            vmc_output(f"{actual_domain}: {exception}", "red", use_tqdm=True)
            conn.rollback()


def cleanup_old_domains():
    """Delete known domains older than 1 day.

    Uses an advisory lock to ensure only one crawler instance performs
    cleanup at a time, preventing race conditions where multiple instances
    might delete domains that other instances just updated.
    """
    # Use a fixed advisory lock ID for cleanup operations
    CLEANUP_LOCK_ID = 999999999

    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            # Try to acquire cleanup lock (non-blocking)
            cursor.execute("SELECT pg_try_advisory_lock(%s)", (CLEANUP_LOCK_ID,))
            result = cursor.fetchone()
            lock_acquired = result[0] if result else False

            if not lock_acquired:
                # Another instance is already running cleanup, skip
                return

            try:
                cursor.execute(
                    """
                        DELETE FROM mastodon_domains
                        WHERE timestamp <=
                            (CURRENT_TIMESTAMP - INTERVAL '1 day') AT TIME ZONE 'UTC'
                        RETURNING domain
                        """,
                )
                deleted_domains = [row[0] for row in cursor.fetchall()]
                if deleted_domains:
                    for d in deleted_domains:
                        vmc_output(
                            f"{d}: Removed from active instance list",
                            "pink",
                            use_tqdm=True,
                        )
                conn.commit()
            finally:
                # Always release the cleanup lock
                cursor.execute("SELECT pg_advisory_unlock(%s)", (CLEANUP_LOCK_ID,))
        except Exception as exception:
            vmc_output(f"Failed to clean up old domains: {exception}", "red")
            conn.rollback()


# =============================================================================
# DATABASE FUNCTIONS - Domain List Retrieval
# =============================================================================


def get_junk_keywords():
    """Get list of junk keywords to filter domains."""
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            cursor.execute("SELECT keywords FROM junk_words")
            # Use set for O(1) lookup instead of O(n) list iteration
            return {row[0] for row in cursor}
        except Exception as exception:
            vmc_output(f"Failed to obtain junk keywords: {exception}", "red")
            conn.rollback()
    return set()


def get_dni_domains():
    """Get list of DNI (Do Not Interact) domains to filter domains."""
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            cursor.execute("SELECT domain FROM dni")
            # Use set for O(1) lookup instead of O(n) list iteration
            return {row[0] for row in cursor}
        except Exception as exception:
            vmc_output(f"Failed to obtain DNI domain list: {exception}", "red")
            conn.rollback()
    return set()


def get_bad_tld():
    """Get list of prohibited TLDs."""
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            cursor.execute("SELECT tld FROM bad_tld")
            # Use set for O(1) lookup
            return {row[0] for row in cursor}
        except Exception as exception:
            vmc_output(f"Failed to obtain bad TLDs: {exception}", "red")
            conn.rollback()
    return set()


def get_domains_by_status(status_column):
    """Get list of domains filtered by status column.

    Args:
        status_column: One of 'failed', 'ignore', 'baddata', 'nxdomain', 'norobots', 'noapi', 'alias'

    Returns:
        Set of domain strings
    """
    valid_columns = [
        "failed",
        "ignore",
        "baddata",
        "nxdomain",
        "norobots",
        "noapi",
        "alias",
    ]
    if status_column not in valid_columns:
        vmc_output(f"Invalid status column: {status_column}", "red")
        return set()

    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            query = f"SELECT domain FROM raw_domains WHERE {status_column} = TRUE"
            _ = cursor.execute(query)  # pyright: ignore[reportCallIssue,reportArgumentType]
            # Use set for O(1) lookup, stream results
            return {row[0].strip() for row in cursor if row[0] and row[0].strip()}
        except Exception as exception:
            vmc_output(
                f"Failed to obtain {status_column} domains: {exception}",
                "red",
            )
            conn.rollback()
    return set()


# Convenience wrapper functions for backwards compatibility
def get_failed_domains():
    """Get list of domains marked as failed."""
    return get_domains_by_status("failed")


def get_ignored_domains():
    """Get list of domains marked as ignored."""
    return get_domains_by_status("ignore")


def get_not_masto_domains():
    """Get list of domains where nodeinfo is not 'mastodon'."""
    with db_pool.connection() as conn, conn.cursor() as cursor:
        try:
            query = (
                "SELECT domain FROM raw_domains "
                "WHERE nodeinfo IS NOT NULL AND nodeinfo != 'mastodon'"
            )
            _ = cursor.execute(query)
            # Use set for O(1) lookup, stream results
            return {row[0].strip() for row in cursor if row[0] and row[0].strip()}
        except Exception as exception:
            vmc_output(f"Failed to obtain non-mastodon domains: {exception}", "red")
            conn.rollback()
    return set()


def get_baddata_domains():
    """Get list of domains marked as having bad data."""
    return get_domains_by_status("baddata")


def get_nxdomain_domains():
    """Get list of domains marked as NXDOMAIN."""
    return get_domains_by_status("nxdomain")


def get_norobots_domains():
    """Get list of domains that prohibit crawling."""
    return get_domains_by_status("norobots")


def get_noapi_domains():
    """Get list of domains whose instance API requires authentication."""
    return get_domains_by_status("noapi")


def get_alias_domains():
    """Get list of domains marked as aliases."""
    return get_domains_by_status("alias")


# =============================================================================
# ERROR HANDLING FUNCTIONS
# =============================================================================


def handle_incorrect_file_type(
    domain, target, content_type, preserve_ignore=False, preserve_nxdomain=False
):
    """Handle responses with incorrect content type."""
    if content_type == "" or content_type is None:
        content_type = "missing Content-Type"
    clean_content_type = re.sub(r";.*$", "", content_type).strip()
    error_message = f"{target} is {clean_content_type}"
    vmc_output(f"{domain}: {error_message}", "yellow", use_tqdm=True)
    log_error(domain, error_message)
    increment_domain_error(domain, f"TYPE+{target}", preserve_ignore, preserve_nxdomain)


def handle_http_status_code(
    domain, target, response, preserve_ignore=False, preserve_nxdomain=False
):
    """Handle non-fatal HTTP status codes."""
    code = response.status_code
    error_message = f"HTTP {code} on {target}"
    vmc_output(f"{domain}: {error_message}", "yellow", use_tqdm=True)
    log_error(domain, error_message)
    increment_domain_error(
        domain, f"{code}+{target}", preserve_ignore, preserve_nxdomain
    )


def handle_http_failed(domain, target, response):
    """Handle HTTP 401/403 on auth endpoints and 410/418 generally."""
    code = response.status_code
    error_message = f"HTTP {code} on {target}"
    vmc_output(f"{domain}: {error_message}", "orange", use_tqdm=True)
    mark_failed_domain(domain)
    delete_domain_if_known(domain)


def handle_tcp_exception(
    domain, target, exception, preserve_ignore=False, preserve_nxdomain=False
):
    """Handle TCP/connection exceptions with appropriate categorization."""
    error_message = str(exception)
    error_message_lower = error_message.casefold()

    # Handle response size violations
    if isinstance(exception, ValueError) and "too large" in error_message_lower:
        error_reason = "FILE"
        vmc_output(f"{domain}: Response too large", "yellow", use_tqdm=True)
        log_error(domain, "Response exceeds size limit")
        increment_domain_error(
            domain, f"{error_reason}+{target}", preserve_ignore, preserve_nxdomain
        )
        return

    # Handle bad file descriptor (usually from cancellation/cleanup issues)
    if "bad file descriptor" in error_message_lower:
        error_reason = "FILE"
        vmc_output(f"{domain}: Connection closed unexpectedly", "yellow", use_tqdm=True)
        log_error(domain, "Bad file descriptor")
        increment_domain_error(
            domain, f"{error_reason}+{target}", preserve_ignore, preserve_nxdomain
        )
        return

    # Check for SSL/TLS errors (includes certificate validation failures)
    ssl_indicators = [
        "_ssl.c",
        "ssl",
        "tls",
        "certificate",
        "cert",
        "sslcertverficationerror",
        "handshake",
        "cipher",
    ]
    if any(indicator in error_message_lower for indicator in ssl_indicators):
        error_reason = "SSL"
        cleaned_message = (
            re.sub(r"\s*(\[[^\]]*\]|\([^)]*\))", "", error_message)
            .replace(":", "")
            .replace(",", "")
            .split(" for ", 1)[0]
            .lstrip()
            .rstrip(" .")
        )
        # Fallback to original if cleaning resulted in empty string
        if not cleaned_message:
            cleaned_message = "SSL connection error"
        vmc_output(f"{domain}: {cleaned_message}", "yellow", use_tqdm=True)
        log_error(domain, cleaned_message)
        increment_domain_error(
            domain, f"{error_reason}+{target}", preserve_ignore, preserve_nxdomain
        )
    # Check for DNS resolution errors
    elif any(
        msg in error_message_lower
        for msg in [
            "no address associated with hostname",
            "temporary failure in name resolution",
            "address family not supported",
            "nodename nor servname provided",
            "name or service not known",
        ]
    ):
        error_reason = "DNS"
        cleaned_message = (
            re.sub(r"\s*(\[[^\]]*\]|\([^)]*\))", "", error_message)
            .replace(":", "")
            .replace(",", "")
            .split(" for ", 1)[0]
            .lstrip()
            .rstrip(" .")
        )
        # Fallback to original if cleaning resulted in empty string
        if not cleaned_message:
            cleaned_message = "DNS resolution failed"
        vmc_output(f"{domain}: {cleaned_message}", "yellow", use_tqdm=True)
        log_error(domain, cleaned_message)
        increment_domain_error(
            domain, f"{error_reason}+{target}", preserve_ignore, preserve_nxdomain
        )
    else:
        # All other errors (TCP, HTTP, etc.) categorized as TCP
        error_reason = "TCP"
        cleaned_message = (
            re.sub(r"\s*(\[[^\]]*\]|\([^)]*\))", "", error_message)
            .replace(":", "")
            .replace(",", "")
            .split(" for ", 1)[0]
            .lstrip()
            .rstrip(" .")
        )
        # Fallback to original if cleaning resulted in empty string
        if not cleaned_message:
            cleaned_message = str(exception)[:100] or "TCP error"
        vmc_output(f"{domain}: {cleaned_message}", "yellow", use_tqdm=True)
        log_error(domain, cleaned_message)
        increment_domain_error(
            domain, f"{error_reason}+{target}", preserve_ignore, preserve_nxdomain
        )


def handle_json_exception(
    domain, target, exception, preserve_ignore=False, preserve_nxdomain=False
):
    """Handle JSON parsing exceptions."""
    error_message = str(exception)
    error_reason = f"JSON+{target}"
    vmc_output(f"{domain}: {target} {error_message}", "yellow", use_tqdm=True)
    log_error(domain, error_message)
    increment_domain_error(
        domain, f"{error_reason}", preserve_ignore, preserve_nxdomain
    )


# =============================================================================
# DOMAIN PROCESSING - Validation and Filtering
# =============================================================================


def should_skip_domain(
    domain,
    not_masto_domains,
    baddata_domains,
    failed_domains,
    ignored_domains,
    nxdomain_domains,
    norobots_domains,
    noapi_domains,
    alias_domains,
    user_choice,
):
    """Check if a domain should be skipped based on its status."""
    if user_choice != "10" and domain in not_masto_domains:
        vmc_output(f"{domain}: Other Platform", "cyan", use_tqdm=True)
        delete_domain_if_known(domain)
        return True
    if user_choice != "11" and domain in ignored_domains:
        vmc_output(f"{domain}: Ignored Domain", "cyan", use_tqdm=True)
        delete_domain_if_known(domain)
        return True
    if user_choice != "12" and domain in failed_domains:
        vmc_output(f"{domain}: Failed Domain", "cyan", use_tqdm=True)
        delete_domain_if_known(domain)
        return True
    if user_choice != "13" and domain in nxdomain_domains:
        vmc_output(f"{domain}: NXDOMAIN", "cyan", use_tqdm=True)
        delete_domain_if_known(domain)
        return True
    if user_choice != "14" and domain in norobots_domains:
        vmc_output(f"{domain}: Crawling Prohibited", "cyan", use_tqdm=True)
        delete_domain_if_known(domain)
        return True
    if user_choice != "15" and domain in noapi_domains:
        vmc_output(f"{domain}: API Authentication Required", "cyan", use_tqdm=True)
        delete_domain_if_known(domain)
        return True
    if user_choice != "16" and domain in alias_domains:
        vmc_output(f"{domain}: Alias Domain", "cyan", use_tqdm=True)
        delete_domain_if_known(domain)
        return True
    if domain in baddata_domains:
        vmc_output(f"{domain}: Bad Domain", "cyan", use_tqdm=True)
        delete_domain_if_known(domain)
        return True
    return False


def is_junk_or_bad_tld(domain, junk_domains, dni_domains, bad_tlds, domain_endings):
    """Check if a domain is junk or has a prohibited TLD."""
    if any(junk in domain for junk in junk_domains):
        vmc_output(f"{domain}: Purging known junk domain", "cyan", use_tqdm=True)
        delete_domain_if_known(domain)
        delete_domain_from_raw(domain)
        return True
    if any(dni in domain for dni in dni_domains):
        vmc_output(f"{domain}: Purging known dni domain", "cyan", use_tqdm=True)
        delete_domain_if_known(domain)
        delete_domain_from_raw(domain)
        return True
    if any(domain.endswith(f".{tld}") for tld in bad_tlds):
        vmc_output(f"{domain}: Purging prohibited TLD", "cyan", use_tqdm=True)
        mark_nxdomain_domain(domain)
        delete_domain_if_known(domain)
        delete_domain_from_raw(domain)
        return True
    if not any(
        domain.endswith(f".{domain_ending}") for domain_ending in domain_endings
    ):
        vmc_output(f"{domain}: Purging unknown TLD", "cyan", use_tqdm=True)
        mark_nxdomain_domain(domain)
        delete_domain_if_known(domain)
        delete_domain_from_raw(domain)
        return True
    return False


# =============================================================================
# DOMAIN PROCESSING - Protocol Checks
# =============================================================================


def check_robots_txt(
    domain, http_client, preserve_ignore=False, preserve_nxdomain=False
):
    """Check robots.txt to ensure crawling is allowed."""
    target = "robots_txt"
    url = f"https://{domain}/robots.txt"
    try:
        response = get_httpx(url, http_client)
        if response.status_code == 200:
            content_type = response.headers.get("Content-Type", "")
            if (
                content_type in mimetypes.types_map.values()
                and not content_type.startswith("text/")
            ):
                handle_incorrect_file_type(
                    domain, target, content_type, preserve_ignore
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
                        vmc_output(
                            f"{domain}: Crawling Prohibited",
                            "orange",
                            use_tqdm=True,
                        )
                        mark_norobots_domain(domain)
                        delete_domain_if_known(domain)
                        return False
        elif response.status_code in http_codes_to_hardfail:
            handle_http_failed(domain, target, response)
            return False
        else:
            handle_http_status_code(
                domain, target, response, preserve_ignore, preserve_nxdomain
            )
            return False
    except httpx.RequestError as exception:
        handle_tcp_exception(
            domain, target, exception, preserve_ignore, preserve_nxdomain
        )
        return False
    return True


def check_host_meta(domain, http_client):
    """Check host-meta endpoint to discover backend domain.

    Returns the backend domain if found, or None if not available.
    """
    url = f"https://{domain}/.well-known/host-meta"
    try:
        response = get_httpx(url, http_client)
        if response.status_code == 200:
            # host-meta is typically XML
            if not response.content:
                return None

            try:
                # Parse XML to extract the webfinger template URL
                import xml.etree.ElementTree as ET

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

    except httpx.RequestError:
        # Connection errors are expected when host-meta isn't available
        return None


def check_webfinger(domain, http_client):
    """Check WebFinger endpoint for backend domain discovery.

    Returns {"backend_domain": domain} on success, None on failure.
    Failures are silent (no logging) since this is a fallback method.
    """
    target = "webfinger"
    url = f"https://{domain}/.well-known/webfinger?resource=acct:{domain}@{domain}"
    try:
        response = get_httpx(url, http_client)
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
            data = parse_json_with_fallback(response, domain, target)
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
            handle_http_failed(domain, target, response)
            return None
        # Other HTTP errors are silent (fallback behavior)
        return None
    except httpx.RequestError:
        # Connection errors are silent (fallback behavior)
        return None
    except json.JSONDecodeError:
        # JSON errors are silent (fallback behavior)
        return None


def sanitize_nodeinfo_url(url: str) -> str:
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
        import re

        clean_path = re.sub(r"/+", "/", parsed.path)
        query = f"?{parsed.query}" if parsed.query else ""
        fragment = f"#{parsed.fragment}" if parsed.fragment else ""
        url = f"{parsed.scheme}://{parsed.netloc}{clean_path}{query}{fragment}"

    return url


def check_nodeinfo(
    domain, backend_domain, http_client, preserve_ignore=False, preserve_nxdomain=False
):
    """Check NodeInfo well-known endpoint for NodeInfo 2.0 URL."""
    target = "nodeinfo"
    url = f"https://{backend_domain}/.well-known/nodeinfo"
    try:
        response = get_httpx(url, http_client)
        if response.status_code == 200:
            content_type = response.headers.get("Content-Type", "")
            if "json" not in content_type:
                handle_incorrect_file_type(
                    domain, target, content_type, preserve_ignore
                )
                return False
            if not response.content:
                exception = "reply is empty"
                handle_json_exception(
                    domain, target, exception, preserve_ignore, preserve_nxdomain
                )
                return False
            data = parse_json_with_fallback(
                response, domain, target, preserve_ignore, preserve_nxdomain
            )
            if data is False:
                return False
            if not isinstance(data, dict):
                return None

            # Check if this is a Matrix server (has m.server field)
            if "m.server" in data:
                vmc_output(f"{domain}: Matrix", "cyan", use_tqdm=True)
                # Save nodeinfo as "matrix" and mark as non-Mastodon
                with db_pool.connection() as conn, conn.cursor() as cursor:
                    try:
                        cursor.execute(
                            """
                                INSERT INTO raw_domains (domain, nodeinfo, errors, reason)
                                VALUES (%s, %s, %s, %s)
                                ON CONFLICT(domain) DO UPDATE SET
                                nodeinfo = excluded.nodeinfo,
                                errors = excluded.errors,
                                reason = excluded.reason
                            """,
                            (domain.lower(), "matrix", None, None),
                        )
                        conn.commit()
                    except Exception as exception:
                        vmc_output(
                            f"{domain}: Failed to save Matrix nodeinfo {exception}",
                            "red",
                            use_tqdm=True,
                        )
                        conn.rollback()
                clear_domain_error(domain)
                delete_domain_if_known(domain)
                return False

            # Check if this is actually nodeinfo data returned directly
            # instead of a well-known document with links
            if "software" in data and "version" in data:
                # This is nodeinfo data returned directly at the well-known endpoint
                # Return it as if it came from a nodeinfo_20 request
                vmc_output(
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
                vmc_output(
                    f"{domain}: Single link object returned instead of array",
                    "white",
                    use_tqdm=True,
                )
                # Wrap the single object in an array for consistent processing
                links = [data]

            if links is not None and len(links) == 0:
                exception = "empty links array in reply"
                handle_json_exception(
                    domain, target, exception, preserve_ignore, preserve_nxdomain
                )
                return False
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
                    nodeinfo_20_url = sanitize_nodeinfo_url(nodeinfo_20_url)
                    return {"nodeinfo_20_url": nodeinfo_20_url}

            exception = "no links in reply"
            handle_json_exception(
                domain, target, exception, preserve_ignore, preserve_nxdomain
            )
            return False
        if response.status_code in http_codes_to_hardfail:
            handle_http_failed(domain, target, response)
            return False
        handle_http_status_code(
            domain, target, response, preserve_ignore, preserve_nxdomain
        )
    except httpx.RequestError as exception:
        handle_tcp_exception(
            domain, target, exception, preserve_ignore, preserve_nxdomain
        )
    except json.JSONDecodeError as exception:
        handle_json_exception(
            domain, target, exception, preserve_ignore, preserve_nxdomain
        )
    return None


def check_nodeinfo_20(
    domain,
    nodeinfo_20_url,
    http_client,
    from_cache=False,
    preserve_ignore=False,
    preserve_nxdomain=False,
):
    """Fetch and parse NodeInfo 2.0 data."""
    target = "nodeinfo_20" if not from_cache else "nodeinfo_20 (cached)"
    try:
        response = get_httpx(nodeinfo_20_url, http_client)
        if response.status_code == 200:
            content_type = response.headers.get("Content-Type", "")
            if "json" not in content_type:
                handle_incorrect_file_type(
                    domain, target, content_type, preserve_ignore, preserve_nxdomain
                )
                return False
            if not response.content:
                exception = "reply empty"
                handle_json_exception(
                    domain, target, exception, preserve_ignore, preserve_nxdomain
                )
                return False
            nodeinfo_20_result = parse_json_with_fallback(
                response, domain, target, preserve_ignore, preserve_nxdomain
            )
            if nodeinfo_20_result is False:
                return False
            return nodeinfo_20_result
        if response.status_code in http_codes_to_hardfail:
            handle_http_failed(domain, target, response)
            return False
        handle_http_status_code(
            domain, target, response, preserve_ignore, preserve_nxdomain
        )
    except httpx.RequestError as exception:
        handle_tcp_exception(
            domain, target, exception, preserve_ignore, preserve_nxdomain
        )
        return False
    except json.JSONDecodeError as exception:
        handle_json_exception(
            domain, target, exception, preserve_ignore, preserve_nxdomain
        )
        return False
    return None


# =============================================================================
# DOMAIN PROCESSING - Instance Processing
# =============================================================================


def is_mastodon_instance(nodeinfo_20_result: dict[str, Any]) -> bool:
    """Check if the NodeInfo response indicates a Mastodon-compatible instance."""
    if not isinstance(nodeinfo_20_result, dict):
        return False

    software = nodeinfo_20_result.get("software")
    if software is None:
        return False

    software_name = software.get("name")
    if software_name is None:
        return False

    return software_name.lower() in {"mastodon"}


def mark_as_non_mastodon(domain, other_platform):
    """Mark a domain as a non-Mastodon platform."""
    if not other_platform:
        other_platform = "Unknown"
    other_platform = other_platform.lower().replace(" ", "-")
    vmc_output(f"{domain}: {other_platform}", "cyan", use_tqdm=True)
    clear_domain_error(domain)
    delete_domain_if_known(domain)


def get_instance_uri(
    backend_domain: str, http_client: httpx.Client
) -> tuple[str | None, bool]:
    """Fetch the instance API and extract the domain/uri field.

    First tries v2 instance API for 'domain' field, then falls back to
    v1 instance API for 'uri' field if v2 fails.

    Returns:
        tuple: (domain/uri string or None, is_401 boolean)
            - First element is the domain/uri if successful, None otherwise
            - Second element is True if a 401 response was encountered, False otherwise
    """
    # Try v2 API first
    instance_api_v2_url = f"https://{backend_domain}/api/v2/instance"
    target_v2 = "instance_api_v2"

    try:
        response = get_httpx(instance_api_v2_url, http_client)
        if response.status_code == 401:
            return (None, True)
        if response.status_code == 200:
            content_type = response.headers.get("Content-Type", "")
            if "json" in content_type and response.content:
                instance_data = parse_json_with_fallback(
                    response, backend_domain, target_v2
                )
                if instance_data and isinstance(instance_data, dict):
                    domain = instance_data.get("domain")
                    # Normalize domain to lowercase for consistent comparison
                    if domain:
                        return (domain.strip().lower(), False)
    except (httpx.RequestError, json.JSONDecodeError):
        pass  # Fall through to v1 API

    # Fallback to v1 API
    instance_api_v1_url = f"https://{backend_domain}/api/v1/instance"
    target_v1 = "instance_api"

    try:
        response = get_httpx(instance_api_v1_url, http_client)
        if response.status_code == 401:
            return (None, True)
        if response.status_code == 200:
            content_type = response.headers.get("Content-Type", "")
            if "json" not in content_type:
                return (None, False)
            if not response.content:
                return (None, False)

            instance_data = parse_json_with_fallback(
                response, backend_domain, target_v1
            )
            if instance_data is False or not instance_data:
                return (None, False)

            if isinstance(instance_data, dict):
                uri = instance_data.get("uri")
                # Normalize domain to lowercase for consistent comparison
                if uri:
                    return (uri.strip().lower(), False)
                return (uri, False)
            return (None, False)
        return (None, False)
    except httpx.RequestError:
        return (None, False)
    except json.JSONDecodeError:
        return (None, False)


def process_mastodon_instance(
    domain,
    nodeinfo_20_result,
    nightly_version_ranges,
    actual_domain=None,
    preserve_ignore=False,
    preserve_nxdomain=False,
):
    """Process a confirmed Mastodon instance and update the database.

    Args:
        domain: The original domain being crawled (used for error tracking)
        nodeinfo_20_result: NodeInfo 2.0 data
        nightly_version_ranges: Version ranges for nightly builds
        actual_domain: The canonical domain from instance API
            (used for database updates)
        preserve_ignore: If True, preserve the ignore flag when recording errors
        preserve_nxdomain: If True, preserve the nxdomain flag when recording errors
    """
    # Use actual_domain for database operations if provided,
    # otherwise fall back to domain
    db_domain = actual_domain if actual_domain else domain

    software_version_full = nodeinfo_20_result["software"]["version"]
    software_version = clean_version(
        nodeinfo_20_result["software"]["version"],
        nightly_version_ranges,
    )

    users = nodeinfo_20_result.get("usage", {}).get("users", {})
    if not users:
        error_to_print = "No usage data in NodeInfo"
        vmc_output(f"{db_domain}: {error_to_print}", "yellow", use_tqdm=True)
        log_error(domain, error_to_print)
        increment_domain_error(domain, "MAU", preserve_ignore, preserve_nxdomain)
        delete_domain_if_known(domain)
        return

    required_fields = [
        ("total", "No user data in NodeInfo"),
        ("activeMonth", "No MAU data in NodeInfo"),
    ]

    for field, error_msg in required_fields:
        if field not in users:
            vmc_output(f"{db_domain}: {error_msg}", "yellow", use_tqdm=True)
            log_error(domain, error_msg)
            increment_domain_error(domain, "MAU", preserve_ignore, preserve_nxdomain)
            delete_domain_if_known(domain)
            return

    active_month_users = users["activeMonth"]

    if version.parse(software_version.split("-")[0]) > version.parse(
        version_main_branch,
    ):
        error_to_print = "Mastodon version invalid"
        vmc_output(f"{db_domain}: {error_to_print}", "yellow", use_tqdm=True)
        log_error(domain, error_to_print)
        increment_domain_error(domain, "VER", preserve_ignore, preserve_nxdomain)
        delete_domain_if_known(domain)
        return

    # Use db_domain (actual_domain if available) for database updates
    update_mastodon_domain(
        db_domain,
        software_version,
        software_version_full,
        active_month_users,
    )

    clear_domain_error(domain)

    version_info = f"Mastodon v{software_version}"
    if software_version != nodeinfo_20_result["software"]["version"]:
        version_info = f"{version_info} ({nodeinfo_20_result['software']['version']})"
    vmc_output(f"{db_domain}: {version_info}", "green", use_tqdm=True)

    # If actual_domain is different from domain, delete the old domain entry
    if actual_domain and actual_domain != domain:
        delete_domain_if_known(domain)


def process_domain(domain, http_client, nightly_version_ranges, user_choice=None):
    """Main processing pipeline for a single domain.

    Args:
        domain: The domain to process
        http_client: The HTTP client to use
        nightly_version_ranges: Version ranges for nightly builds
        user_choice: The user's menu choice (used to determine if retrying ignored/nxdomain domains)
    """
    preserve_ignore = user_choice == "11"
    preserve_nxdomain = user_choice == "13"

    if not check_robots_txt(domain, http_client, preserve_ignore, preserve_nxdomain):
        return

    # Try to discover backend domain via host-meta first
    backend_domain = check_host_meta(domain, http_client)

    if backend_domain:
        # host-meta succeeded, skip webfinger
        vmc_output(
            f"{domain}: Found backend via host-meta: {backend_domain}",
            "white",
            use_tqdm=True,
        )
    else:
        # host-meta failed, try webfinger
        webfinger_result = check_webfinger(domain, http_client)
        if not webfinger_result:
            # webfinger failed, try nodeinfo with original domain as fallback
            backend_domain = domain
            vmc_output(
                f"{domain}: Both host-meta and webfinger failed, "
                "trying nodeinfo at original domain",
                "white",
                use_tqdm=True,
            )
        else:
            backend_domain = webfinger_result["backend_domain"]

    # Check nodeinfo at the discovered backend domain
    nodeinfo_result = check_nodeinfo(
        domain, backend_domain, http_client, preserve_ignore, preserve_nxdomain
    )
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

        nodeinfo_20_result = check_nodeinfo_20(
            domain,
            nodeinfo_20_url,
            http_client,
            preserve_ignore=preserve_ignore,
            preserve_nxdomain=preserve_nxdomain,
        )
        if nodeinfo_20_result is False:
            return
        if not nodeinfo_20_result:
            return

    if is_mastodon_instance(nodeinfo_20_result):
        # Get the actual domain from the instance API
        instance_uri, is_401 = get_instance_uri(backend_domain, http_client)

        if is_401:
            # Instance API requires authentication (401 Unauthorized)
            error_to_print = "Instance API requires authentication"
            vmc_output(f"{domain}: {error_to_print}", "orange", use_tqdm=True)
            log_error(domain, error_to_print)
            mark_noapi_domain(domain)
            delete_domain_if_known(domain)
            return

        if instance_uri is None:
            # Instance API endpoint is required for Mastodon instances
            error_to_print = "could not retrieve instance URI"
            vmc_output(f"{domain}: {error_to_print}", "yellow", use_tqdm=True)
            log_error(domain, error_to_print)
            increment_domain_error(domain, "API", preserve_ignore, preserve_nxdomain)
            return

        # Check if this is an alias (redirect to another instance)
        # Use instance_uri (from API) as the authoritative canonical domain
        # Only domains that match the instance_uri should be stored
        if is_alias_domain(domain, instance_uri):
            vmc_output(
                f"{domain}: Alias - redirects to {instance_uri}",
                "cyan",
                use_tqdm=True,
            )
            mark_alias_domain(domain)
            delete_domain_if_known(domain)
            return

        # Save software information from nodeinfo to database
        # Only save for validated Mastodon instances that aren't aliases
        software_data = nodeinfo_20_result.get("software")
        if software_data and isinstance(software_data, dict):
            save_nodeinfo_software(domain, software_data)

        process_mastodon_instance(
            domain,
            nodeinfo_20_result,
            nightly_version_ranges,
            actual_domain=instance_uri,
            preserve_ignore=preserve_ignore,
            preserve_nxdomain=preserve_nxdomain,
        )
    else:
        # Save software information for non-Mastodon platforms unconditionally
        software_data = nodeinfo_20_result.get("software")
        if software_data and isinstance(software_data, dict):
            save_nodeinfo_software(domain, software_data)

        mark_as_non_mastodon(domain, nodeinfo_20_result["software"]["name"])


# =============================================================================
# DOMAIN PROCESSING - Batch Processing
# =============================================================================


def check_and_record_domains(
    domain_list,
    not_masto_domains,
    baddata_domains,
    failed_domains,
    ignored_domains,
    user_choice,
    junk_domains,
    dni_domains,
    bad_tlds,
    domain_endings,
    http_client,
    nxdomain_domains,
    norobots_domains,
    noapi_domains,
    alias_domains,
    nightly_version_ranges,
):
    """Process a list of domains concurrently with progress tracking.

    Uses threading for cross-domain parallelism.
    """
    max_workers = int(os.getenv("VMCRAWL_MAX_THREADS", "2"))
    shutdown_event = threading.Event()

    def process_single_domain(domain):
        if shutdown_event.is_set():
            return

        if should_skip_domain(
            domain,
            not_masto_domains,
            baddata_domains,
            failed_domains,
            ignored_domains,
            nxdomain_domains,
            norobots_domains,
            noapi_domains,
            alias_domains,
            user_choice,
        ):
            return

        if is_junk_or_bad_tld(
            domain,
            junk_domains,
            dni_domains,
            bad_tlds,
            domain_endings,
        ):
            return

        try:
            process_domain(domain, http_client, nightly_version_ranges, user_choice)
        except httpx.CloseError:
            pass
        except Exception as exception:
            if not shutdown_event.is_set():
                target = "shutdown"
                preserve_ignore = user_choice == "11"
                preserve_nxdomain = user_choice == "13"
                handle_tcp_exception(
                    domain, target, exception, preserve_ignore, preserve_nxdomain
                )

    executor = ThreadPoolExecutor(max_workers=max_workers)
    try:
        # Submit all domains at once for maximum parallelism
        # The thread pool will manage concurrency automatically
        futures = {
            executor.submit(process_single_domain, domain): domain
            for domain in domain_list
        }

        try:
            for future in tqdm(
                as_completed(futures),
                total=len(domain_list),
                desc=f"{appname}",
                unit="d",
            ):
                try:
                    future.result()
                except httpx.CloseError:
                    pass
                except Exception as exception:
                    if not shutdown_event.is_set():
                        domain = futures[future]
                        vmc_output(
                            f"{domain}: Failed to complete processing {exception}",
                            "red",
                            use_tqdm=True,
                        )
        except KeyboardInterrupt:
            shutdown_event.set()
            vmc_output(f"\n{appname} interrupted by user", "red")
            for future in futures:
                future.cancel()
            executor.shutdown(wait=False, cancel_futures=True)
            return
    finally:
        if not shutdown_event.is_set():
            executor.shutdown(wait=True)


# =============================================================================
# STATISTICS FUNCTIONS - Mastodon Domain Counts
# =============================================================================


def get_mastodon_domains():
    """Get total count of known Mastodon domains."""
    cursor = conn.cursor()
    value_to_return = 0
    try:
        cursor.execute("SELECT COUNT(domain) AS domains FROM mastodon_domains;")
        result = cursor.fetchone()
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain total Mastodon domains: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_unique_versions():
    """Get count of unique software versions."""
    cursor = conn.cursor()
    value_to_return = 0
    try:
        cursor.execute(
            "SELECT COUNT(DISTINCT software_version) "
            "AS unique_software_versions FROM mastodon_domains;",
        )
        result = cursor.fetchone()
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain unique versions: {e}")
        conn.rollback()
    finally:
        cursor.close()


# =============================================================================
# STATISTICS FUNCTIONS - User Counts
# =============================================================================


def get_mau():
    """Get total monthly active user count across all instances."""
    cursor = conn.cursor()
    value_to_return = 0
    try:
        cursor.execute("SELECT SUM(active_users_monthly) AS mau FROM mastodon_domains;")
        result = cursor.fetchone()
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain active users: {e}")
        conn.rollback()
    finally:
        cursor.close()


# =============================================================================
# STATISTICS FUNCTIONS - Branch Instance Counts
# =============================================================================


def get_main_branch_instances():
    """Get count of instances on main branch."""
    cursor = conn.cursor()
    value_to_return = 0
    try:
        cursor.execute(
            """
            SELECT COUNT(DISTINCT domain) as "Main Total"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT branch || '.%'
                FROM patch_versions
                WHERE n_level = -1
            );
        """,
        )
        result = cursor.fetchone()
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain total main instances: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_latest_branch_instances():
    """Get count of instances on latest branch."""
    cursor = conn.cursor()
    value_to_return = 0
    try:
        cursor.execute(
            """
            SELECT COUNT(DISTINCT domain) as "Latest Total"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT branch || '.%'
                FROM patch_versions
                WHERE n_level = 0
            );
        """,
        )
        result = cursor.fetchone()
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain total latest instances: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_previous_branch_instances():
    """Get count of instances on previous release branch."""
    cursor = conn.cursor()
    value_to_return = 0
    try:
        cursor.execute(
            """
            SELECT COUNT(DISTINCT domain) as "Latest Total"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT branch || '.%'
                FROM patch_versions
                WHERE n_level = 1
            );
        """,
        )
        result = cursor.fetchone()
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain total previous instances: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_deprecated_branch_instances():
    """Get count of instances on deprecated branches."""
    cursor = conn.cursor()
    value_to_return = 0
    try:
        cursor.execute(
            """
            SELECT COUNT(DISTINCT domain) as "Latest Total"
            FROM mastodon_domains
            WHERE EXISTS (
                SELECT 1
                FROM patch_versions
                WHERE n_level >= 2
                  AND mastodon_domains.software_version LIKE
                      patch_versions.branch || '.%'
            );
        """,
        )
        result = cursor.fetchone()
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain total deprecated instances: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_eol_branch_instances():
    """Get count of instances on EOL branches."""
    cursor = conn.cursor()
    value_to_return = 0
    try:
        cursor.execute(
            """
            SELECT COUNT(DISTINCT mastodon_domains.domain) as "Latest Total"
            FROM mastodon_domains
            WHERE EXISTS (
                SELECT 1
                FROM eol_versions
                WHERE mastodon_domains.software_version LIKE
                    eol_versions.software_version || '%'
            );
        """,
        )
        result = cursor.fetchone()
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain total EOL instances: {e}")
        conn.rollback()
    finally:
        cursor.close()


# =============================================================================
# STATISTICS FUNCTIONS - Patched Instance Counts
# =============================================================================


def get_main_patched_instances():
    """Get count of instances on latest main version."""
    cursor = conn.cursor()
    value_to_return = 0
    try:
        cursor.execute(
            """
            SELECT COUNT(DISTINCT domain) as "Main Patched"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT software_version
                FROM patch_versions
                WHERE main = True
            ) || '%';
        """,
        )
        result = cursor.fetchone()
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain main patched instances: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_latest_patched_instances():
    """Get count of instances on latest release version."""
    cursor = conn.cursor()
    value_to_return = 0
    try:
        cursor.execute(
            """
            SELECT COUNT(DISTINCT domain) as "Latest Patched"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT software_version
                FROM patch_versions
                WHERE n_level = 0
            ) || '%';
        """,
        )
        result = cursor.fetchone()
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain release patched instances: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_previous_patched_instances():
    """Get count of instances on latest previous branch version."""
    cursor = conn.cursor()
    value_to_return = 0
    try:
        cursor.execute(
            """
            SELECT COUNT(DISTINCT domain) as "Previous Patched"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT software_version
                FROM patch_versions
                WHERE n_level = 1
            ) || '%';
        """,
        )
        result = cursor.fetchone()
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain previous patched instances: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_deprecated_patched_instances():
    """Get count of instances on latest deprecated branch versions."""
    cursor = conn.cursor()
    value_to_return = 0
    try:
        cursor.execute(
            """
            SELECT COUNT(DISTINCT domain) as "Deprecated Patched"
            FROM mastodon_domains
            WHERE EXISTS (
                SELECT 1
                FROM patch_versions
                WHERE n_level >= 2
                  AND mastodon_domains.software_version LIKE
                      patch_versions.software_version || '%'
            );
        """,
        )
        result = cursor.fetchone()
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain deprecated patched instances: {e}")
        conn.rollback()
    finally:
        cursor.close()


# =============================================================================
# STATISTICS FUNCTIONS - Branch User Counts (Active)
# =============================================================================


def get_main_branch_mau():
    """Get active users on main branch instances."""
    cursor = conn.cursor()
    value_to_return = 0
    try:
        cursor.execute(
            """
            SELECT SUM(active_users_monthly) as "Main Total"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT branch || '.%'
                FROM patch_versions
                WHERE n_level = -1
            );
        """,
        )
        result = cursor.fetchone()
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain active main instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_latest_branch_mau():
    """Get active users on latest branch instances."""
    cursor = conn.cursor()
    value_to_return = 0
    try:
        cursor.execute(
            """
            SELECT SUM(active_users_monthly) as "Latest Total"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT branch || '.%'
                FROM patch_versions
                WHERE n_level = 0
            );
        """,
        )
        result = cursor.fetchone()
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain active latest instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_previous_branch_mau():
    """Get active users on previous release branch instances."""
    cursor = conn.cursor()
    value_to_return = 0
    try:
        cursor.execute(
            """
            SELECT SUM(active_users_monthly) as "Latest Total"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT branch || '.%'
                FROM patch_versions
                WHERE n_level = 1
            );
        """,
        )
        result = cursor.fetchone()
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain active previous instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_deprecated_branch_mau():
    """Get active users on deprecated branch instances."""
    cursor = conn.cursor()
    value_to_return = 0
    try:
        cursor.execute(
            """
            SELECT SUM(active_users_monthly) as "Latest Total"
            FROM mastodon_domains
            WHERE EXISTS (
                SELECT 1
                FROM patch_versions
                WHERE n_level >= 2
                  AND mastodon_domains.software_version LIKE
                      patch_versions.branch || '.%'
            );
        """,
        )
        result = cursor.fetchone()
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain active deprecated instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_eol_branch_mau():
    """Get active users on EOL branch instances."""
    cursor = conn.cursor()
    value_to_return = 0
    try:
        cursor.execute(
            """
            SELECT SUM(mastodon_domains.active_users_monthly) as "Latest Total"
            FROM mastodon_domains
            WHERE EXISTS (
                SELECT 1
                FROM eol_versions
                WHERE mastodon_domains.software_version LIKE
                    eol_versions.software_version || '%'
            );
        """,
        )
        result = cursor.fetchone()
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain active EOL instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


# =============================================================================
# STATISTICS FUNCTIONS - Patched User Counts (Active)
# =============================================================================


def get_main_patched_mau():
    """Get active users on latest main version instances."""
    cursor = conn.cursor()
    value_to_return = 0
    try:
        cursor.execute(
            """
            SELECT SUM(active_users_monthly) as "Main Patched"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT software_version
                FROM patch_versions
                WHERE main = True
            ) || '%';
        """,
        )
        result = cursor.fetchone()
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain active main patched instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_latest_patched_mau():
    """Get active users on latest release version instances."""
    cursor = conn.cursor()
    value_to_return = 0
    try:
        cursor.execute(
            """
            SELECT SUM(active_users_monthly) as "Latest Patched"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT software_version
                FROM patch_versions
                WHERE n_level = 0
            ) || '%';
        """,
        )
        result = cursor.fetchone()
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain active release patched instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_previous_patched_mau():
    """Get active users on latest previous branch version instances."""
    cursor = conn.cursor()
    value_to_return = 0
    try:
        cursor.execute(
            """
            SELECT SUM(active_users_monthly) as "Previous Patched"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT software_version
                FROM patch_versions
                WHERE n_level = 1
            ) || '%';
        """,
        )
        result = cursor.fetchone()
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain active previous patched instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_deprecated_patched_mau():
    """Get active users on latest deprecated branch version instances."""
    cursor = conn.cursor()
    value_to_return = 0
    try:
        cursor.execute(
            """
            SELECT SUM(active_users_monthly) as "Deprecated Patched"
            FROM mastodon_domains
            WHERE EXISTS (
                SELECT 1
                FROM patch_versions
                WHERE n_level >= 2
                  AND mastodon_domains.software_version LIKE
                      patch_versions.software_version || '%'
            );
        """,
        )
        result = cursor.fetchone()
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain active deprecated patched instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


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
            cursor.execute(
                """
        INSERT INTO statistics (
        date, mau, unique_versions, main_instances,
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
        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
        )
        ON CONFLICT (date) DO UPDATE SET
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
            print(f"Failed to insert/update statistics: {e}")
            conn.rollback()


# =============================================================================
# DATA LOADING FUNCTIONS
# =============================================================================


def load_from_database(user_choice):
    """Load domain list from database based on user menu selection."""
    query_map = {
        "0": (
            "SELECT domain FROM raw_domains WHERE errors = 0 ORDER BY LENGTH(DOMAIN)"
        ),
        "1": (
            "SELECT domain FROM raw_domains WHERE "
            "(failed IS NULL OR failed = FALSE) AND "
            "(ignore IS NULL OR ignore = FALSE) AND "
            "(nxdomain IS NULL OR nxdomain = FALSE) AND "
            "(norobots IS NULL OR norobots = FALSE) AND "
            "(noapi IS NULL OR noapi = FALSE) AND "
            "(baddata IS NULL OR baddata = FALSE) AND "
            "(alias IS NULL OR alias = FALSE) AND "
            "(nodeinfo = 'mastodon' OR nodeinfo IS NULL) "
            "ORDER BY domain"
        ),
        "4": (
            "SELECT domain FROM raw_domains WHERE reason IS NOT NULL ORDER BY domain"
        ),
        "5": (
            "SELECT domain FROM raw_domains WHERE reason IS NOT NULL "
            "AND nodeinfo = 'mastodon' ORDER BY domain;"
        ),
        "10": (
            "SELECT domain FROM raw_domains WHERE nodeinfo != 'mastodon' "
            "ORDER BY domain"
        ),
        "11": "SELECT domain FROM raw_domains WHERE ignore = TRUE ORDER BY domain",
        "12": "SELECT domain FROM raw_domains WHERE failed = TRUE ORDER BY domain",
        "13": "SELECT domain FROM raw_domains WHERE nxdomain = TRUE ORDER BY domain",
        "14": "SELECT domain FROM raw_domains WHERE norobots = TRUE ORDER BY domain",
        "15": "SELECT domain FROM raw_domains WHERE noapi = TRUE ORDER BY domain",
        "16": "SELECT domain FROM raw_domains WHERE alias = TRUE ORDER BY domain",
        "20": (
            "SELECT domain FROM raw_domains WHERE reason LIKE 'SSL%' ORDER BY errors"
        ),
        "21": (
            "SELECT domain FROM raw_domains WHERE reason LIKE 'TCP%' ORDER BY errors"
        ),
        "22": (
            "SELECT domain FROM raw_domains WHERE reason LIKE 'DNS%' ORDER BY errors"
        ),
        "30": (
            "SELECT domain FROM raw_domains WHERE reason ~ '^2[0-9]{2}.*' "
            "ORDER BY errors"
        ),
        "31": (
            "SELECT domain FROM raw_domains WHERE reason ~ '^3[0-9]{2}.*' "
            "ORDER BY errors"
        ),
        "32": (
            "SELECT domain FROM raw_domains WHERE reason ~ '^4[0-9]{2}.*' "
            "ORDER BY errors"
        ),
        "33": (
            "SELECT domain FROM raw_domains WHERE reason ~ '^5[0-9]{2}.*' "
            "ORDER BY errors"
        ),
        "40": (
            "SELECT domain FROM raw_domains WHERE reason LIKE 'JSON%' ORDER BY errors"
        ),
        "41": (
            "SELECT domain FROM raw_domains WHERE reason LIKE 'FILE%' ORDER BY errors"
        ),
        "42": (
            "SELECT domain FROM raw_domains WHERE reason LIKE 'TYPE%' ORDER BY errors"
        ),
        "43": (
            "SELECT domain FROM raw_domains WHERE reason LIKE 'MAU%' ORDER BY errors"
        ),
        "44": (
            "SELECT domain FROM raw_domains WHERE reason LIKE 'API%' ORDER BY errors"
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
        "53": (
            "SELECT domain FROM raw_domains WHERE nodeinfo = 'mastodon' ORDER BY domain"
        ),
    }

    params = None

    if user_choice in ["2", "3"]:
        query = query_map["1"]
    else:
        query = query_map.get(user_choice)

        if user_choice == "50":
            params = {"versions": all_patched_versions}
            vmc_output("Excluding versions:", "pink")
            for version in params["versions"]:
                vmc_output(f" - {version}", "pink")
        elif user_choice == "51":
            params = [f"{version_main_branch}%"]

    if not query:
        vmc_output(f"Choice {user_choice} is invalid, using default query", "pink")
        query = query_map["1"]

    # Use server-side cursor for large result sets to avoid loading all into memory
    with db_pool.connection() as conn, conn.cursor(name="domain_loader") as cursor:
        cursor.itersize = 1000  # Fetch 1000 rows at a time
        try:
            if params:
                _ = cursor.execute(query, params)  # pyright: ignore[reportCallIssue,reportArgumentType]
            else:
                _ = cursor.execute(query)  # pyright: ignore[reportCallIssue,reportArgumentType]
            domain_list = [
                row[0].strip()
                for row in cursor
                if row[0] and row[0].strip() and not has_emoji_chars(row[0])
            ]
            conn.commit()
        except Exception as exception:
            vmc_output(f"Failed to obtain selected domain list: {exception}", "red")
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
            if not domain or has_emoji_chars(domain):
                continue

            domain_list.append(domain)
            cursor.execute(
                "SELECT COUNT(*) FROM raw_domains WHERE domain = %s",
                (domain,),
            )
            result = cursor.fetchone()
            exists = result is not None and result[0] > 0

            if not exists:
                cursor.execute(
                    "INSERT INTO raw_domains (domain, errors) VALUES (%s, %s)",
                    (domain, None),
                )
            conn.commit()
    return domain_list


# =============================================================================
# MENU AND CLI FUNCTIONS
# =============================================================================


def get_menu_options() -> dict[str, dict[str, str]]:
    """Return the menu options dictionary."""
    return {
        "Process new domains": {"0": "Uncrawled"},
        "Change process direction": {"1": "Standard", "2": "Reverse", "3": "Random"},
        "Retry any (non-fatal) errors": {
            "4": "Any",
            "5": "Known",
        },
        "Retry fatal errors": {
            "10": "Other",
            "11": "Ignored",
            "12": "Failed",
            "13": "NXDOMAIN",
            "14": "Prohibited",
            "15": "NoAPI",
            "16": "Alias",
        },
        "Retry connection errors": {
            "20": "SSL",
            "21": "TCP",
            "22": "DNS",
        },
        "Retry TCP errors": {"30": "2xx", "31": "3xx", "32": "4xx", "33": "5xx"},
        "Retry target errors": {
            "40": "Bad JSON",
            "41": "Bad Size",
            "42": "Bad Type",
            "43": "Bad MAU",
            "44": "Bad API",
        },
        "Retry known instances": {
            "50": "Unpatched",
            "51": f"{version_main_branch}",
            "52": "Active",
            "53": "All",
        },
    }


def print_menu(menu_options: dict[str, dict[str, str]] | None = None) -> None:
    """Print the text-based menu to stdout."""
    if menu_options is None:
        menu_options = get_menu_options()

    for category, options in menu_options.items():
        options_str = " ".join(f"({key}) {value}" for key, value in options.items())
        vmc_output(f"{category}: ", "cyan", end="")
        vmc_output(options_str, "")
    vmc_output("Enter your choice (1, 2, 3, etc):", "bold", end=" ")
    sys.stdout.flush()


def interactive_select_menu(menu_options: dict[str, dict[str, str]]) -> str | None:
    """Interactive menu picker using arrow keys (TTY only)."""
    if is_running_headless():
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
        curses.curs_set(0)
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
                return None

    try:
        return curses.wrapper(_menu)
    except Exception:
        return None


def get_user_choice() -> str:
    """Read user menu choice from stdin."""
    return sys.stdin.readline().strip()


# =============================================================================
# MODULE-LEVEL INITIALIZATION
# =============================================================================

# Version information (fetched at module load)
version_main_branch = get_main_version_branch()
version_main_release = get_main_version_release()
version_latest_release = get_highest_mastodon_version()
version_backport_releases = get_backport_mastodon_versions()
all_patched_versions = [version_main_release] + version_backport_releases

# Update database with current version information
update_patch_versions()
delete_old_patch_versions()


# =============================================================================
# MAIN FUNCTION
# =============================================================================


def main():
    """Main entry point for the crawler."""
    parser = argparse.ArgumentParser(
        description="Crawl version information from Mastodon instances.",
    )
    parser.add_argument(
        "-f",
        "--file",
        type=str,
        help="bypass database and use a file instead (ex: ~/domains.txt)",
    )
    parser.add_argument(
        "-r",
        "--new",
        action="store_true",
        help="only process new domains added to the database (same as menu item 0)",
    )
    parser.add_argument(
        "-t",
        "--target",
        type=str,
        help="target only a specific domain and ignore the database (ex: vmst.io)",
    )

    args = parser.parse_args()

    if args.file and args.target:
        vmc_output("You cannot set both file and target arguments", "red")
        sys.exit(1)

    vmc_output(f"{appname} v{appversion} ({current_filename})", "bold")
    if is_running_headless():
        vmc_output("Running in headless mode", "pink")
    try:
        domain_list_file = args.file if args.file is not None else None
        single_domain_target = args.target if args.target is not None else None
        try:
            if domain_list_file:
                user_choice = 1
                domain_list = load_from_file(domain_list_file)
                vmc_output("Crawling domains from provided file", "cyan")
            elif single_domain_target:
                user_choice = 1
                domain_list = single_domain_target.replace(" ", "").split(",")
                domain_word = "s" if len(domain_list) > 1 else ""
                vmc_output(
                    f"Crawling domain{domain_word} from target argument",
                    "cyan",
                )
            else:
                if args.new:
                    user_choice = "0"
                elif is_running_headless():
                    user_choice = "3"
                else:
                    menu_options = get_menu_options()
                    selection = interactive_select_menu(menu_options)
                    if selection is None:
                        print_menu(menu_options)
                        user_choice = get_user_choice()
                    else:
                        user_choice = selection

                vmc_output(
                    f"Crawling domains from database choice {user_choice}",
                    "cyan",
                )
                domain_list = load_from_database(user_choice)

            if user_choice == "2":
                domain_list.reverse()
            elif user_choice == "3":
                random.shuffle(domain_list)

        except FileNotFoundError:
            vmc_output(f"File not found: {domain_list_file}", "red")
            sys.exit(1)
        except psycopg.Error as exception:
            vmc_output(f"Database error: {exception}", "red")
            sys.exit(1)

        junk_domains = get_junk_keywords()
        dni_domains = get_dni_domains()
        bad_tlds = get_bad_tld()
        domain_endings = get_domain_endings()
        failed_domains = get_failed_domains()
        ignored_domains = get_ignored_domains()
        not_masto_domains = get_not_masto_domains()
        baddata_domains = get_baddata_domains()
        nxdomain_domains = get_nxdomain_domains()
        norobots_domains = get_norobots_domains()
        noapi_domains = get_noapi_domains()
        alias_domains = get_alias_domains()
        nightly_version_ranges = get_nightly_version_ranges()

        cleanup_old_domains()

        check_and_record_domains(
            domain_list,
            not_masto_domains,
            baddata_domains,
            failed_domains,
            ignored_domains,
            user_choice,
            junk_domains,
            dni_domains,
            bad_tlds,
            domain_endings,
            http_client,
            nxdomain_domains,
            norobots_domains,
            noapi_domains,
            alias_domains,
            nightly_version_ranges,
        )

        save_statistics()

    except KeyboardInterrupt:
        vmc_output(f"\n{appname} interrupted by user", "red")
    finally:
        # Close single connection and pool
        try:
            conn.close()
        except Exception:
            pass
        try:
            db_pool.close(timeout=5)
        except Exception:
            pass
        try:
            http_client.close()
        except Exception:
            pass
        # Force final garbage collection
        gc.collect()

    if is_running_headless():
        if not (args.file or args.target or args.new or args.buffer):
            try:
                os.execv(sys.executable, ["python3"] + sys.argv)
            except Exception as exception:
                vmc_output(f"Failed to restart {appname}: {exception}", "red")
    else:
        sys.exit(0)


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    main()
