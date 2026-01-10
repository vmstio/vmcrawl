#!/usr/bin/env python3

# =============================================================================
# IMPORTS
# =============================================================================

try:
    import argparse
    import gc
    import hashlib
    import json
    import mimetypes
    import os
    import random
    import re
    import sys
    import threading
    import time
    import unicodedata
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from datetime import datetime, timedelta, timezone
    from urllib.parse import urlparse, urlunparse

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
    load_dotenv()
except Exception as exception:
    print(f"Error loading .env file: {exception}")
    sys.exit(1)

# =============================================================================
# APPLICATION METADATA
# =============================================================================

toml_file_path = os.path.join(os.path.dirname(__file__), "pyproject.toml")
try:
    project_info = toml.load(toml_file_path)
    appname = project_info["project"]["name"]
    appversion = project_info["project"]["version"]
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
color_bold = "\033[1m"
color_reset = "\033[0m"
color_cyan = "\033[96m"
color_green = "\033[92m"
color_magenta = "\033[95m"
color_orange = "\033[38;5;208m"
color_pink = "\033[38;5;198m"
color_purple = "\033[94m"
color_red = "\033[91m"
color_yellow = "\033[93m"

colors = {
    "bold": f"{color_bold}",
    "reset": f"{color_reset}",
    "cyan": f"{color_cyan}",
    "green": f"{color_green}",
    "magenta": f"{color_magenta}",
    "orange": f"{color_orange}",
    "pink": f"{color_pink}",
    "purple": f"{color_purple}",
    "red": f"{color_red}",
    "yellow": f"{color_yellow}",
    "white": f"{color_reset}",
}

# HTTP status codes for special handling
http_codes_to_authfail = [401]  # auth
http_codes_to_hardfail = [418, 410]  # gone

# Define maintained branches (adjust as needed)
backport_branches = os.getenv("VMCRAWL_BACKPORTS", "4.5").split(",")

# =============================================================================
# DATABASE CONNECTION
# =============================================================================

db_name = os.getenv("VMCRAWL_POSTGRES_DATA")
db_user = os.getenv("VMCRAWL_POSTGRES_USER")
db_password = os.getenv("VMCRAWL_POSTGRES_PASS")
db_host = os.getenv("VMCRAWL_POSTGRES_HOST", "localhost")
db_port = os.getenv("VMCRAWL_POSTGRES_PORT", "5432")

conn_string = f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"

# Create connection pool for thread-safe database access
# For 2 vCPU systems: Use conservative pool size based on CPU formula: (cores * 2) + 1
# With PgBouncer: Keep small (5 connections) as PgBouncer handles connection multiplexing
# Without PgBouncer: Still keep at 5 for 2 vCPU shared database server
max_workers = int(os.getenv("VMCRAWL_MAX_THREADS", "2"))
max_db_connections = 5  # Optimal for 2 vCPU: (2 * 2) + 1 = 5

try:
    db_pool = ConnectionPool(
        conn_string,
        min_size=2,  # Keep 2 warm connections
        max_size=max_db_connections,
        timeout=30,
        max_waiting=max_workers,  # Allow worker threads to queue briefly
    )
    # Also maintain a single connection for backwards compatibility with module-level code
    conn = psycopg.connect(conn_string)
except psycopg.Error as exception:
    print(f"Error connecting to PostgreSQL database: {exception}")
    sys.exit(1)

# =============================================================================
# HTTP CLIENT CONFIGURATION
# =============================================================================

common_timeout = int(os.getenv("VMCRAWL_COMMON_TIMEOUT", "7"))
http_custom_user_agent = f"{appname}/{appversion} (https://docs.vmst.io/{appname})"
http_custom_headers = {"User-Agent": http_custom_user_agent}

# Memory protection: limit response sizes to prevent memory bombs
# Max response size: 10MB (should be plenty for any legitimate Mastodon API response)
max_response_size = int(os.getenv("VMCRAWL_MAX_RESPONSE_SIZE", str(10 * 1024 * 1024)))

# Create limits object for httpx
limits = httpx.Limits(
    max_keepalive_connections=5,
    max_connections=10,
    keepalive_expiry=30.0,
)

http_client = httpx.Client(
    http2=True,
    follow_redirects=True,
    headers=http_custom_headers,
    timeout=common_timeout,
    limits=limits,
    max_redirects=10,  # Prevent infinite redirect loops
)

# =============================================================================
# UTILITY FUNCTIONS - Output and Environment
# =============================================================================


def vmc_output(text: str, color: str, use_tqdm: bool = False, **kwargs) -> None:
    """Print colored output, optionally using tqdm.write for progress bar compatibility."""
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


def print_line_break():
    """Print a line of equals signs matching console width."""
    width = os.get_terminal_size().columns
    print("=" * width)


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


def is_valid_email(email):
    """Validate email format using regex."""
    pattern = r"^[\w\.-]+(?:\+[\w\.-]+)?@[\w\.-]+\.\w+$"
    return re.match(pattern, email) is not None


def normalize_email(email):
    """Normalize obfuscated email addresses (e.g., 'user [at] domain [dot] com')."""
    email = re.sub(
        r"(\[at\]|\(at\)|\{at\}| at | @ |\[@\]| \[at\] | \(at\) | \{at\} )",
        "@",
        email,
        flags=re.IGNORECASE,
    )
    email = re.sub(
        r"(\[dot\]|\(dot\)|\{dot\}| dot | \[dot\] | \(dot\) | \{dot\} )",
        ".",
        email,
        flags=re.IGNORECASE,
    )
    return email


def has_emoji_chars(domain):
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


def limit_url_depth(source_url, depth=2):
    """Limit URL path depth to specified number of segments."""
    parsed_url = urlparse(source_url)
    path_parts = parsed_url.path.split("/")
    limited_path = "/" + "/".join([part for part in path_parts if part][:depth])
    new_url = urlunparse(parsed_url._replace(path=limited_path))
    return new_url


# =============================================================================
# HTTP FUNCTIONS
# =============================================================================


def get_httpx(url, http_client):
    """Make HTTP GET request with HTTP/2 fallback on connection errors and size limits."""

    def stream_with_size_limit(client, url):
        """Stream response and enforce size limit during download."""
        # Get the stream context manager and enter it manually
        stream_ctx = client.stream("GET", url)
        response = stream_ctx.__enter__()

        try:
            # Check Content-Length header first if available
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > max_response_size:
                stream_ctx.__exit__(None, None, None)
                raise ValueError(
                    f"Response too large: {content_length} bytes (max: {max_response_size})"
                )

            # Stream the response and check size as we download
            chunks = []
            total_size = 0

            for chunk in response.iter_bytes(chunk_size=8192):
                chunks.append(chunk)
                total_size += len(chunk)

                if total_size > max_response_size:
                    stream_ctx.__exit__(None, None, None)
                    raise ValueError(
                        f"Response too large: {total_size} bytes (max: {max_response_size})"
                    )

            # All data received within size limit - construct final response
            # We need to manually build a Response object with our collected data
            final_response = httpx.Response(
                status_code=response.status_code,
                headers=response.headers,
                request=response.request,
            )
            # Directly set the content to bypass decompression
            final_response._content = b"".join(chunks)

            stream_ctx.__exit__(None, None, None)
            return final_response

        except Exception:
            stream_ctx.__exit__(None, None, None)
            raise

    try:
        return stream_with_size_limit(http_client, url)

    except httpx.RequestError as exception:
        error_str = str(exception).casefold()

        http2_error_indicators = ["connectionterminated"]

        if any(indicator in error_str for indicator in http2_error_indicators):
            fallback_client = httpx.Client(
                http2=False,
                follow_redirects=True,
                headers=http_custom_headers,
                timeout=common_timeout,
                limits=limits,
                max_redirects=10,
            )
            try:
                return stream_with_size_limit(fallback_client, url)
            finally:
                fallback_client.close()
        else:
            raise exception


def get_domain_endings():
    """Fetch and cache the set of valid TLDs from IANA."""
    url = "http://data.iana.org/TLD/tlds-alpha-by-domain.txt"
    cache_file_path = get_cache_file_path(url)
    max_cache_age = 86400  # 1 day in seconds

    if is_cache_valid(cache_file_path, max_cache_age):
        with open(cache_file_path, "r") as cache_file:
            # Use set for O(1) lookup
            return {line.strip().lower() for line in cache_file if line.strip()}
    else:
        domain_endings_response = get_httpx(url, http_client)
        if domain_endings_response.status_code in [200]:
            # Use set for O(1) lookup
            domain_endings = {
                line.strip().lower()
                for line in domain_endings_response.text.splitlines()
                if line.strip() and not line.startswith("#")
            }
            with open(cache_file_path, "w") as cache_file:
                cache_file.write("\n".join(sorted(domain_endings)))
            return domain_endings
        else:
            raise Exception(
                f"Failed to fetch domain endings. HTTP Status Code: {domain_endings_response.status_code}"
            )

    return set()


# =============================================================================
# VERSION FUNCTIONS - Mastodon Version Retrieval
# =============================================================================


def read_main_version_info(url):
    """Parse Mastodon version.rb file to extract version information."""
    version_info = {}
    try:
        response = get_httpx(url, http_client)
        response.raise_for_status()
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


def get_highest_mastodon_version():
    """Get the highest stable Mastodon release version from GitHub."""
    highest_version = None
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
                    release_version
                ) > version.parse(highest_version):
                    highest_version = release_version
    except httpx.HTTPError as exception:
        vmc_output(f"Failed to retrieve Mastodon release version: {exception}", "red")
        return None

    return highest_version


def get_backport_mastodon_versions():
    """Get the latest version for each backport branch from GitHub."""
    url = "https://api.github.com/repos/mastodon/mastodon/releases"

    backport_versions = {branch: "" for branch in backport_branches}

    response = get_httpx(url, http_client)
    response.raise_for_status()
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


def get_nightly_version_ranges():
    """Get nightly version ranges from the database."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT version, start_date, end_date
            FROM nightly_versions
            ORDER BY start_date DESC
        """
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


def clean_version(software_version_full, nightly_version_ranges):
    """Apply all version cleaning transformations."""
    software_version = clean_version_suffix(software_version_full)
    software_version = clean_version_oddstring(software_version)
    software_version = clean_version_dumbstring(software_version)
    software_version = clean_version_date(software_version)
    software_version = clean_version_suffix_more(software_version)
    software_version = clean_version_hometown(software_version)
    software_version = clean_version_development(software_version)
    software_version = clean_version_wrongpatch(software_version)
    software_version = clean_version_doubledash(software_version)
    software_version = clean_version_nightly(software_version, nightly_version_ranges)
    software_version = clean_version_main_missing_prerelease(software_version)
    software_version = clean_version_release_with_prerelease(software_version)
    software_version = clean_version_strip_incorrect_prerelease(software_version)
    return software_version


def clean_version_suffix(software_version_full):
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


def clean_version_suffix_more(software_version):
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


def clean_version_dumbstring(software_version):
    """Remove known unwanted strings from versions."""
    unwanted_strings = ["-pre", "-theconnector", "-theatlsocial"]
    for unwanted_string in unwanted_strings:
        software_version = software_version.replace(unwanted_string, "")
    return software_version


def clean_version_oddstring(software_version):
    """Replace known typos in version strings."""
    if "mastau" in software_version:
        software_version = software_version.replace("mastau", "alpha")
    return software_version


def clean_version_date(software_version):
    """Convert date-based suffixes to nightly format."""
    match = re.search(r"-(\d{2})(\d{2})(\d{2})$", software_version)
    if match:
        yy, mm, dd = match.groups()
        formatted_date = f"-nightly.20{yy}-{mm}-{dd}"
        return re.sub(r"-(\d{6})$", formatted_date, software_version)
    return software_version


def clean_version_development(software_version):
    """Normalize development version formats (rc, beta)."""
    patterns = {r"rc(\d+)": r"-rc.\1", r"beta(\d+)": r"-beta.\1"}
    for pattern, replacement in patterns.items():
        software_version = re.sub(pattern, replacement, software_version)
    return software_version


def clean_version_hometown(software_version):
    """Map Hometown version numbers to corresponding Mastodon versions."""
    if software_version == "1.0.6":
        software_version = "3.5.3"
    elif software_version == "1.0.7":
        software_version = "3.5.5"
    elif software_version == "3.4.6ht":
        software_version = "3.4.6"
    return software_version


def clean_version_doubledash(software_version):
    """Fix double dashes and trailing dashes in version strings."""
    if "--" in software_version:
        software_version = software_version.replace("--", "-")
    if software_version.endswith("-"):
        software_version = software_version[:-1]
    return software_version


def clean_version_wrongpatch(software_version):
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
            elif y == m:
                if z != 0:
                    z = 0
                    return f"{x}.{y}.{z}{additional_data or ''}"
                return software_version
            else:
                return software_version
        else:
            return software_version
    else:
        return software_version


def clean_version_nightly(software_version, nightly_version_ranges):
    """Map nightly versions to their corresponding release versions."""
    software_version = re.sub(r"-nightly-\d{8}", "", software_version)

    match = re.match(
        r"4\.[3456]\.0-nightly\.(\d{4}-\d{2}-\d{2})(-security)?", software_version
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


def clean_version_main_missing_prerelease(software_version):
    """Add missing prerelease suffix to main branch versions."""
    if software_version.startswith(version_main_branch) and "-" not in software_version:
        software_version = f"{software_version}-alpha.1"
    return software_version


def clean_version_release_with_prerelease(software_version):
    """Strip prerelease suffix from stable release versions."""
    if (
        version_latest_release
        and software_version.startswith(version_latest_release)
        and "-" in software_version
        and not version_latest_release.endswith(".0")
    ):
        software_version = software_version.split("-")[0]
    return software_version


def clean_version_strip_incorrect_prerelease(software_version):
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
            zip(version_backport_releases, backport_branches)
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


def log_error(domain, error_to_print):
    """Log an error for a domain to the error_log table."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                cursor.execute(
                    """
                    INSERT INTO error_log (domain, error)
                    VALUES (%s, %s)
                """,
                    (domain, error_to_print),
                )
                conn.commit()
            except Exception as exception:
                vmc_output(
                    f"{domain}: Failed to log error {exception}", "red", use_tqdm=True
                )
                conn.rollback()


def increment_domain_error(domain, error_reason):
    """Increment error count for a domain and record the error reason."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                cursor.execute(
                    "SELECT errors FROM raw_domains WHERE domain = %s", (domain,)
                )
                result = cursor.fetchone()
                if result:
                    current_errors = result[0] if result[0] is not None else 0
                    new_errors = current_errors + 1
                else:
                    new_errors = 1

                cursor.execute(
                    """
                    INSERT INTO raw_domains (domain, failed, ignore, errors, reason, nxdomain, norobots)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT(domain) DO UPDATE SET
                    failed = excluded.failed,
                    ignore = excluded.ignore,
                    errors = excluded.errors,
                    reason = excluded.reason,
                    nxdomain = excluded.nxdomain,
                    norobots = excluded.norobots
                """,
                    (domain, None, None, new_errors, error_reason, None, None),
                )
                conn.commit()
            except Exception as exception:
                vmc_output(
                    f"{domain}: Failed to increment domain error {exception}",
                    "red",
                    use_tqdm=True,
                )
                conn.rollback()


def clear_domain_error(domain):
    """Clear all error flags for a domain."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                cursor.execute(
                    """
                    INSERT INTO raw_domains (domain, failed, ignore, errors, reason, nxdomain, norobots)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT(domain) DO UPDATE SET
                    failed = excluded.failed,
                    ignore = excluded.ignore,
                    errors = excluded.errors,
                    reason = excluded.reason,
                    nxdomain = excluded.nxdomain,
                    norobots = excluded.norobots
                """,
                    (domain, None, None, None, None, None, None),
                )
                conn.commit()
            except Exception as exception:
                vmc_output(
                    f"{domain}: Failed to clear domain errors {exception}",
                    "red",
                    use_tqdm=True,
                )
                conn.rollback()


def delete_if_error_max(domain):
    """Delete domain from known domains if error threshold is exceeded."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                cursor.execute(
                    "SELECT errors FROM raw_domains WHERE domain = %s", (domain,)
                )
                result = cursor.fetchone()
                if result and result[0] >= error_threshold:
                    cursor.execute(
                        "SELECT timestamp FROM mastodon_domains WHERE domain = %s",
                        (domain,),
                    )
                    timestamp = cursor.fetchone()
                    if (
                        timestamp
                        and (
                            datetime.now(timezone.utc)
                            - timestamp[0].replace(tzinfo=timezone.utc)
                        ).days
                        >= error_threshold
                    ):
                        delete_domain_if_known(domain)

            except Exception as exception:
                vmc_output(
                    f"{domain}: Failed to delete maxed out domain {exception}",
                    "red",
                    use_tqdm=True,
                )
                conn.rollback()


# =============================================================================
# DATABASE FUNCTIONS - Domain Status Marking
# =============================================================================


def mark_ignore_domain(domain):
    """Mark a domain as ignored (non-Mastodon platform)."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                cursor.execute(
                    """
                    INSERT INTO raw_domains (domain, failed, ignore, errors, reason, nxdomain, norobots)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT(domain) DO UPDATE SET
                    failed = excluded.failed,
                    ignore = excluded.ignore,
                    errors = excluded.errors,
                    reason = excluded.reason,
                    nxdomain = excluded.nxdomain,
                    norobots = excluded.norobots
                """,
                    (domain, None, True, None, None, None, None),
                )
                conn.commit()
            except Exception as exception:
                vmc_output(f"Failed to mark domain ignored: {exception}", "red")
                conn.rollback()


def mark_failed_domain(domain):
    """Mark a domain as failed (authentication required)."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                cursor.execute(
                    """
                    INSERT INTO raw_domains (domain, failed, ignore, errors, reason, nxdomain, norobots)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT(domain) DO UPDATE SET
                    failed = excluded.failed,
                    ignore = excluded.ignore,
                    errors = excluded.errors,
                    reason = excluded.reason,
                    nxdomain = excluded.nxdomain,
                    norobots = excluded.norobots
                """,
                    (domain, True, None, None, None, None, None),
                )
                conn.commit()
            except Exception as exception:
                vmc_output(f"Failed to mark domain failed: {exception}", "red")
                conn.rollback()


def mark_nxdomain_domain(domain):
    """Mark a domain as NXDOMAIN (gone/not found)."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                cursor.execute(
                    """
                    INSERT INTO raw_domains (domain, failed, ignore, errors, reason, nxdomain, norobots)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT(domain) DO UPDATE SET
                    failed = excluded.failed,
                    ignore = excluded.ignore,
                    errors = excluded.errors,
                    reason = excluded.reason,
                    nxdomain = excluded.nxdomain,
                    norobots = excluded.norobots
                """,
                    (domain, None, None, None, None, True, None),
                )
                conn.commit()
            except Exception as exception:
                vmc_output(f"Failed to mark domain NXDOMAIN: {exception}", "red")
                conn.rollback()


def mark_norobots_domain(domain):
    """Mark a domain as norobots (crawling prohibited)."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                cursor.execute(
                    """
                    INSERT INTO raw_domains (domain, failed, ignore, errors, reason, nxdomain, norobots)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT(domain) DO UPDATE SET
                    failed = excluded.failed,
                    ignore = excluded.ignore,
                    errors = excluded.errors,
                    reason = excluded.reason,
                    nxdomain = excluded.nxdomain,
                    norobots = excluded.norobots
                """,
                    (domain, None, None, None, None, None, True),
                )
                conn.commit()
            except Exception as exception:
                vmc_output(f"Failed to mark domain NoRobots: {exception}", "red")
                conn.rollback()


# =============================================================================
# DATABASE FUNCTIONS - Domain CRUD Operations
# =============================================================================


def delete_domain_if_known(domain):
    """Delete a domain from the mastodon_domains table."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                cursor.execute(
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


def delete_domain_from_raw(domain):
    """Delete a domain from the raw_domains table."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                cursor.execute(
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


def update_mastodon_domain(
    actual_domain,
    software_version,
    software_version_full,
    total_users,
    active_month_users,
    contact_account,
    source_url,
):
    """Insert or update a Mastodon domain in the database."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                cursor.execute(
                    """
                    INSERT INTO mastodon_domains
                    (domain, software_version, total_users, active_users_monthly, timestamp, contact, source, full_version)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT(domain) DO UPDATE SET
                    software_version = excluded.software_version,
                    total_users = excluded.total_users,
                    active_users_monthly = excluded.active_users_monthly,
                    timestamp = excluded.timestamp,
                    contact = excluded.contact,
                    source = excluded.source,
                    full_version = excluded.full_version
                """,
                    (
                        actual_domain,
                        software_version,
                        total_users,
                        active_month_users,
                        datetime.now(timezone.utc),
                        contact_account,
                        source_url,
                        software_version_full,
                    ),
                )
                conn.commit()
            except Exception as exception:
                vmc_output(f"{actual_domain}: {exception}", "red", use_tqdm=True)
                conn.rollback()


def cleanup_old_domains():
    """Delete known domains older than 1 week."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                cursor.execute(
                    """
                    DELETE FROM mastodon_domains
                    WHERE timestamp <= (CURRENT_TIMESTAMP - INTERVAL '1 week') AT TIME ZONE 'UTC'
                    RETURNING domain
                    """
                )
                deleted_domains = [row[0] for row in cursor.fetchall()]
                if deleted_domains:
                    for d in deleted_domains:
                        vmc_output(
                            f"{d}: Removed from known domains", "pink", use_tqdm=True
                        )
                conn.commit()
            except Exception as exception:
                vmc_output(f"Failed to clean up old domains: {exception}", "red")
                conn.rollback()


# =============================================================================
# DATABASE FUNCTIONS - Domain List Retrieval
# =============================================================================


def get_junk_keywords():
    """Get list of junk keywords to filter domains."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                cursor.execute("SELECT keywords FROM junk_words")
                # Use set for O(1) lookup instead of O(n) list iteration
                return {row[0] for row in cursor}
            except Exception as exception:
                vmc_output(f"Failed to obtain junk keywords: {exception}", "red")
                conn.rollback()
    return set()


def get_bad_tld():
    """Get list of prohibited TLDs."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                cursor.execute("SELECT tld FROM bad_tld")
                # Use set for O(1) lookup
                return {row[0] for row in cursor}
            except Exception as exception:
                vmc_output(f"Failed to obtain bad TLDs: {exception}", "red")
                conn.rollback()
    return set()


def get_failed_domains():
    """Get list of domains marked as failed."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                cursor.execute("SELECT domain FROM raw_domains WHERE failed = TRUE")
                # Use set for O(1) lookup, stream results
                return {row[0].strip() for row in cursor if row[0] and row[0].strip()}
            except Exception as exception:
                vmc_output(f"Failed to obtain failed domains: {exception}", "red")
                conn.rollback()
    return set()


def get_ignored_domains():
    """Get list of domains marked as ignored."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                cursor.execute("SELECT domain FROM raw_domains WHERE ignore = TRUE")
                # Use set for O(1) lookup, stream results
                return {row[0].strip() for row in cursor if row[0] and row[0].strip()}
            except Exception as exception:
                vmc_output(f"Failed to obtain ignored domains: {exception}", "red")
                conn.rollback()
    return set()


def get_baddata_domains():
    """Get list of domains marked as having bad data."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                cursor.execute("SELECT domain FROM raw_domains WHERE baddata = TRUE")
                # Use set for O(1) lookup, stream results
                return {row[0].strip() for row in cursor if row[0] and row[0].strip()}
            except Exception as exception:
                vmc_output(f"Failed to obtain baddata domains: {exception}", "red")
                conn.rollback()
    return set()


def get_nxdomain_domains():
    """Get list of domains marked as NXDOMAIN."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                cursor.execute("SELECT domain FROM raw_domains WHERE nxdomain = TRUE")
                # Use set for O(1) lookup, stream results
                return {row[0].strip() for row in cursor if row[0] and row[0].strip()}
            except Exception as exception:
                vmc_output(f"Failed to obtain NXDOMAIN domains: {exception}", "red")
                conn.rollback()
    return set()


def get_norobots_domains():
    """Get list of domains that prohibit crawling."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                cursor.execute("SELECT domain FROM raw_domains WHERE norobots = TRUE")
                # Use set for O(1) lookup, stream results
                return {row[0].strip() for row in cursor if row[0] and row[0].strip()}
            except Exception as exception:
                vmc_output(f"Failed to obtain NoRobots domains: {exception}", "red")
                conn.rollback()
    return set()


# =============================================================================
# ERROR HANDLING FUNCTIONS
# =============================================================================


def handle_incorrect_file_type(domain, target, content_type):
    """Handle responses with incorrect content type."""
    if content_type == "" or content_type is None:
        content_type = "missing Content-Type"
    clean_content_type = re.sub(r";.*$", "", content_type).strip()
    error_message = f"{target} is {clean_content_type}"
    vmc_output(f"{domain}: {error_message}", "yellow", use_tqdm=True)
    log_error(domain, error_message)
    increment_domain_error(domain, f"TYPE+{target}")
    delete_if_error_max(domain)


def handle_http_status_code(domain, target, response):
    """Handle non-fatal HTTP status codes."""
    code = response.status_code
    error_message = f"HTTP {code} on {target}"
    vmc_output(f"{domain}: {error_message}", "yellow", use_tqdm=True)
    log_error(domain, error_message)
    increment_domain_error(domain, code)
    delete_if_error_max(domain)


def handle_http_failed(domain, target, response):
    """Handle HTTP 401/403 on auth endpoints and 410/418 generally."""
    code = response.status_code
    error_message = f"HTTP {code} on {target}"
    vmc_output(f"{domain}: {error_message}", "orange", use_tqdm=True)
    mark_failed_domain(domain)
    delete_domain_if_known(domain)


def handle_tcp_exception(domain, exception):
    """Handle TCP/connection exceptions with appropriate categorization."""
    error_message = str(exception)

    # Handle response size violations
    if isinstance(exception, ValueError) and "too large" in error_message.casefold():
        error_reason = "SIZE"
        vmc_output(
            f"{domain}: Response too large (memory protection)", "orange", use_tqdm=True
        )
        log_error(domain, "Response exceeds size limit")
        increment_domain_error(domain, error_reason)
        delete_if_error_max(domain)
        return

    # Handle bad file descriptor (usually from cancellation/cleanup issues)
    if "bad file descriptor" in error_message.casefold():
        error_reason = "FD"
        vmc_output(f"{domain}: Connection closed unexpectedly", "yellow", use_tqdm=True)
        log_error(domain, "Bad file descriptor")
        increment_domain_error(domain, error_reason)
        delete_if_error_max(domain)
        return

    if "_ssl.c" in error_message.casefold():
        error_reason = "SSL"
        error_message = (
            re.sub(r"\s*(\[[^\]]*\]|\([^)]*\))", "", error_message)
            .replace(":", "")
            .replace(",", "")
            .split(" for ", 1)[0]
            .lstrip()
            .rstrip(" .")
        )
        vmc_output(f"{domain}: {error_message}", "yellow", use_tqdm=True)
        log_error(domain, error_message)
        increment_domain_error(domain, error_reason)
        delete_if_error_max(domain)
    elif "maximum allowed redirects" in error_message.casefold():
        error_reason = "MAX"
        error_message = error_message.strip(".")
        vmc_output(f"{domain}: {error_message}", "yellow", use_tqdm=True)
        log_error(domain, error_message)
        increment_domain_error(domain, error_reason)
        delete_if_error_max(domain)
    elif any(
        msg in error_message.casefold()
        for msg in [
            "nodename nor servname provided",
            "name or service not known",
        ]
    ):
        error_message = (
            re.sub(r"\s*(\[[^\]]*\]|\([^)]*\))", "", error_message)
            .replace(":", "")
            .replace(",", "")
            .split(" for ", 1)[0]
            .lstrip()
            .rstrip(" .")
        )
        vmc_output(f"{domain}: {error_message}", "orange", use_tqdm=True)
        mark_nxdomain_domain(domain)
        delete_domain_if_known(domain)
    elif any(
        msg in error_message.casefold()
        for msg in [
            "no address associated with hostname",
            "temporary failure in name resolution",
            "address family not supported",
        ]
    ):
        error_reason = "DNS"
        error_message = (
            re.sub(r"\s*(\[[^\]]*\]|\([^)]*\))", "", error_message)
            .replace(":", "")
            .replace(",", "")
            .split(" for ", 1)[0]
            .lstrip()
            .rstrip(" .")
        )
        vmc_output(f"{domain}: {error_message}", "yellow", use_tqdm=True)
        log_error(domain, error_message)
        increment_domain_error(domain, error_reason)
        delete_if_error_max(domain)
    elif any(
        msg in error_message.casefold()
        for msg in [
            "timed out",
            "connection reset by peer",
            "network is unreachable",
            "connection refused",
            "could not connect to host",
            "no route to host",
            "streamreset",
            "server disconnected",
        ]
    ):
        error_reason = "TCP"
        if "streamreset" in error_message.casefold():
            error_message = "HTTP/2 stream was abruptly terminated"
        error_message = (
            re.sub(r"\s*(\[[^\]]*\]|\([^)]*\))", "", error_message)
            .replace(":", "")
            .replace(",", "")
            .split(" for ", 1)[0]
            .lstrip()
            .rstrip(" .")
        )
        vmc_output(f"{domain}: {error_message}", "yellow", use_tqdm=True)
        log_error(domain, error_message)
        increment_domain_error(domain, error_reason)
        delete_if_error_max(domain)
    else:
        error_reason = "HTTP"
        error_message = (
            re.sub(r"\s*(\[[^\]]*\]|\([^)]*\))", "", error_message)
            .replace(":", "")
            .replace(",", "")
            .split(" for ", 1)[0]
            .lstrip()
            .rstrip(" .")
        )
        vmc_output(f"{domain}: {error_message}", "yellow", use_tqdm=True)
        log_error(domain, error_message)
        increment_domain_error(domain, error_reason)
        delete_if_error_max(domain)


def handle_json_exception(domain, target, exception):
    """Handle JSON parsing exceptions."""
    error_message = str(exception)
    error_reason = f"JSON+{target}"
    vmc_output(f"{domain}: {target} {error_message}", "yellow", use_tqdm=True)
    log_error(domain, error_message)
    increment_domain_error(domain, error_reason)
    delete_if_error_max(domain)


# =============================================================================
# DOMAIN PROCESSING - Validation and Filtering
# =============================================================================


def should_skip_domain(
    domain,
    ignored_domains,
    baddata_domains,
    failed_domains,
    nxdomain_domains,
    norobots_domains,
    user_choice,
):
    """Check if a domain should be skipped based on its status."""
    if user_choice != "6" and domain in ignored_domains:
        vmc_output(f"{domain}: Other Platform", "cyan", use_tqdm=True)
        delete_domain_if_known(domain)
        return True
    if user_choice != "7" and domain in failed_domains:
        vmc_output(
            f"{domain}: Authentication Required (401/403)", "cyan", use_tqdm=True
        )
        delete_domain_if_known(domain)
        return True
    if user_choice != "8" and domain in nxdomain_domains:
        vmc_output(f"{domain}: Hard Failed (418/410)", "cyan", use_tqdm=True)
        delete_domain_if_known(domain)
        return True
    if user_choice != "9" and domain in norobots_domains:
        vmc_output(f"{domain}: Crawling Prohibited", "cyan", use_tqdm=True)
        delete_domain_if_known(domain)
        return True
    if domain in baddata_domains:
        vmc_output(f"{domain}: Bad Domain", "cyan", use_tqdm=True)
        delete_domain_if_known(domain)
        return True
    return False


def is_junk_or_bad_tld(domain, junk_domains, bad_tlds, domain_endings):
    """Check if a domain is junk or has a prohibited TLD."""
    if any(junk in domain for junk in junk_domains):
        vmc_output(f"{domain}: Purging known junk domain", "cyan", use_tqdm=True)
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


def check_robots_txt(domain, http_client):
    """Check robots.txt to ensure crawling is allowed."""
    target = "robots_txt"
    url = f"https://{domain}/robots.txt"
    try:
        response = get_httpx(url, http_client)
        if response.status_code in [200]:
            content_type = response.headers.get("Content-Type", "")
            if (
                content_type in mimetypes.types_map.values()
                and not content_type.startswith("text/")
            ):
                handle_incorrect_file_type(domain, target, content_type)
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
                            f"{domain}: Crawling Prohibited", "orange", use_tqdm=True
                        )
                        mark_norobots_domain(domain)
                        delete_domain_if_known(domain)
                        return False
        elif response.status_code in http_codes_to_hardfail:
            handle_http_failed(domain, target, response)
            return False
    except httpx.RequestError as exception:
        handle_tcp_exception(domain, exception)
        return False
    return True


def check_webfinger(domain, http_client):
    """Check WebFinger endpoint for backend domain discovery."""
    target = "webfinger"
    url = f"https://{domain}/.well-known/webfinger?resource=acct:{domain}@{domain}"
    try:
        response = get_httpx(url, http_client)
        content_type = response.headers.get("Content-Type", "")
        content_length = response.headers.get("Content-Length", "")
        if response.status_code in [200]:
            if "json" not in content_type:
                handle_incorrect_file_type(domain, target, content_type)
                return False
            if not response.content or content_length == "0":
                return None
            try:
                data = response.json()
            except json.JSONDecodeError:
                try:
                    decoder = json.JSONDecoder()
                    data, _ = decoder.raw_decode(response.text, 0)
                except json.JSONDecodeError as exception:
                    handle_json_exception(domain, target, exception)
                    return False
            aliases = data.get("aliases", [])
            if not aliases:
                return None
            first_alias = next((alias for alias in aliases if "https" in alias), None)
            if first_alias:
                backend_domain = urlparse(first_alias).netloc
                if "localhost" in backend_domain:
                    return None
                return {"backend_domain": backend_domain}
            else:
                return None
        elif response.status_code in http_codes_to_hardfail:
            handle_http_failed(domain, target, response)
            return False
    except httpx.RequestError as exception:
        handle_tcp_exception(domain, exception)
        return False
    except json.JSONDecodeError as exception:
        handle_json_exception(domain, target, exception)
        return False
    return None


def check_nodeinfo(domain, backend_domain, http_client):
    """Check NodeInfo well-known endpoint for NodeInfo 2.0 URL."""
    target = "nodeinfo"
    url = f"https://{backend_domain}/.well-known/nodeinfo"
    try:
        response = get_httpx(url, http_client)
        if response.status_code in [200]:
            content_type = response.headers.get("Content-Type", "")
            if "json" not in content_type:
                handle_incorrect_file_type(domain, target, content_type)
                return False
            if not response.content:
                exception = "reply is empty"
                handle_json_exception(domain, target, exception)
                return False
            else:
                try:
                    data = response.json()
                except json.JSONDecodeError:
                    try:
                        decoder = json.JSONDecoder()
                        data, _ = decoder.raw_decode(response.text, 0)
                    except json.JSONDecodeError as exception:
                        handle_json_exception(domain, target, exception)
                        return False
            links = data.get("links")
            if links is not None and len(links) == 0:
                exception = "empty links array in reply"
                handle_json_exception(domain, target, exception)
                return False
            if links:
                nodeinfo_20_url = None
                for i, link in enumerate(links):
                    rel_value = link.get("rel", "")
                    type_value = link.get("type", "")
                    href_value = link.get("href", "")
                    if (
                        "nodeinfo.diaspora.software/ns/schema/" in rel_value
                        or "nodeinfo.diaspora.software/ns/schema/" in type_value
                        or "/nodeinfo/" in href_value
                    ):
                        if "href" in link:
                            nodeinfo_20_url = link["href"]
                            break
                        elif (
                            i + 1 < len(links)
                            and "href" in links[i + 1]
                            and "rel" not in links[i + 1]
                        ):
                            nodeinfo_20_url = links[i + 1]["href"]
                            break

                if nodeinfo_20_url:
                    return {"nodeinfo_20_url": nodeinfo_20_url}

            exception = "no links in reply"
            handle_json_exception(domain, target, exception)
            return False
        elif response.status_code in http_codes_to_hardfail:
            handle_http_failed(domain, target, response)
            return False
        else:
            handle_http_status_code(domain, target, response)
    except httpx.RequestError as exception:
        handle_tcp_exception(domain, exception)
    except json.JSONDecodeError as exception:
        handle_json_exception(domain, target, exception)
    return None


def check_nodeinfo_20(domain, nodeinfo_20_url, http_client):
    """Fetch and parse NodeInfo 2.0 data."""
    target = "nodeinfo_20"
    try:
        response = get_httpx(nodeinfo_20_url, http_client)
        if response.status_code in [200]:
            content_type = response.headers.get("Content-Type", "")
            if "json" not in content_type:
                handle_incorrect_file_type(domain, target, content_type)
                return False
            if not response.content:
                exception = "reply empty"
                handle_json_exception(domain, target, exception)
                return False
            else:
                try:
                    nodeinfo_20_result = response.json()
                except json.JSONDecodeError:
                    try:
                        decoder = json.JSONDecoder()
                        nodeinfo_20_result, _ = decoder.raw_decode(response.text, 0)
                    except json.JSONDecodeError as exception:
                        handle_json_exception(domain, target, exception)
                        return False
                return nodeinfo_20_result
        elif response.status_code in http_codes_to_hardfail:
            handle_http_failed(domain, target, response)
            return False
        else:
            handle_http_status_code(domain, target, response)
    except httpx.RequestError as exception:
        handle_tcp_exception(domain, exception)
        return False
    except json.JSONDecodeError as exception:
        handle_json_exception(domain, target, exception)
        return False
    return None


# =============================================================================
# DOMAIN PROCESSING - Instance Processing
# =============================================================================


def is_mastodon_instance(nodeinfo_20_result: dict) -> bool:
    """Check if the NodeInfo response indicates a Mastodon-compatible instance."""
    if not isinstance(nodeinfo_20_result, dict):
        return False

    software = nodeinfo_20_result.get("software")
    if software is None:
        return False

    software_name = software.get("name")
    if software_name is None:
        return False

    return software_name.lower() in {"mastodon", "hometown", "kmyblue", "glitchcafe"}


def mark_as_non_mastodon(domain, other_platform):
    """Mark a domain as a non-Mastodon platform."""
    if not other_platform:
        other_platform = "Unknown Platform"
    vmc_output(f"{domain}: {other_platform}", "cyan", use_tqdm=True)
    mark_ignore_domain(domain)
    delete_domain_if_known(domain)


def process_mastodon_instance(
    domain, backend_domain, nodeinfo_20_result, http_client, nightly_version_ranges
):
    """Process a confirmed Mastodon instance and update the database."""
    software_name = nodeinfo_20_result["software"]["name"].lower()
    software_version_full = nodeinfo_20_result["software"]["version"]
    software_version = clean_version(
        nodeinfo_20_result["software"]["version"], nightly_version_ranges
    )

    users = nodeinfo_20_result.get("usage", {}).get("users", {})
    if not users:
        error_to_print = "No usage data in NodeInfo"
        vmc_output(f"{domain}: {error_to_print}", "yellow", use_tqdm=True)
        log_error(domain, error_to_print)
        increment_domain_error(domain, "###")
        delete_domain_if_known(domain)
        return

    required_fields = [
        ("total", "No user data in NodeInfo"),
        ("activeMonth", "No MAU data in NodeInfo"),
    ]

    for field, error_msg in required_fields:
        if field not in users:
            vmc_output(f"{domain}: {error_msg}", "yellow", use_tqdm=True)
            log_error(domain, error_msg)
            increment_domain_error(domain, "###")
            delete_domain_if_known(domain)
            return

    total_users = users["total"]
    active_month_users = users["activeMonth"]

    if software_version.startswith("4"):
        instance_api_url = f"https://{backend_domain}/api/v2/instance"
    else:
        instance_api_url = f"https://{backend_domain}/api/v1/instance"

    target = "instance_api"
    try:
        response = get_httpx(instance_api_url, http_client)
        if response.status_code in [200]:
            content_type = response.headers.get("Content-Type", "")
            if not response.content:
                error_message = "reply is empty"
                vmc_output(
                    f"{domain}: {target} {error_message}", "yellow", use_tqdm=True
                )
                log_error(domain, f"{target} {error_message}")
                handle_json_exception(domain, target, error_message)
                return False
            elif "json" not in content_type:
                handle_incorrect_file_type(domain, target, content_type)
                return False

            try:
                response_json = response.json()
            except json.JSONDecodeError:
                try:
                    decoder = json.JSONDecoder()
                    response_json, _ = decoder.raw_decode(response.text, 0)
                except json.JSONDecodeError as exception:
                    handle_json_exception(domain, target, exception)
                    return False

            if "error" in response_json:
                error_message = "returned an error"
                vmc_output(
                    f"{domain}: {target} {error_message}", "yellow", use_tqdm=True
                )
                log_error(domain, f"{target} {error_message}")
                handle_json_exception(domain, target, error_message)
                return False
            else:
                instance_api_data = response_json

            if software_version.startswith("4"):
                actual_domain = instance_api_data["domain"].lower()
                if "email" in instance_api_data["contact"]:
                    contact_account = normalize_email(
                        instance_api_data["contact"]["email"]
                    ).lower()
                else:
                    contact_account = None
                if "source_url" in instance_api_data:
                    source_url = instance_api_data["source_url"]
                else:
                    source_url = None
            else:
                actual_domain = instance_api_data["uri"].lower()
                if "email" in instance_api_data:
                    contact_account = normalize_email(
                        instance_api_data["email"]
                    ).lower()
                else:
                    contact_account = None
                source_url = None

            if not is_valid_email(contact_account):
                contact_account = None

            if source_url:
                source_url = limit_url_depth(source_url)

            if source_url == "/source.tar.gz":
                source_url = f"https://{actual_domain}{source_url}"

            if software_name == "hometown":
                source_url = "https://github.com/hometown-fork/hometown"

            if actual_domain == "gc2.jp":
                source_url = "https://github.com/gc2-jp/freespeech"

            if version.parse(software_version.split("-")[0]) > version.parse(
                version_main_branch
            ):
                error_to_print = "Mastodon version invalid"
                vmc_output(f"{domain}: {error_to_print}", "yellow", use_tqdm=True)
                log_error(domain, error_to_print)
                increment_domain_error(domain, "###")
                delete_domain_if_known(domain)
                return

            update_mastodon_domain(
                actual_domain,
                software_version,
                software_version_full,
                total_users,
                active_month_users,
                contact_account,
                source_url,
            )

            clear_domain_error(domain)

            version_info = f"Mastodon v{software_version}"
            if software_version != nodeinfo_20_result["software"]["version"]:
                version_info = (
                    f"{version_info} ({nodeinfo_20_result['software']['version']})"
                )
            vmc_output(f"{domain}: {version_info}", "green", use_tqdm=True)
        elif response.status_code in http_codes_to_authfail:
            handle_http_failed(domain, target, response)
            return False
        elif response.status_code in http_codes_to_hardfail:
            handle_http_failed(domain, target, response)
            return None
        else:
            handle_http_status_code(domain, target, response)
    except httpx.RequestError as exception:
        handle_tcp_exception(domain, exception)
    except json.JSONDecodeError as exception:
        handle_json_exception(domain, target, exception)


def process_domain(domain, http_client, nightly_version_ranges):
    """Main processing pipeline for a single domain."""
    if not check_robots_txt(domain, http_client):
        return

    webfinger_result = check_webfinger(domain, http_client)
    if webfinger_result is False:
        return
    if not webfinger_result:
        backend_domain = domain
    else:
        backend_domain = webfinger_result["backend_domain"]

    nodeinfo_result = check_nodeinfo(domain, backend_domain, http_client)
    if nodeinfo_result is False:
        return
    if not nodeinfo_result:
        return

    nodeinfo_20_result = check_nodeinfo_20(
        domain, nodeinfo_result["nodeinfo_20_url"], http_client
    )
    if nodeinfo_20_result is False:
        return
    if not nodeinfo_20_result:
        return

    if is_mastodon_instance(nodeinfo_20_result):
        process_mastodon_instance(
            domain,
            backend_domain,
            nodeinfo_20_result,
            http_client,
            nightly_version_ranges,
        )
    else:
        mark_as_non_mastodon(domain, nodeinfo_20_result["software"]["name"])


# =============================================================================
# DOMAIN PROCESSING - Batch Processing
# =============================================================================


def check_and_record_domains(
    domain_list,
    ignored_domains,
    baddata_domains,
    failed_domains,
    user_choice,
    junk_domains,
    bad_tlds,
    domain_endings,
    http_client,
    nxdomain_domains,
    norobots_domains,
    nightly_version_ranges,
):
    """Process a list of domains concurrently with progress tracking."""
    max_workers = int(os.getenv("VMCRAWL_MAX_THREADS", "2"))
    shutdown_event = threading.Event()

    # Thread-local storage for HTTP clients to avoid contention
    thread_local = threading.local()

    def get_thread_http_client():
        """Get or create a thread-local HTTP client."""
        if not hasattr(thread_local, "http_client"):
            thread_local.http_client = httpx.Client(
                http2=True,
                follow_redirects=True,
                headers=http_custom_headers,
                timeout=common_timeout,
                limits=limits,
                max_redirects=10,
            )
        return thread_local.http_client

    def process_single_domain(domain):
        if shutdown_event.is_set():
            return

        if should_skip_domain(
            domain,
            ignored_domains,
            baddata_domains,
            failed_domains,
            nxdomain_domains,
            norobots_domains,
            user_choice,
        ):
            return

        if is_junk_or_bad_tld(domain, junk_domains, bad_tlds, domain_endings):
            return

        try:
            # Use thread-local HTTP client instead of shared one
            client = get_thread_http_client()
            process_domain(domain, client, nightly_version_ranges)
        except httpx.CloseError:
            pass
        except Exception as exception:
            if not shutdown_event.is_set():
                handle_tcp_exception(domain, exception)

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

        # Clean up thread-local HTTP clients
        if hasattr(thread_local, "http_client"):
            try:
                thread_local.http_client.close()
            except Exception:
                pass


# =============================================================================
# DATA LOADING FUNCTIONS
# =============================================================================


def load_from_database(user_choice):
    """Load domain list from database based on user menu selection."""
    query_map = {
        "0": "SELECT domain FROM raw_domains WHERE errors = 0 ORDER BY LENGTH(DOMAIN) ASC",
        "1": "SELECT domain FROM raw_domains WHERE (failed IS NULL OR failed = FALSE) AND (ignore IS NULL OR ignore = FALSE) AND (nxdomain IS NULL OR nxdomain = FALSE) AND (norobots IS NULL OR norobots = FALSE) AND (baddata IS NULL OR baddata = FALSE) AND (errors <= %s OR errors IS NULL) ORDER BY domain ASC",
        "6": "SELECT domain FROM raw_domains WHERE ignore = TRUE ORDER BY domain",
        "7": "SELECT domain FROM raw_domains WHERE failed = TRUE ORDER BY domain",
        "8": "SELECT domain FROM raw_domains WHERE nxdomain = TRUE ORDER BY domain",
        "9": "SELECT domain FROM raw_domains WHERE norobots = TRUE ORDER BY domain",
        "10": "SELECT domain FROM raw_domains WHERE reason = 'SSL' ORDER BY errors ASC",
        "11": "SELECT domain FROM raw_domains WHERE reason = 'HTTP' ORDER BY errors ASC",
        "12": "SELECT domain FROM raw_domains WHERE reason IN ('TIMEOUT', 'TIME', 'TCP') ORDER BY errors ASC",
        "13": "SELECT domain FROM raw_domains WHERE reason = 'MAX' ORDER BY errors ASC",
        "14": "SELECT domain FROM raw_domains WHERE reason = 'DNS' ORDER BY errors ASC",
        "20": "SELECT domain FROM raw_domains WHERE reason ~ '^2[0-9]{2}' ORDER BY errors ASC",
        "21": "SELECT domain FROM raw_domains WHERE reason ~ '^3[0-9]{2}' ORDER BY errors ASC",
        "22": "SELECT domain FROM raw_domains WHERE reason ~ '^4[0-9]{2}' ORDER BY errors ASC",
        "23": "SELECT domain FROM raw_domains WHERE reason ~ '^5[0-9]{2}' ORDER BY errors ASC",
        "30": "SELECT domain FROM raw_domains WHERE reason LIKE '%JSON%' ORDER BY errors ASC",
        "31": "SELECT domain FROM raw_domains WHERE reason LIKE '%TYPE%' ORDER BY errors ASC",
        "40": "SELECT domain FROM mastodon_domains WHERE software_version != ALL(%(versions)s::text[]) ORDER BY active_users_monthly DESC",
        "41": "SELECT domain FROM mastodon_domains WHERE software_version LIKE %s ORDER BY active_users_monthly DESC",
        "42": "SELECT domain FROM mastodon_domains WHERE software_version::TEXT ~ 'alpha|beta|rc' ORDER BY active_users_monthly DESC",
        "43": "SELECT domain FROM mastodon_domains WHERE active_users_monthly = '0' ORDER BY active_users_monthly DESC",
        "44": "SELECT domain FROM mastodon_domains ORDER BY active_users_monthly DESC",
        "45": "SELECT domain FROM raw_domains WHERE reason = '###' ORDER BY errors ASC",
        "46": "SELECT domain FROM mastodon_domains WHERE timestamp <= (CURRENT_TIMESTAMP - INTERVAL '3 days') AT TIME ZONE 'UTC' ORDER BY active_users_monthly DESC",
        "50": "SELECT domain FROM raw_domains WHERE errors > %s ORDER BY errors ASC",
        "51": "SELECT domain FROM raw_domains WHERE errors > %s AND errors < %s ORDER BY errors ASC",
        "52": "SELECT domain FROM raw_domains WHERE errors IS NOT NULL ORDER BY errors ASC",
    }

    if user_choice in ["2", "3"]:
        query = query_map["1"]
        params = [error_buffer]
    else:
        query = query_map.get(user_choice)

        params = []
        if user_choice in ["1"]:
            params = [error_buffer]
        elif user_choice == "50":
            params = [int(error_buffer * 2)]
        elif user_choice == "51":
            params = [error_buffer, int(error_buffer * 2)]
        elif user_choice == "40":
            params = {"versions": all_patched_versions}
            vmc_output("Excluding versions:", "pink")
            for version in params["versions"]:
                vmc_output(f" - {version}", "pink")
        elif user_choice == "41":
            params = [f"{version_main_branch}%"]

    if not query:
        vmc_output(f"Choice {user_choice} is invalid, using default query", "pink")
        query = query_map["1"]
        params = [error_threshold]

    with db_pool.connection() as conn:
        # Use server-side cursor for large result sets to avoid loading all into memory
        with conn.cursor(name="domain_loader") as cursor:
            cursor.itersize = 1000  # Fetch 1000 rows at a time
            try:
                cursor.execute(query, params if params else None)  # type: ignore
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
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            with open(os.path.expanduser(file_name), "r") as file:
                for line in file:
                    domain = line.strip()
                    if not domain or has_emoji_chars(domain):
                        continue

                    domain_list.append(domain)
                    cursor.execute(
                        "SELECT COUNT(*) FROM raw_domains WHERE domain = %s", (domain,)
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


def get_menu_options() -> dict:
    """Return the menu options dictionary."""
    return {
        "Process new domains": {"0": "Recently Fetched"},
        "Change process direction": {"1": "Standard", "2": "Reverse", "3": "Random"},
        "Retry fatal errors": {
            "6": "Ignored",
            "7": "Failed",
            "8": "NXDOMAIN",
            "9": "Prohibited",
        },
        "Retry connection errors": {
            "10": "SSL",
            "11": "HTTP",
            "12": "TCP",
            "13": "MAX",
            "14": "DNS",
        },
        "Retry HTTP errors": {"20": "2xx", "21": "3xx", "22": "4xx", "23": "5xx"},
        "Retry target errors": {
            "30": "JSON",
            "31": "TYPE",
        },
        "Retry known instances": {
            "40": "Unpatched",
            "41": "Main",
            "42": "Development",
            "43": "Inactive",
            "44": "All Good",
            "45": "Misreporting",
            "46": "Stale (3+ days)",
        },
        "Retry general errors": {
            "50": f"Domains w/ >{int(error_buffer * 2)} Errors",
            "51": f"Domains w/ {error_buffer}-{int(error_buffer * 2)} Errors",
            "52": "Domains with any errors",
        },
    }


def print_menu(menu_options: dict | None = None) -> None:
    """Print the text-based menu to stdout."""
    if menu_options is None:
        menu_options = get_menu_options()

    for category, options in menu_options.items():
        options_str = " ".join(f"({key}) {value}" for key, value in options.items())
        vmc_output(f"{category}: ", "cyan", end="")
        vmc_output(options_str, "")
    vmc_output("Enter your choice (1, 2, 3, etc):", "bold", end=" ")
    sys.stdout.flush()


def interactive_select_menu(menu_options: dict) -> str | None:
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

# Error handling configuration
error_threshold = int(common_timeout)
error_buffer = int(os.getenv("VMCRAWL_ERROR_BUFFER", error_threshold))

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
        description="Crawl version information from Mastodon instances."
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
        "-d",
        "--buffer",
        action="store_true",
        help="only process domains which recently reached the error threshold (same as menu item 51)",
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
                vmc_output(
                    f"Crawling domain{'s' if len(domain_list) > 1 else ''} from target argument",
                    "cyan",
                )
            else:
                if args.new:
                    user_choice = "0"
                elif args.buffer:
                    user_choice = "51"
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
                    f"Crawling domains from database choice {user_choice}", "cyan"
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
        bad_tlds = get_bad_tld()
        domain_endings = get_domain_endings()
        failed_domains = get_failed_domains()
        ignored_domains = get_ignored_domains()
        baddata_domains = get_baddata_domains()
        nxdomain_domains = get_nxdomain_domains()
        norobots_domains = get_norobots_domains()
        nightly_version_ranges = get_nightly_version_ranges()

        cleanup_old_domains()

        check_and_record_domains(
            domain_list,
            ignored_domains,
            baddata_domains,
            failed_domains,
            user_choice,
            junk_domains,
            bad_tlds,
            domain_endings,
            http_client,
            nxdomain_domains,
            norobots_domains,
            nightly_version_ranges,
        )

    except KeyboardInterrupt:
        vmc_output(f"\n{appname} interrupted by user", "red")
    finally:
        # Close single connection and pool
        conn.close()
        db_pool.close()
        http_client.close()
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
    pass


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    main()
