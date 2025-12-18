#!/usr/bin/env python3

# Import required modules
try:
    import argparse
    import csv
    import json
    import hashlib
    import mimetypes
    import os
    import random
    import re
    import sys
    import threading
    import time
    import toml
    import unicodedata
    import httpx
    import psycopg
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from datetime import datetime, timedelta, timezone
    from urllib.parse import urlparse, urlunparse
    from dotenv import load_dotenv
    from io import StringIO
    from lxml import etree  # type: ignore
    from packaging import version
    from tqdm import tqdm
except ImportError as e:
    print(f"Error importing module: {e}")
    sys.exit(1)

# Detect the current filename
current_filename = os.path.basename(__file__)


# tqdm-aware print function to prevent progress bar disruption
def tqdm_print(text, color=None):
    """Print text without disrupting tqdm progress bars."""
    if color:
        vmc_output(text, color, use_tqdm=True)
    else:
        tqdm.write(text)


# Import the dotenv file
try:
    load_dotenv()
except Exception as e:
    print(f"Error loading .env file: {e}")
    sys.exit(1)

# PostgreSQL connection parameters
db_name = os.getenv("VMCRAWL_POSTGRES_DATA")
db_user = os.getenv("VMCRAWL_POSTGRES_USER")
db_password = os.getenv("VMCRAWL_POSTGRES_PASS")
db_host = os.getenv("VMCRAWL_POSTGRES_HOST", "localhost")
db_port = os.getenv("VMCRAWL_POSTGRES_PORT", "5432")

# Create PostgreSQL connection string
conn_string = f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"

try:
    conn = psycopg.connect(conn_string)
    # print("Connected to PostgreSQL database successfully.")
except psycopg.Error as e:
    print(f"Error connecting to PostgreSQL database: {e}")
    sys.exit(1)

# Define maintained branches (adjust as needed)
backport_branches = os.getenv("VMCRAWL_BACKPORTS", "4.5").split(",")

# Versioning information
toml_file_path = os.path.join(os.path.dirname(__file__), "pyproject.toml")
try:
    # Read the TOML file
    project_info = toml.load(toml_file_path)

    # Extract project information
    appname = project_info["project"]["name"]
    appversion = project_info["project"]["version"]
    appdescription = project_info["project"]["description"]

except FileNotFoundError:
    print(f"Error: {toml_file_path} not found.")
except toml.TomlDecodeError:
    print(f"Error: {toml_file_path} is not a valid TOML file.")
except KeyError as e:
    print(f"Error: Missing expected key in TOML file: {e}")

# Add your color constants here
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
color_gray = "\033[90m"

# Used to easily reference color constants
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
    "gray": f"{color_gray}",
}

# HTTP client configuration
common_timeout = int(os.getenv("VMCRAWL_COMMON_TIMEOUT", "7"))
http_custom_user_agent = f"{appname}/{appversion} (https://docs.vmst.io/{appname})"
http_custom_headers = {"User-Agent": http_custom_user_agent}
http_client = httpx.Client(
    http2=True,
    follow_redirects=True,
    headers=http_custom_headers,
    timeout=common_timeout,
)
http_codes_to_softfail = [429, 423, 422, 405, 404, 403, 402, 401, 400]
http_codes_to_hardfail = [451, 418, 410]


def get_with_fallback(url, http_client):
    try:
        return http_client.get(url)
    except httpx.RequestError as e:
        error_str = str(e).casefold()

        # Check for HTTP/2 specific issues
        http2_error_indicators = ["connectionterminated"]

        if any(indicator in error_str for indicator in http2_error_indicators):
            # Create a new client with HTTP/2 explicitly disabled
            fallback_client = httpx.Client(
                http2=False,
                follow_redirects=True,
                headers=http_custom_headers,
                timeout=common_timeout,
            )
            return fallback_client.get(url)
        else:
            # If it's not an HTTP/2 issue, just raise the error
            raise e


def get_cache_file_path(url: str) -> str:
    # Create a unique cache file path based on the URL
    url_hash = hashlib.md5(url.encode()).hexdigest()
    cache_dir = "/tmp/vmcrawl_cache"
    os.makedirs(cache_dir, exist_ok=True)
    return os.path.join(cache_dir, f"{url_hash}.cache")


def is_cache_valid(cache_file_path: str, max_age_seconds: int) -> bool:
    if not os.path.exists(cache_file_path):
        return False
    cache_age = time.time() - os.path.getmtime(cache_file_path)
    return cache_age < max_age_seconds


def read_main_version_info(url):
    """
    Read version information from a remote Ruby file.
    Returns a dictionary containing major, minor, patch and prerelease values.
    """
    version_info = {}
    try:
        response = get_with_fallback(url, http_client)
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
    except httpx.HTTPError as e:
        vmc_output(f"Failed to retrieve Mastodon main version: {e}", "red")
        return None

    return version_info


def get_highest_mastodon_version():
    try:
        release_url = "https://api.github.com/repos/mastodon/mastodon/releases"
        response = get_with_fallback(release_url, http_client)
        if response.status_code == 200:
            releases = response.json()
            highest_version = None
            for release in releases:
                release_version = release["tag_name"].lstrip("v")
                # Skip pre-release versions (those with a prerelease segment, e.g., 4.2.0-rc1)
                if version.parse(release_version).is_prerelease:
                    continue
                if highest_version is None or version.parse(
                    release_version
                ) > version.parse(highest_version):
                    highest_version = release_version
    except httpx.HTTPError as e:
        vmc_output(f"Failed to retrieve Mastodon release version: {e}", "red")
        return None

    return highest_version


def get_backport_mastodon_versions():
    url = "https://api.github.com/repos/mastodon/mastodon/releases"

    # Initialize with None instead of empty string
    backport_versions = {branch: "" for branch in backport_branches}

    response = get_with_fallback(url, http_client)
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

    # Replace any remaining None values with a default version
    for branch in backport_versions:
        if backport_versions[branch] is None:
            backport_versions[branch] = f"{branch}.0"

    return list(backport_versions.values())


def get_main_version_release():
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
    url = "https://raw.githubusercontent.com/mastodon/mastodon/refs/heads/main/lib/mastodon/version.rb"
    version_info = read_main_version_info(url)
    if not version_info:
        return "0.0"

    major = version_info.get("major", "0")
    minor = version_info.get("minor", "0")

    obtained_main_branch = f"{major}.{minor}"
    return obtained_main_branch


def update_patch_versions():
    """
    Update the patch versions in the database.
    """
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
    """
    Delete rows from the patch_versions table where software_version is in all_patched_versions.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            DELETE FROM patch_versions
            WHERE software_version != ALL(%s::text[])
        """,
            (all_patched_versions,),
        )
        conn.commit()


# Common variables
error_threshold = int(common_timeout)
error_buffer = int(os.getenv("VMCRAWL_ERROR_BUFFER", error_threshold))
version_main_branch = get_main_version_branch()
version_main_release = get_main_version_release()
version_latest_release = get_highest_mastodon_version()
version_backport_releases = get_backport_mastodon_versions()
all_patched_versions = [version_main_release] + version_backport_releases

update_patch_versions()
delete_old_patch_versions()


def vmc_output(text: str, color: str, use_tqdm: bool = False, **kwargs) -> None:
    # tqdm output should stay on one line; lowercasing helps keep style consistent
    if use_tqdm:
        text = text.lower()
    colored_text = f"{colors.get(color, '')}{text}{colors['reset']}"
    if use_tqdm:
        tqdm.write(colored_text, **kwargs)
    else:
        print(colored_text, **kwargs)


def get_domain_endings():
    url = "http://data.iana.org/TLD/tlds-alpha-by-domain.txt"
    cache_file_path = get_cache_file_path(url)
    max_cache_age = 86400  # 1 day in seconds

    if is_cache_valid(cache_file_path, max_cache_age):
        with open(cache_file_path, "r") as cache_file:
            domain_endings = [line.strip().lower() for line in cache_file.readlines()]
    else:
        domain_endings_response = get_with_fallback(url, http_client)
        if domain_endings_response.status_code in [200]:
            domain_endings = [
                line.strip().lower()
                for line in domain_endings_response.text.splitlines()
                if not line.startswith("#")
            ]
            with open(cache_file_path, "w") as cache_file:
                cache_file.write("\n".join(domain_endings))
        else:
            raise Exception(
                f"Failed to fetch domain endings. HTTP Status Code: {domain_endings_response.status_code}"
            )

    return domain_endings


def get_iftas_dni():
    url = "https://connect.iftas.org/wp-content/uploads/2024/04/dni.csv"
    cache_file_path = get_cache_file_path(url)
    max_cache_age = 86400  # 1 day in seconds

    if is_cache_valid(cache_file_path, max_cache_age):
        with open(cache_file_path, "r") as cache_file:
            iftas_domains = [line.strip().lower() for line in cache_file.readlines()]
    else:
        iftas_dns_response = get_with_fallback(url, http_client)
        if iftas_dns_response.status_code in [200]:

            csv_content = StringIO(iftas_dns_response.text)
            reader = csv.DictReader(csv_content)
            iftas_domains = [
                row["#domain"].strip().lower() for row in reader if "#domain" in row
            ]

            with open(cache_file_path, "w") as cache_file:
                cache_file.write("\n".join(iftas_domains))
        else:
            raise Exception(
                f"Failed to fetch IFTAS DNS. HTTP Status Code: {iftas_dns_response.status_code}"
            )

    return iftas_domains


def is_running_headless():
    return not os.isatty(sys.stdout.fileno())


def get_nightly_version_ranges():
    # Define nightly version ranges with their respective start and end dates
    # First date is the date on the -security release or the first nightly
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT version, start_date, end_date
            FROM nightly_versions
            ORDER BY start_date DESC
        """
        )
        nightly_version_ranges = [(row[0], row[1], row[2]) for row in cur.fetchall()]
        # Convert start_date and end_date to datetime objects if they aren't already
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
                    else datetime.fromisoformat(str(end_date)) if end_date else None
                ),
            )
            for version, start_date, end_date in nightly_version_ranges
        ]
    return nightly_version_ranges


def is_valid_email(email):
    pattern = r"^[\w\.-]+(?:\+[\w\.-]+)?@[\w\.-]+\.\w+$"
    return re.match(pattern, email) is not None


def normalize_email(email):
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


def has_emoji_or_special_chars(domain):
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


def log_error(domain, error_to_print):
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO error_log (domain, error)
            VALUES (%s, %s)
        """,
            (domain, error_to_print),
        )
        conn.commit()
    except Exception as e:
        vmc_output(f"Failed to log error: {e}", "red")
        conn.rollback()
    finally:
        cursor.close()


def increment_domain_error(domain, error_reason):
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT errors FROM raw_domains WHERE domain = %s", (domain,))
        result = cursor.fetchone()
        if result:
            current_errors = result[0] if result[0] is not None else 0
            new_errors = current_errors + 1
        else:
            # If the domain is not found, initialize errors count to 1
            new_errors = 1

        # Insert or update the domain with the new errors count
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
    except Exception as e:
        vmc_output(f"Failed to increment domain error: {e}", "red")
        conn.rollback()
    finally:
        cursor.close()


def delete_if_error_max(domain):
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT errors FROM raw_domains WHERE domain = %s", (domain,))
        result = cursor.fetchone()
        if result and result[0] >= error_threshold:
            cursor.execute(
                "SELECT timestamp FROM mastodon_domains WHERE domain = %s", (domain,)
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

    except Exception as e:
        vmc_output(f"Failed to delete maxed out domain: {e}", "red")
        conn.rollback()
    finally:
        cursor.close()


def clear_domain_error(domain):
    cursor = conn.cursor()
    try:
        # Insert or update the domain with the new errors count
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
    except Exception as e:
        vmc_output(f"Failed to clear domain error: {e}", "red")
        conn.rollback()
    finally:
        cursor.close()


def mark_ignore_domain(domain):
    cursor = conn.cursor()
    try:
        # Insert or update the domain with the new errors count
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
    except Exception as e:
        vmc_output(f"Failed to mark domain ignored: {e}", "red")
        conn.rollback()
    finally:
        cursor.close()


def mark_failed_domain(domain):
    cursor = conn.cursor()
    try:
        # Insert or update the domain with the new errors count
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
    except Exception as e:
        vmc_output(f"Failed to mark domain failed: {e}", "red")
        conn.rollback()
    finally:
        cursor.close()


def mark_nxdomain_domain(domain):
    cursor = conn.cursor()
    try:
        # Insert or update the domain with the new errors count
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
    except Exception as e:
        vmc_output(f"Failed to mark domain NXDOMAIN: {e}", "red")
        conn.rollback()
    finally:
        cursor.close()


def mark_norobots_domain(domain):
    cursor = conn.cursor()
    try:
        # Insert or update the domain with the new errors count
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
    except Exception as e:
        vmc_output(f"Failed to mark domain NoRobots: {e}", "red")
        conn.rollback()
    finally:
        cursor.close()


def limit_url_depth(source_url, depth=2):
    parsed_url = urlparse(source_url)
    # Split the path into parts
    path_parts = parsed_url.path.split("/")
    # Filter out empty strings and limit the depth
    limited_path = "/" + "/".join([part for part in path_parts if part][:depth])
    # Reconstruct the URL with the limited depth path
    new_url = urlunparse(parsed_url._replace(path=limited_path))
    return new_url


def delete_domain_if_known(domain):
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            DELETE FROM mastodon_domains WHERE domain = %s
            """,
            (domain,),
        )
        conn.commit()
    except Exception as e:
        vmc_output(f"Failed to delete known domain: {e}", "red")
        conn.rollback()
    finally:
        cursor.close()


def delete_domain_from_raw(domain):
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            DELETE FROM raw_domains WHERE domain = %s
            """,
            (domain,),
        )
        conn.commit()
    except Exception as e:
        vmc_output(f"Failed to delete known domain: {e}", "red")
        conn.rollback()
    finally:
        cursor.close()


def clean_version(software_version_full):
    software_version = clean_version_suffix(software_version_full)
    software_version = clean_version_oddstring(software_version)
    software_version = clean_version_dumbstring(software_version)
    software_version = clean_version_date(software_version)
    software_version = clean_version_suffix_more(software_version)
    software_version = clean_version_hometown(software_version)
    software_version = clean_version_development(software_version)
    software_version = clean_version_wrongpatch(software_version)
    software_version = clean_version_doubledash(software_version)
    software_version = clean_version_nightly(
        software_version, get_nightly_version_ranges()
    )
    software_version = clean_version_main_missing_prerelease(software_version)
    software_version = clean_version_release_with_prerelease(software_version)
    software_version = clean_version_strip_incorrect_prerelease(software_version)
    return software_version


def clean_version_dumbstring(software_version):
    # List of unwanted strings from versions to filter out
    unwanted_strings = ["-pre", "-theconnector", "-theatlsocial"]

    for unwanted_string in unwanted_strings:
        software_version = software_version.replace(unwanted_string, "")

    return software_version


def clean_version_suffix(software_version_full):
    # Remove any unwanted or invalid suffixes from the version string
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


def clean_version_date(software_version):
    # Regular expression to match the pattern "-YYMMDD"
    match = re.search(r"-(\d{2})(\d{2})(\d{2})$", software_version)

    if match:
        yy, mm, dd = match.groups()
        # Assuming the year starts with '20'
        formatted_date = f"-nightly.20{yy}-{mm}-{dd}"
        # Replace the matched part with the formatted date
        return re.sub(r"-(\d{6})$", formatted_date, software_version)

    # Return the original version if the pattern is not found
    return software_version


def clean_version_development(software_version):
    patterns = {r"rc(\d+)": r"-rc.\1", r"beta(\d+)": r"-beta.\1"}

    for pattern, replacement in patterns.items():
        software_version = re.sub(pattern, replacement, software_version)

    return software_version


def clean_version_hometown(software_version):
    if software_version == "1.0.6":
        software_version = "3.5.3"
    elif software_version == "1.0.7":
        software_version = "3.5.5"
    elif software_version == "3.4.6ht":
        software_version = "3.4.6"

    return software_version


def clean_version_doubledash(software_version):
    if "--" in software_version:
        software_version = software_version.replace("--", "-")
    if software_version.endswith("-"):
        software_version = software_version[:-1]

    return software_version


def clean_version_oddstring(software_version):
    if "mastau" in software_version:
        software_version = software_version.replace("mastau", "alpha")

    return software_version


def clean_version_wrongpatch(software_version):
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)(-.+)?$", software_version)

    if match:
        if version_latest_release:
            a, b, c = (
                int(version_latest_release.split(".")[0]),
                int(version_latest_release.split(".")[1]),
                int(version_latest_release.split(".")[2]),
            )
        else:
            a, b, c = (
                0,
                0,
                0,
            )  # Default values or handle the case where version_latest_release is None
        m = int(version_main_branch.split(".")[1])
        x, y, z = int(match.group(1)), int(match.group(2)), int(match.group(3))
        additional_data = match.group(
            4
        )  # This will be None if no dash and additional data is present

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
    # Remove incorrect date-based nightly suffixes like -nightly-YYYYMMDD (YYYYMMDD = 8 digits)
    software_version = re.sub(r"-nightly-\d{8}", "", software_version)

    # Handle -nightly with date and -security suffix
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
    if software_version.startswith(version_main_branch) and "-" not in software_version:
        software_version = f"{software_version}-alpha.1"
    return software_version


def clean_version_release_with_prerelease(software_version):
    if (
        version_latest_release
        and software_version.startswith(version_latest_release)
        and "-" in software_version
        and not version_latest_release.endswith(".0")
    ):
        software_version = software_version.split("-")[0]
    return software_version


def clean_version_strip_incorrect_prerelease(software_version):
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)(-.+)?$", software_version)
    if match:
        x, y, z, prerelease = match.groups()
        if int(z) != 0 and prerelease:
            return f"{x}.{y}.{z}"
    return software_version


def get_junk_keywords():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT keywords FROM junk_words")
        junk_domains = [row[0] for row in cursor.fetchall()]
        conn.commit()
        return junk_domains
    except Exception as e:
        vmc_output(f"Failed to obtain junk keywords: {e}", "red")
        conn.rollback()
    finally:

        cursor.close()
    return []


def get_bad_tld():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT tld FROM bad_tld")
        bad_tlds = [row[0] for row in cursor.fetchall()]
        conn.commit()
        return bad_tlds
    except Exception as e:
        vmc_output(f"Failed to obtain bad TLDs: {e}", "red")
        conn.rollback()
    finally:
        cursor.close()
    return []


def get_failed_domains():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT domain FROM raw_domains WHERE failed = TRUE")
        failed_domains = [row[0].strip() for row in cursor.fetchall() if row[0].strip()]
        conn.commit()
    except Exception as e:
        vmc_output(f"Failed to obtain failed domains: {e}", "red")
        conn.rollback()
    finally:
        cursor.close()
    return failed_domains


def get_ignored_domains():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT domain FROM raw_domains WHERE ignore = TRUE")
        ignored_domains = [
            row[0].strip() for row in cursor.fetchall() if row[0].strip()
        ]
        conn.commit()
    except Exception as e:
        vmc_output(f"Failed to obtain ignored domains: {e}", "red")
        conn.rollback()
    finally:
        cursor.close()
    return ignored_domains


def get_baddata_domains():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT domain FROM raw_domains WHERE baddata = TRUE")
        baddata_domains = [
            row[0].strip() for row in cursor.fetchall() if row[0].strip()
        ]
        conn.commit()
    except Exception as e:
        vmc_output(f"Failed to obtain baddata domains: {e}", "red")
        conn.rollback()
    finally:
        cursor.close()
    return baddata_domains


def get_nxdomain_domains():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT domain FROM raw_domains WHERE nxdomain = TRUE")
        nxdomain_domains = [
            row[0].strip() for row in cursor.fetchall() if row[0].strip()
        ]
        conn.commit()
    except Exception as e:
        vmc_output(f"Failed to obtain NXDOMAIN domains: {e}", "red")
        conn.rollback()
    finally:
        cursor.close()
    return nxdomain_domains


def get_norobots_domains():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT domain FROM raw_domains WHERE norobots = TRUE")
        norobots_domains = [
            row[0].strip() for row in cursor.fetchall() if row[0].strip()
        ]
        conn.commit()
    except Exception as e:
        vmc_output(f"Failed to obtain NoRobots domains: {e}", "red")
        conn.rollback()
    finally:
        cursor.close()
    return norobots_domains


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
    iftas_domains,
    nightly_version_ranges,
):
    # Get max workers from environment or default to 2
    max_workers = int(os.getenv("VMCRAWL_MAX_THREADS", "2"))
    
    # Shutdown event for graceful interruption
    shutdown_event = threading.Event()

    def process_single_domain(domain):
        """Process a single domain with all checks."""
        # Check if shutdown was requested
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

        # if is_iftas_domain(domain, iftas_domains):
        #     return

        try:
            process_domain(domain, http_client)
        except httpx.CloseError:
            # Suppress errors from closed HTTP client during shutdown
            pass
        except Exception as e:
            if not shutdown_event.is_set():
                handle_http_exception(domain, e)

    # Use ThreadPoolExecutor for concurrent processing
    executor = ThreadPoolExecutor(max_workers=max_workers)
    try:
        # Submit all tasks and wrap with tqdm for progress tracking
        futures = {
            executor.submit(process_single_domain, domain): domain
            for domain in domain_list
        }

        # Process completed tasks with progress bar
        try:
            for future in tqdm(
                as_completed(futures),
                total=len(domain_list),
                desc="vmcrawl",
                unit="d",
            ):
                try:
                    future.result()  # Get result or raise exception if any
                except httpx.CloseError:
                    # Suppress errors from closed HTTP client during shutdown
                    pass
                except Exception as e:
                    if not shutdown_event.is_set():
                        domain = futures[future]
                        vmc_output(
                            f"{domain}: Unexpected error in thread: {e}", "red", use_tqdm=True
                        )
        except KeyboardInterrupt:
            shutdown_event.set()
            print("\nProcess interrupted. Canceling pending tasks...")
            # Cancel all pending futures
            for future in futures:
                future.cancel()
            # Don't wait for running threads, just shutdown immediately
            executor.shutdown(wait=False, cancel_futures=True)
            return
    finally:
        # Normal cleanup if no interrupt
        if not shutdown_event.is_set():
            executor.shutdown(wait=True)


def should_skip_domain(
    domain,
    ignored_domains,
    baddata_domains,
    failed_domains,
    nxdomain_domains,
    norobots_domains,
    user_choice,
):
    # Check against user choices and known domain lists
    if user_choice != "6" and domain in ignored_domains:
        vmc_output(f"{domain}: Other Platform", "cyan", use_tqdm=True)
        delete_domain_if_known(domain)
        return True
    if user_choice != "7" and domain in failed_domains:
        vmc_output(f"{domain}: HTTP Blocked", "magenta", use_tqdm=True)
        delete_domain_if_known(domain)
        return True
    if user_choice != "8" and domain in nxdomain_domains:
        vmc_output(f"{domain}: Emoji Domain", "magenta", use_tqdm=True)
        delete_domain_if_known(domain)
        return True
    if user_choice != "9" and domain in norobots_domains:
        vmc_output(f"{domain}: Crawling Prohibited", "magenta", use_tqdm=True)
        delete_domain_if_known(domain)
        return True
    if domain in baddata_domains:
        vmc_output(f"{domain}: Bad Domain", "magenta", use_tqdm=True)
        delete_domain_if_known(domain)
        return True
    return False


def is_junk_or_bad_tld(domain, junk_domains, bad_tlds, domain_endings):
    if any(junk in domain for junk in junk_domains):
        vmc_output(f"{domain}: Purging known junk domain", "magenta", use_tqdm=True)
        delete_domain_if_known(domain)
        delete_domain_from_raw(domain)
        return True
    if any(domain.endswith(f".{tld}") for tld in bad_tlds):
        vmc_output(f"{domain}: Purging prohibited TLD", "magenta", use_tqdm=True)
        mark_nxdomain_domain(domain)
        delete_domain_if_known(domain)
        delete_domain_from_raw(domain)
        return True
    if not any(
        domain.endswith(f".{domain_ending}") for domain_ending in domain_endings
    ):
        vmc_output(f"{domain}: Purging unknown TLD", "magenta", use_tqdm=True)
        mark_nxdomain_domain(domain)
        delete_domain_if_known(domain)
        delete_domain_from_raw(domain)
        return True
    return False


def is_iftas_domain(domain, iftas_domains):
    if any(domain.endswith(f"{dni}") for dni in iftas_domains):
        vmc_output(f"{domain}: Known IFTAS DNI domain", "magenta", use_tqdm=True)
        mark_nxdomain_domain(domain)
        delete_domain_if_known(domain)
        return True
    return False


def process_domain(domain, http_client):
    if has_emoji_or_special_chars(domain):
        vmc_output(f"{domain}: Emoji Domain", "magenta", use_tqdm=True)
        mark_nxdomain_domain(domain)
        delete_domain_if_known(domain)
        return

    if not check_robots_txt(domain, http_client):
        return  # Stop processing this domain

    webfinger_data = check_webfinger(domain, http_client)
    if not webfinger_data:
        return

    nodeinfo_data = check_nodeinfo(
        domain, webfinger_data["backend_domain"], http_client
    )
    if not nodeinfo_data:
        return

    if is_mastodon_instance(nodeinfo_data):
        process_mastodon_instance(domain, webfinger_data, nodeinfo_data, http_client)
    else:
        mark_as_non_mastodon(domain)


def check_robots_txt(domain, http_client):
    url = f"https://{domain}/robots.txt"
    try:
        response = get_with_fallback(url, http_client)
        # Check for valid HTTP status code
        if response.status_code in [200]:
            content_type = response.headers.get("Content-Type", "")
            if (
                content_type in mimetypes.types_map.values()
                and not content_type.startswith("text/")
            ):
                error_message = "robots.txt invalid"
                vmc_output(f"{domain}: {error_message}", "orange", use_tqdm=True)
                log_error(domain, error_message)
                increment_domain_error(domain, "TXT")
                delete_if_error_max(domain)
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
                            f"{domain}: Crawling Prohibited", "magenta", use_tqdm=True
                        )
                        mark_norobots_domain(domain)
                        delete_domain_if_known(domain)
                        return False
        # Check for specific HTTP status codes
        elif response.status_code in http_codes_to_hardfail:
            vmc_output(
                f"{domain}: HTTP {response.status_code} on robots.txt",
                "magenta",
                use_tqdm=True,
            )
            mark_failed_domain(domain)
            delete_domain_if_known(domain)
            return False
    except httpx.RequestError as e:
        handle_http_exception(domain, e)
        return False
    return True


def check_webfinger(domain, http_client):
    url = f"https://{domain}/.well-known/webfinger?resource=acct:{domain}@{domain}"
    try:
        response = get_with_fallback(url, http_client)
        content_type = response.headers.get("Content-Type", "")
        content_length = response.headers.get("Content-Length", "")
        if response.status_code in [200]:
            if "json" not in content_type:
                # WebFinger reply is not JSON
                hostmeta_result = check_hostmeta(domain, http_client)
                if hostmeta_result:
                    backend_domain = hostmeta_result["backend_domain"]
                    return {"backend_domain": backend_domain}
                else:
                    return None
            if not response.content or content_length == "0":
                # WebFinger reply is empty
                hostmeta_result = check_hostmeta(domain, http_client)
                if hostmeta_result:
                    backend_domain = hostmeta_result["backend_domain"]
                    return {"backend_domain": backend_domain}
                else:
                    return None
            if "aliases" not in response.content.decode("utf-8"):
                # WebFinger reply is invalid
                hostmeta_result = check_hostmeta(domain, http_client)
                if hostmeta_result:
                    backend_domain = hostmeta_result["backend_domain"]
                    return {"backend_domain": backend_domain}
                else:
                    return None
            if "localhost" in response.content.decode("utf-8"):
                error_message = "WebFinger alias points to localhost"
                vmc_output(f"{domain}: {error_message}", "orange", use_tqdm=True)
                log_error(domain, error_message)
                increment_domain_error(domain, "???")
                delete_domain_if_known(domain)
                return None
            else:
                data = response.json()
            aliases = data.get("aliases", [])
            if not aliases:
                mark_as_non_mastodon(domain)
                return None
            first_alias = next((alias for alias in aliases if "https" in alias), None)
            if first_alias:
                backend_domain = urlparse(first_alias).netloc
                return {"backend_domain": backend_domain}
                # Check for specific HTTP status codes
            else:
                # WebFinger reply has no valid alias
                hostmeta_result = check_hostmeta(domain, http_client)
                if hostmeta_result:
                    backend_domain = hostmeta_result["backend_domain"]
                    return {"backend_domain": backend_domain}
                else:
                    return None
        elif response.status_code in http_codes_to_hardfail:
            vmc_output(
                f"{domain}: HTTP {response.status_code} on WebFinger",
                "magenta",
                use_tqdm=True,
            )
            mark_failed_domain(domain)
            delete_domain_if_known(domain)
            return False
        elif response.status_code in http_codes_to_softfail:
            if "json" in content_type:
                mark_as_non_mastodon(domain)
                return None
            else:
                # WebFinger didn't reply
                hostmeta_result = check_hostmeta(domain, http_client)
                if hostmeta_result:
                    backend_domain = hostmeta_result["backend_domain"]
                    return {"backend_domain": backend_domain}
                else:
                    return None
        else:
            error_message = f"HTTP {response.status_code} on WebFinger"
            vmc_output(f"{domain}: {error_message}", "yellow", use_tqdm=True)
            log_error(domain, error_message)
            increment_domain_error(domain, str(response.status_code))
            delete_if_error_max(domain)
    except httpx.RequestError as e:
        handle_http_exception(domain, e)
    except json.JSONDecodeError as e:
        handle_json_exception(domain, e)
    return None


def check_hostmeta(domain, http_client):
    url = f"https://{domain}/.well-known/host-meta"
    try:
        response = get_with_fallback(url, http_client)
        if response.status_code in [200]:
            content_type = response.headers.get("Content-Type", "")
            if "xml" not in content_type:
                # HostMeta reply is not XML
                return {"backend_domain": domain}
            if "xhtml" in content_type:
                # HostMeta reply is an XHTML file
                return {"backend_domain": domain}
            if not response.content:
                # HostMeta reply is empty
                return {"backend_domain": domain}
            else:
                content = response.content.strip()
                content = content.lower()
                parser = etree.XMLParser(recover=True)
                try:
                    xmldata = etree.fromstring(content, parser=parser)
                except etree.XMLSyntaxError as e:
                    # XML syntax error while parsing HostMeta
                    return {"backend_domain": domain}
                ns = {"xrd": "http://docs.oasis-open.org/ns/xri/xrd-1.0"}  # Namespace
                try:
                    link = xmldata.find(".//xrd:link[@rel='lrdd']", namespaces=ns)
                except AttributeError:
                    # Unable to find lrdd link due to XML structure
                    return {"backend_domain": domain}
                except etree.XMLSyntaxError:
                    # XML syntax error while parsing HostMeta
                    return {"backend_domain": domain}
                if link is None:
                    # No lrdd link found in HostMeta
                    return {"backend_domain": domain}
                else:
                    parsed_link = urlparse(link.get("template"))
                    backend_domain = parsed_link.netloc
                    return {"backend_domain": backend_domain}
        elif response.status_code in http_codes_to_hardfail:
            vmc_output(
                f"{domain}: HTTP {response.status_code} on HostMeta",
                "magenta",
                use_tqdm=True,
            )
            mark_failed_domain(domain)
            delete_domain_if_known(domain)
            return False
        elif response.status_code in http_codes_to_softfail:
            # HostMeta didn't reply
            return {"backend_domain": domain}
        else:
            error_message = f"HTTP {response.status_code} on HostMeta"
            vmc_output(f"{domain}: {error_message}", "yellow", use_tqdm=True)
            log_error(domain, f"{error_message}")
            increment_domain_error(domain, str(response.status_code))
            delete_if_error_max(domain)
    except httpx.RequestError as e:
        handle_http_exception(domain, e)


def check_nodeinfo(domain, backend_domain, http_client):
    url = f"https://{backend_domain}/.well-known/nodeinfo"
    try:
        response = get_with_fallback(url, http_client)
        if response.status_code in [200]:
            content_type = response.headers.get("Content-Type", "")
            if "json" not in content_type:
                error_message = "NodeInfo reply is not a JSON file"
                vmc_output(f"{domain}: {error_message}", "orange", use_tqdm=True)
                log_error(domain, error_message)
                increment_domain_error(domain, "JSON")
                delete_if_error_max(domain)
                return None
            if not response.content:
                error_message = "NodeInfo reply is empty"
                vmc_output(f"{domain}: {error_message}", "orange", use_tqdm=True)
                log_error(domain, error_message)
                increment_domain_error(domain, "JSON")
                delete_if_error_max(domain)
                return None
            else:
                try:
                    data = response.json()
                except json.JSONDecodeError as e:
                    error_message = f"Invalid JSON response: {e}"
                    vmc_output(f"{domain}: {error_message}", "orange", use_tqdm=True)
                    log_error(domain, error_message)
                    increment_domain_error(domain, "JSON")
                    delete_if_error_max(domain)
                    return None
            if "links" in data and len(data["links"]) > 0:
                nodeinfo_2_url = next(
                    (
                        link["href"]
                        for link in data["links"]
                        if link.get("rel")
                        == "http://nodeinfo.diaspora.software/ns/schema/2.0"
                        and "href" in link
                    ),
                    None,
                )
                if not nodeinfo_2_url:
                    rel_index = next(
                        (
                            i
                            for i, link in enumerate(data["links"])
                            if link.get("rel")
                            == "http://nodeinfo.diaspora.software/ns/schema/2.0"
                            and "href" not in link
                        ),
                        None,
                    )
                    if rel_index is not None and rel_index + 1 < len(data["links"]):
                        next_obj = data["links"][rel_index + 1]
                        if "href" in next_obj and "rel" not in next_obj:
                            nodeinfo_2_url = next_obj["href"]

                if nodeinfo_2_url and "wp-json" not in nodeinfo_2_url:
                    nodeinfo_response = get_with_fallback(nodeinfo_2_url, http_client)
                    if nodeinfo_response.status_code in [200]:
                        nodeinfo_response_content_type = nodeinfo_response.headers.get(
                            "Content-Type", ""
                        )
                        if "json" not in nodeinfo_response_content_type:
                            error_message = "NodeInfo V2 reply not JSON"
                            vmc_output(
                                f"{domain}: {error_message}", "orange", use_tqdm=True
                            )
                            log_error(domain, error_message)
                            increment_domain_error(domain, "JSON")
                            delete_if_error_max(domain)
                            return None
                        if not nodeinfo_response.content:
                            error_message = "NodeInfo V2 reply empty"
                            vmc_output(
                                f"{domain}: {error_message}", "orange", use_tqdm=True
                            )
                            log_error(domain, error_message)
                            increment_domain_error(domain, "JSON")
                            delete_if_error_max(domain)
                            return None
                        else:
                            return nodeinfo_response.json()
                    elif nodeinfo_response.status_code in http_codes_to_hardfail:
                        vmc_output(
                            f"HTTP {response.status_code} on NodeInfo",
                            "magenta",
                            use_tqdm=True,
                        )
                        mark_failed_domain(domain)
                        delete_domain_if_known(domain)
                        return False
                    else:
                        error_message = (
                            f"HTTP {nodeinfo_response.status_code} on NodeInfo"
                        )
                        vmc_output(
                            f"{domain}: {error_message}", "yellow", use_tqdm=True
                        )
                        log_error(domain, f"{error_message}")
                        increment_domain_error(
                            domain, str(nodeinfo_response.status_code)
                        )
                        delete_if_error_max(domain)
                else:
                    mark_as_non_mastodon(domain)
            else:
                mark_as_non_mastodon(domain)
        elif response.status_code in http_codes_to_hardfail:
            vmc_output(
                f"{domain}: HTTP {response.status_code} on NodeInfo",
                "magenta",
                use_tqdm=True,
            )
            mark_failed_domain(domain)
            delete_domain_if_known(domain)
        else:
            error_message = f"HTTP {response.status_code} on NodeInfo"
            vmc_output(f"{domain}: {error_message}", "yellow", use_tqdm=True)
            log_error(domain, f"{error_message}")
            increment_domain_error(domain, str(response.status_code))
            delete_if_error_max(domain)
    except httpx.RequestError as e:
        handle_http_exception(domain, e)
    except json.JSONDecodeError as e:
        handle_json_exception(domain, e)
    return None


def is_mastodon_instance(nodeinfo_data: dict) -> bool:
    """Check if the given NodeInfo response indicates a Mastodon instance."""
    if not isinstance(nodeinfo_data, dict):
        return False

    software = nodeinfo_data.get("software")
    if software is None:
        return False

    software_name = software.get("name")
    if software_name is None:
        return False

    return software_name.lower() in {"mastodon", "hometown", "kmyblue", "glitchcafe"}


def process_mastodon_instance(domain, webfinger_data, nodeinfo_data, http_client):
    software_name = nodeinfo_data["software"]["name"].lower()
    software_version_full = nodeinfo_data["software"]["version"]
    software_version = clean_version(nodeinfo_data["software"]["version"])

    if "usage" not in nodeinfo_data or "users" not in nodeinfo_data["usage"]:
        error_to_print = f"v{software_version} (no user count)"
        vmc_output(f"{domain}: {error_to_print}", "light_green", use_tqdm=True)
        log_error(domain, error_to_print)
        increment_domain_error(domain, "###")
        delete_domain_if_known(domain)
        return

    if "total" in nodeinfo_data["usage"]["users"]:
        total_users = nodeinfo_data["usage"]["users"]["total"]
    else:
        error_to_print = f"v{software_version} (no total user count)"
        vmc_output(f"{domain}: {error_to_print}", "light_green", use_tqdm=True)
        log_error(domain, error_to_print)
        increment_domain_error(domain, "###")
        delete_domain_if_known(domain)
        return
    if "activeMonth" in nodeinfo_data["usage"]["users"]:
        active_month_users = nodeinfo_data["usage"]["users"]["activeMonth"]
    else:
        error_to_print = f"v{software_version} (invalid MAU reported)"
        vmc_output(f"{domain}: {error_to_print}", "light_green", use_tqdm=True)
        log_error(domain, error_to_print)
        increment_domain_error(domain, "###")
        delete_domain_if_known(domain)
        return

    if software_version.startswith("4"):
        instance_api_url = f'https://{webfinger_data["backend_domain"]}/api/v2/instance'
    else:
        instance_api_url = f'https://{webfinger_data["backend_domain"]}/api/v1/instance'

    try:
        response = get_with_fallback(instance_api_url, http_client)
        if response.status_code in [200]:
            content_type = response.headers.get("Content-Type", "")
            if not response.content:
                error_message = "Instance API reply is empty"
                vmc_output(f"{domain}: {error_message}", "orange", use_tqdm=True)
                log_error(domain, error_message)
                increment_domain_error(domain, "API")
                delete_if_error_max(domain)
                return None
            elif "json" not in content_type:
                error_message = "Instance API reply not JSON"
                vmc_output(f"{domain}: {error_message}", "orange", use_tqdm=True)
                log_error(domain, error_message)
                increment_domain_error(domain, "API")
                delete_if_error_max(domain)
                return None

            response_json = response.json()
            if "error" in response_json:
                error_message = "Instance API returned an error"
                vmc_output(f"{domain}: {error_message}", "orange", use_tqdm=True)
                log_error(domain, error_message)
                increment_domain_error(domain, "API")
                delete_if_error_max(domain)
                return None
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
                if "created_at" in instance_api_data["contact"]:
                    admin_creation = instance_api_data["contact"]["created_at"]
                else:
                    admin_creation = None
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
                if "created_at" in instance_api_data:
                    admin_creation = instance_api_data["contact_account"]["created_at"]
                else:
                    admin_creation = None
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

            # Check for invalid software versions
            if version.parse(software_version.split("-")[0]) > version.parse(
                version_main_branch
            ):
                error_to_print = f'v{software_version.split("-")[0]} (version invalid)'
                vmc_output(f"{domain}: {error_to_print}", "yellow", use_tqdm=True)
                log_error(domain, error_to_print)
                increment_domain_error(domain, "???")
                delete_domain_if_known(domain)
                return

            # Update database
            update_mastodon_domain(
                actual_domain,
                software_version,
                software_version_full,
                total_users,
                active_month_users,
                contact_account,
                source_url,
                admin_creation,
            )

            clear_domain_error(domain)

            if software_version == nodeinfo_data["software"]["version"]:
                vmc_output(f"{domain}: v{software_version}", "green", use_tqdm=True)
            else:
                vmc_output(
                    f'{domain}: v{software_version} ({nodeinfo_data["software"]["version"]})',
                    "green",
                    use_tqdm=True,
                )

        else:
            error_message = "API request failed"
            vmc_output(f"{domain}: {error_message}", "orange", use_tqdm=True)
            log_error(domain, error_message)
            increment_domain_error(domain, "API")
            delete_if_error_max(domain)

    except httpx.RequestError as e:
        handle_http_exception(domain, e)
    except json.JSONDecodeError as e:
        handle_json_exception(domain, e)


def update_mastodon_domain(
    actual_domain,
    software_version,
    software_version_full,
    total_users,
    active_month_users,
    contact_account,
    source_url,
    admin_creation,
):
    cursor = conn.cursor()
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
    except Exception as e:
        vmc_output(f"Failed to update Mastodon domain data: {e}", "red", use_tqdm=True)
        conn.rollback()
    finally:
        cursor.close()


def mark_as_non_mastodon(domain):
    vmc_output(f"{domain}: Other Platform", "cyan", use_tqdm=True)
    mark_ignore_domain(domain)
    delete_domain_if_known(domain)


def handle_http_exception(domain, exception):
    error_message = str(exception)
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


def handle_json_exception(domain, exception):
    error_message = str(exception)
    error_reason = "JSON"
    vmc_output(f"{domain}: {error_message}", "orange", use_tqdm=True)
    log_error(domain, error_message)
    increment_domain_error(domain, error_reason)
    delete_if_error_max(domain)


def cleanup_old_domains():
    cursor = conn.cursor()
    try:
        # Delete known domains older than 1 week
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
                vmc_output(f"{d}: Removed from known domains", "pink")
        conn.commit()
    except Exception as e:
        vmc_output(f"Failed to clean up old domains: {e}", "red")
        conn.rollback()
    finally:
        cursor.close()


def read_domain_list(file_path):
    with open(file_path, "r") as file:
        return [line.strip() for line in file]


def load_from_database(user_choice):
    # PostgreSQL uses SIMILAR TO instead of GLOB, and different timestamp functions
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
        "30": "SELECT domain FROM raw_domains WHERE reason = '###' ORDER BY errors ASC",
        "31": "SELECT domain FROM raw_domains WHERE reason = 'JSON' ORDER BY errors ASC",
        "32": "SELECT domain FROM raw_domains WHERE reason = 'TXT' ORDER BY errors ASC",
        "33": "SELECT domain FROM raw_domains WHERE reason = 'API' ORDER BY errors ASC",
        "34": "SELECT domain FROM raw_domains WHERE reason = '???' ORDER BY errors ASC",
        "40": "SELECT domain FROM mastodon_domains WHERE software_version != ALL(%(versions)s::text[]) ORDER BY active_users_monthly DESC",
        "41": "SELECT domain FROM mastodon_domains WHERE software_version LIKE %s ORDER BY active_users_monthly DESC",
        "42": "SELECT domain FROM mastodon_domains WHERE active_users_monthly = '0' ORDER BY active_users_monthly DESC",
        "43": "SELECT domain FROM mastodon_domains ORDER BY active_users_monthly DESC",
        "50": "SELECT domain FROM raw_domains WHERE errors > %s ORDER BY errors ASC",
        "51": "SELECT domain FROM raw_domains WHERE errors > %s AND errors < %s ORDER BY errors ASC",
    }

    if user_choice in ["2", "3"]:  # Reverse or Random
        query = query_map["1"]  # Default query
        params = [error_buffer]
    else:
        query = query_map.get(user_choice)

        # Set parameters based on query type
        params = []
        if user_choice in ["1"]:
            params = [error_buffer]
        elif user_choice == "50":
            params = [int(error_buffer*2)]
        elif user_choice == "51":
            params = [error_buffer, int(error_buffer*2)]
        elif user_choice == "40":
            params = {"versions": all_patched_versions}
            vmc_output("Excluding versions:", "pink")
            for version in params["versions"]:
                vmc_output(f" - {version}", "pink")
        elif user_choice == "41":
            params = [f"{version_main_branch}%"]

    if not query:
        vmc_output(
            f"Choice {user_choice} was not available, using default query", "pink"
        )
        query = query_map["1"]  # Default query
        params = [error_threshold]

    cursor = conn.cursor()
    try:
        cursor.execute(query, params if params else None)  # type: ignore
        domain_list = [row[0].strip() for row in cursor.fetchall() if row[0].strip()]
        conn.commit()
    except Exception as e:
        vmc_output(f"Failed to obtain selected domain list: {e}", "red")
        conn.rollback()
        domain_list = []
    finally:
        cursor.close()

    return domain_list


def load_from_file(file_name):
    cursor = conn.cursor()
    domain_list = []
    with open(file_name, "r") as file:
        for line in file:
            domain = line.strip()
            if domain:  # Ensure the domain is not empty
                domain_list.append(domain)
                # Check if the domain already exists in the database
                cursor.execute(
                    "SELECT COUNT(*) FROM raw_domains WHERE domain = %s", (domain,)
                )
                result = cursor.fetchone()
                exists = result is not None and result[0] > 0

                # If not, insert the new domain into the database
                if not exists:
                    cursor.execute(
                        "INSERT INTO raw_domains (domain, errors) VALUES (%s, %s)",
                        (domain, None),
                    )
                    cursor.close()
                conn.commit()
    return domain_list


def print_menu() -> None:
    menu_options = {
        "Process new domains": {"0": "Recently Fetched"},
        "Change process direction": {"1": "Standard", "2": "Reverse", "3": "Random"},
        "Retry fatal errors": {
            "6": "Other Platforms",
            "7": "HTTP 410/418",
            "8": "Emoji Domain",
            "9": "Crawling Prohibited",
        },
        "Retry connection errors": {
            "10": "SSL",
            "11": "HTTP",
            "12": "TCP",
            "13": "Redirects",
            "14": "DNS",
        },
        "Retry HTTP errors": {"20": "2xx", "21": "3xx", "22": "4xx", "23": "5xx"},
        "Retry specific errors": {
            "30": "###",
            "31": "JSON",
            "32": "TXT",
            "33": "API",
            "34": "???",
        },
        "Retry good data": {
            "40": "Unpatched",
            "41": "Main",
            "42": "Inactive",
            "43": "All Good",
        },
        "Retry general errors": {
            "50": f"Domains w/ >{int(error_buffer*2)} Errors",
            "51": f"Domains w/ {error_buffer}-{int(error_buffer*2)} Errors",
        },
    }

    for category, options in menu_options.items():
        options_str = " ".join(f"({key}) {value}" for key, value in options.items())
        vmc_output(f"{category}: ", "cyan", end="")
        vmc_output(options_str, "")  # Print options without color
    vmc_output("Enter your choice (1, 2, 3, etc):", "bold", end=" ")
    sys.stdout.flush()


def get_user_choice() -> str:
    return sys.stdin.readline().strip()


def main():
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
    else:
        vmc_output("Running in interactive mode", "pink")
    try:
        domain_list_file = args.file if args.file is not None else None
        single_domain_target = args.target if args.target is not None else None
        try:
            if domain_list_file:  # File name provided as argument
                user_choice = 1
                domain_list = load_from_file(domain_list_file)
                vmc_output("Crawling domains from file…", "pink")
            elif single_domain_target:  # Single domain provided as argument
                user_choice = 1
                domain_list = single_domain_target.replace(" ", "").split(",")
                vmc_output(
                    f"Crawling domain{'s' if len(domain_list) > 1 else ''} from target…",
                    "pink",
                )
            else:  # Load from database by default
                if args.new:
                    user_choice = "0"
                elif args.buffer:
                    user_choice = "51"
                elif is_running_headless():
                    user_choice = "3"  # Default to random crawl in headless mode
                else:
                    print_menu()
                    user_choice = get_user_choice()

                vmc_output(
                    f"Crawling domains from database choice {user_choice}…", "pink"
                )
                domain_list = load_from_database(user_choice)

            if user_choice == "2":
                domain_list.reverse()
            elif user_choice == "3":  # Assuming "3" is the option for randomizing
                random.shuffle(domain_list)

        except FileNotFoundError:
            vmc_output(f"File not found: {domain_list_file}", "red")
            sys.exit(1)
        except psycopg.Error as e:
            vmc_output(f"Database error: {e}", "red")
            sys.exit(1)

        junk_domains = get_junk_keywords()
        bad_tlds = get_bad_tld()
        domain_endings = get_domain_endings()
        failed_domains = get_failed_domains()
        ignored_domains = get_ignored_domains()
        baddata_domains = get_baddata_domains()
        nxdomain_domains = get_nxdomain_domains()
        norobots_domains = get_norobots_domains()
        iftas_domains = get_iftas_dni()
        nightly_version_ranges = get_nightly_version_ranges()

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
            iftas_domains,
            nightly_version_ranges,
        )
        cleanup_old_domains()
        vmc_output("Crawling complete!", "pink")
    except KeyboardInterrupt:
        vmc_output(f"\n{appname} interrupted by user", "red")
    finally:
        conn.close()
        http_client.close()

    if is_running_headless():
        if not (args.file or args.target or args.new or args.buffer):
            try:
                vmc_output(f"Re-executing {appname}...", "pink")
                os.execv(sys.executable, ["python3"] + sys.argv)
            except Exception as e:
                vmc_output(f"Failed to re-execute {appname}: {e}", "red")
    else:
        sys.exit(0)
    pass


if __name__ == "__main__":
    main()
