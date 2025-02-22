#!/usr/bin/env python3

# Import required modules
try:
    import argparse
    import csv
    import hashlib
    import httpx
    import os
    import random
    import re
    import psycopg
    import sys
    import time
    import toml
    from dotenv import load_dotenv
    from io import StringIO
    from packaging import version
except ImportError as e:
    print(f"Error importing module: {e}")
    sys.exit(1)

# Import the dotenv file
try:
    load_dotenv()
except Exception as e:
    print(f"Error loading .env file: {e}")
    sys.exit(1)

# PostgreSQL connection parameters
db_name = os.getenv("POSTGRES_DB")
db_user = os.getenv("POSTGRES_USER")
db_password = os.getenv("POSTGRES_PASSWORD")
db_host = os.getenv("POSTGRES_HOST", "localhost")
db_port = os.getenv("POSTGRES_PORT", "5432")

# Create PostgreSQL connection string
conn_string = f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"

try:
    conn = psycopg.connect(conn_string)
    # print("Connected to PostgreSQL database successfully.")
except psycopg.Error as e:
    print(f"Error connecting to PostgreSQL database: {e}")
    sys.exit(1)

# Versioning information
toml_file_path = os.path.join(os.path.dirname(__file__), 'pyproject.toml')
try:
    # Read the TOML file
    project_info = toml.load(toml_file_path)

    # Extract project information
    appname = project_info['project']['name']
    appversion = project_info['project']['version']
    appdescription = project_info['project']['description']

except FileNotFoundError:
    print(f"Error: {toml_file_path} not found.")
except toml.TomlDecodeError:
    print(f"Error: {toml_file_path} is not a valid TOML file.")
except KeyError as e:
    print(f"Error: Missing expected key in TOML file: {e}")

# Add your color constants here
color_bold = '\033[1m'
color_reset = '\033[0m'
color_cyan = '\033[96m'
color_dark_green = '\033[32m'
color_green = '\033[92m'
color_magenta = '\033[95m'
color_orange = '\033[38;5;208m'
color_pink = '\033[38;5;198m'
color_purple = '\033[94m'
color_red = '\033[91m'
color_yellow = '\033[93m'

# Used to easily reference color constants
colors = {
    "bold": f"{color_bold}",
    "reset": f"{color_reset}",
    "cyan": f"{color_cyan}",
    "dark_green": f"{color_dark_green}",
    "green": f"{color_green}",
    "magenta": f"{color_magenta}",
    "orange": f"{color_orange}",
    "pink": f"{color_pink}",
    "purple": f"{color_purple}",
    "red": f"{color_red}",
    "yellow": f"{color_yellow}"
}

# HTTP client configuration
common_timeout = 7
http_custom_user_agent = f'{appname}/{appversion} (https://docs.vmst.io/projects/{appname})'
http_custom_headers = {'User-Agent': http_custom_user_agent}
http_client = httpx.Client(http2=True, follow_redirects=True, headers=http_custom_headers, timeout=common_timeout)
http_codes_to_softfail = [451, 429, 423, 422, 405, 404, 403, 402, 401, 400]
http_codes_to_hardfail = [418, 410]

def get_cache_file_path(url: str) -> str:
    # Create a unique cache file path based on the URL
    url_hash = hashlib.md5(url.encode()).hexdigest()
    cache_dir = '/tmp/vmcrawl_cache'
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
        response = httpx.get(url)
        response.raise_for_status()
        lines = response.text.splitlines()

        for i, line in enumerate(lines):
            match = re.search(r'def (\w+)', line)
            if match:
                key = match.group(1)
                if key in ["major", "minor", "patch", "default_prerelease"]:
                    value = lines[i+1].strip()
                    if value.isnumeric() or re.match(r"'[^']+'", value):
                        version_info[key] = value.replace("'", "")
    except httpx.HTTPError as e:
        print(f"Failed to retrieve Mastodon main version: {e}")
        return {}

    return version_info

def get_highest_mastodon_version():
    release_url = "https://api.github.com/repos/mastodon/mastodon/releases"
    cache_file_path = get_cache_file_path(release_url)
    max_cache_age = 3600  # 1 hour in seconds

    if is_cache_valid(cache_file_path, max_cache_age):
        with open(cache_file_path, 'r') as cache_file:
            highest_version = cache_file.read().strip()
    else:
        response = http_client.get(release_url)
        if response.status_code == 200:
            releases = response.json()
            highest_version = None
            for release in releases:
                release_version = release["tag_name"]

                # Preprocess the version string to remove the 'v' symbol
                if "v" in release_version:
                    release_version = release_version.split("v")[1]

                if highest_version is None or version.parse(release_version) > version.parse(highest_version):
                    highest_version = release_version

            with open(cache_file_path, 'w') as cache_file:
                if highest_version is not None:
                    cache_file.write(highest_version)
        else:
            print("Failed to retrieve latest Mastodon release version. HTTP Status Code:", response.status_code)
            return None

    return highest_version

def get_main_version_release():
    url = "https://raw.githubusercontent.com/mastodon/mastodon/refs/heads/main/lib/mastodon/version.rb"
    cache_file_path = get_cache_file_path(url)
    max_cache_age = 3600  # 1 hour in seconds

    if is_cache_valid(cache_file_path, max_cache_age):
        with open(cache_file_path, 'r') as cache_file:
            version_info = {}
            for line in cache_file:
                key, value = line.strip().split(':')
                version_info[key] = value
    else:
        version_info = read_main_version_info(url)
        with open(cache_file_path, 'w') as cache_file:
            for key, value in version_info.items():
                cache_file.write(f"{key}:{value}\n")

    major = version_info.get('major', '0')
    minor = version_info.get('minor', '0')
    patch = version_info.get('patch', '0')
    pre = version_info.get('default_prerelease', 'alpha.0')

    obtained_main_version = f"{major}.{minor}.{patch}-{pre}"
    return obtained_main_version

def get_main_version_branch():
    url = "https://raw.githubusercontent.com/mastodon/mastodon/refs/heads/main/lib/mastodon/version.rb"
    cache_file_path = get_cache_file_path(url)
    max_cache_age = 3600  # 1 hour in seconds

    if is_cache_valid(cache_file_path, max_cache_age):
        with open(cache_file_path, 'r') as cache_file:
            version_info = {}
            for line in cache_file:
                key, value = line.strip().split(':')
                version_info[key] = value
    else:
        version_info = read_main_version_info(url)
        with open(cache_file_path, 'w') as cache_file:
            for key, value in version_info.items():
                cache_file.write(f"{key}:{value}\n")

    major = version_info.get('major', '0')
    minor = version_info.get('minor', '0')

    obtained_main_branch = f"{major}.{minor}"
    return obtained_main_branch

# Common variables
error_threshold = int(common_timeout)
version_main_branch = get_main_version_branch()
version_main_release = get_main_version_release()
version_latest_release = get_highest_mastodon_version()

def update_patch_versions():
    """
    Update the patch versions in the database.
    """
    with conn.cursor() as cur:
        cur.execute("UPDATE patch_versions SET software_version = %s WHERE main = TRUE", (version_main_branch,))
        cur.execute("UPDATE patch_versions SET software_version = %s WHERE release = TRUE AND n_level = 0", (version_latest_release,))
        conn.commit()

update_patch_versions()

def print_colored(text: str, color: str, **kwargs) -> None:
    print(f"{colors.get(color, '')}{text}{colors['reset']}", **kwargs)

def get_domain_endings():
    domain_endings_url = 'http://data.iana.org/TLD/tlds-alpha-by-domain.txt'
    cache_file_path = get_cache_file_path(domain_endings_url)
    max_cache_age = 86400  # 1 day in seconds

    if is_cache_valid(cache_file_path, max_cache_age):
        with open(cache_file_path, 'r') as cache_file:
            domain_endings = [line.strip().lower() for line in cache_file.readlines()]
    else:
        domain_endings_response = http_client.get(domain_endings_url)
        if domain_endings_response.status_code in [200]:
            domain_endings = [line.strip().lower() for line in domain_endings_response.text.splitlines() if not line.startswith('#')]
            with open(cache_file_path, 'w') as cache_file:
                cache_file.write('\n'.join(domain_endings))
        else:
            raise Exception(f"Failed to fetch domain endings. HTTP Status Code: {domain_endings_response.status_code}")

    return domain_endings

def get_iftas_dni():
    iftas_dns_url = "https://connect.iftas.org/wp-content/uploads/2024/04/dni.csv"
    cache_file_path = get_cache_file_path(iftas_dns_url)
    max_cache_age = 86400  # 1 day in seconds

    if is_cache_valid(cache_file_path, max_cache_age):
        with open(cache_file_path, 'r') as cache_file:
            iftas_domains = [line.strip().lower() for line in cache_file.readlines()]
    else:
        iftas_dns_response = http_client.get(iftas_dns_url)
        if iftas_dns_response.status_code in [200]:

            csv_content = StringIO(iftas_dns_response.text)
            reader = csv.DictReader(csv_content)
            iftas_domains = [row['#domain'].strip().lower() for row in reader if '#domain' in row]

            with open(cache_file_path, 'w') as cache_file:
                cache_file.write('\n'.join(iftas_domains))
        else:
            raise Exception(f"Failed to fetch IFTAS DNS. HTTP Status Code: {iftas_dns_response.status_code}")

    return iftas_domains

def is_running_headless():
    return not os.isatty(sys.stdout.fileno())
