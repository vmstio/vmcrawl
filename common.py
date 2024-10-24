try:
    import httpx
    import toml
except ImportError as e:
    print(f"Error importing module: {e}")

# Versioning information
toml_file_path='pyproject.toml'
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
http_codes_to_fail = [451, 429, 422, 418, 410, 405, 404, 403, 402, 401, 400, 300]

# Common variables
error_threshold = int(7)
version_main_branch = "4.4"
version_latest_release = "4.3.1"

def print_colored(text: str, color: str, **kwargs) -> None:
    print(f"{colors.get(color, '')}{text}{colors['reset']}", **kwargs)

def get_domain_endings():
    # Obtain the list of domain endings
    domain_endings_url = 'http://data.iana.org/TLD/tlds-alpha-by-domain.txt'
    domain_endings_response = http_client.get(domain_endings_url)
    if domain_endings_response.status_code in [200]:
        domain_endings = [line.strip().lower() for line in domain_endings_response.text.splitlines() if not line.startswith('#')]
        return domain_endings
    else:
        raise Exception(f"Failed to fetch domain endings. HTTP Status Code: {domain_endings_response.status_code}")