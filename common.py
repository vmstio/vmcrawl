try:
    import httpx
except ImportError as e:
    print(f"Error importing module: {e}")

# Versioning information
appname = 'vmcrawl'
appversion = '0.2'

# Add your color constants here
color_bold = '\033[1m'
color_reset = '\033[0m'
color_cyan = '\033[96m'
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
    "green": f"{color_green}",
    "magenta": f"{color_magenta}",
    "orange": f"{color_orange}",
    "pink": f"{color_pink}",
    "purple": f"{color_purple}",
    "red": f"{color_red}",
    "yellow": f"{color_yellow}"
}

# HTTP client configuration
http_custom_user_agent = f'{appname}/{appversion} (https://docs.vmst.io/projects/{appname})'
http_custom_headers = {'User-Agent': http_custom_user_agent}
http_client = httpx.Client(http2=True, follow_redirects=True, headers=http_custom_headers, timeout=5)

# Common variables
error_threshold = int(5)
version_main_branch = "4.4"
version_latest_release = "4.3.0"