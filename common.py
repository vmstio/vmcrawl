try:
    import httpx
except ImportError as e:
    print(f"Error importing module: {e}")

appname = 'vmcrawl'
appversion = '0.1'

# Add your color constants here
color_bold = '\033[1m'
color_red = '\033[91m'
color_green = '\033[92m'
color_yellow = '\033[93m'
color_magenta = '\033[95m'
color_cyan = '\033[96m'
color_orange = '\033[38;5;208m'
color_pink = '\033[38;5;198m'
color_purple = '\033[94m'
color_reset = '\033[0m'

colors = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "pink": "\033[38;5;198m",
    "yellow": "\033[93m",
    "orange": "\033[38;5;208m",
    "cyan": "\033[96m",
    "red": "\033[91m",
    "green": "\033[92m",
    "cyan": "\033[96m",
    "magenta": "\033[95m",
    "purple": "\033[94m",
}

# HTTP client configuration
httpx_version = httpx.__version__
default_user_agent = 'python-httpx/{httpx_version}'
appended_user_agent = '{appname}/{appversion} (https://docs.vmst.io/projects/{appname})'
custom_headers = {
    'User-Agent': appended_user_agent,
}

http_client = httpx.Client(http2=True, follow_redirects=True, headers=custom_headers, timeout=5)