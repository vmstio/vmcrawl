# vmcrawl

## Overview

`vmcrawl` is a Mastodon-focused version reporting crawler.
It is written in Python, with a PostgreSQL database backend.
It performs periodic polling of known Mastodon instances to track version information, user counts, and security patch status.

## Requirements

- Python 3.13 or higher
- PostgreSQL database
- [UV](https://docs.astral.sh/uv/)

## Installation

### Quick Start (Development)

For development or testing, you can quickly set up `vmcrawl` in the current directory:

```bash
git clone https://github.com/vmstio/vmcrawl.git
cd vmcrawl
uv sync
./vmcrawl.sh
```

### Production Installation

For production deployments, follow these steps to install `vmcrawl` as a system service:

#### 1. Install Application

```bash
# Clone application files
git clone https://github.com/vmstio/vmcrawl.git /opt/vmcrawl
```

#### 2. Create System User

```bash
# Create vmcrawl user and set ownership
useradd -r -s /bin/bash -d /opt/vmcrawl vmcrawl
chown -R vmcrawl:vmcrawl /opt/vmcrawl
```

#### 3. Set Up Virtual Environment

```bash
# Switch to vmcrawl user
sudo -u vmcrawl -i

# Install uv package manager
curl -LsSf https://astral.sh/uv/install.sh | sh

# Exit and log back in to refresh the PATH
exit
sudo -u vmcrawl -i

# Create virtual environment and install dependencies
cd /opt/vmcrawl
uv sync

# Exit vmcrawl user
exit
```

#### 4. Configure Environment Variables

```bash
sudo -u vmcrawl vim /opt/vmcrawl/.env
```

Add your configuration:

```bash
VMCRAWL_POSTGRES_DATA="dbname"
VMCRAWL_POSTGRES_USER="username"
VMCRAWL_POSTGRES_PASS="password"
VMCRAWL_POSTGRES_HOST="localhost"
VMCRAWL_POSTGRES_PORT="5432"
```

On your PostgreSQL server, execute the contents of `database.sql` to create tables and indexes.

#### 5. Install Service Files

```bash
# Make the shell script executable
chmod +x /opt/vmcrawl/vmcrawl.sh

# Copy service files to systemd
cp /opt/vmcrawl/vmcrawl.service /etc/systemd/system/

# Reload systemd
systemctl daemon-reload
```

#### 6. Enable and Start Services

```bash
# Enable crawler service to start on boot
systemctl enable vmcrawl.service

# Start the crawler service
systemctl start vmcrawl.service

# Check crawler status
systemctl status vmcrawl.service
```

### Docker Installation

You can also run `vmcrawl` using Docker:

```bash
docker build -t vmcrawl .
docker run -d --name vmcrawl --env-file .env vmcrawl
```

## Scripts

The project includes a single main script with multiple subcommands:

| Command              | Purpose                                                                    |
| -------------------- | -------------------------------------------------------------------------- |
| `crawler.py`         | Default crawl mode - processes domains, collects version/user data, generates statistics |
| `crawler.py crawl`   | Same as default - crawl version information from Mastodon instances        |
| `crawler.py fetch`   | Fetches new domains from federated instance peer lists                     |
| `crawler.py dni`     | Fetches and manages IFTAS DNI (Do Not Interact) list of blocked domains    |
| `crawler.py nightly` | Manages nightly/development version tracking in the database               |

### Automated Tasks

**Statistics Generation:**

Statistics are automatically generated and recorded by the main crawler (`crawler.py`) during its crawling operations. Historical statistics tracking is integrated into the crawling workflow, eliminating the need for a separate statistics service.

## Usage

### Fetching Domains

To start using `vmcrawl` you will need to populate your database with instances to crawl. You can fetch a list of fediverse instances from an existing Mastodon instance:

```bash
./vmcrawl.sh fetch
```

The first time this is launched it will default to polling `vmst.io` for instances to crawl.
If you wish to override this you can target a specific instance:

```bash
./vmcrawl.sh fetch --target example.social
```

Once you have established a set of known good Mastodon instances, you can use them to fetch new federated instances:

```bash
./vmcrawl.sh fetch
```

This will scan the top 10 instances in your database by total users.

You can change the limits or offset the domain list from the top:

```bash
./vmcrawl.sh fetch --limit 100 --offset 50
```

You can use `limit` and `offset` together, or individually, but neither option can be combined with the `target` argument.

Unless you specifically target a server, `vmcrawl.sh fetch` will only attempt to fetch from instances with over 100 active users.
If a server fails to fetch, it will be added to a `no_peers` table and not attempt to fetch new instances from it in the future.

You can also select a random sampling of servers to fetch from, instead of going by user count:

```bash
./vmcrawl.sh fetch --random
```

You can combine `random` with the `limit` command, but not with `target` or `offset`.

### Crawling Instances

After you have a list of instances to crawl, run the following command:

```bash
./vmcrawl.sh
```

Selecting `0` from the interactive menu will begin to process all of your fetched domains.

#### Menu Options

The crawler provides an interactive curses-based menu with color support and arrow key navigation when run in a terminal (TTY mode). In headless mode, it automatically uses text-based prompts.

You can customize the crawling process with the following options:

**Process new domains:**

- `0` Uncrawled (recently fetched domains)

**Change process direction:**

- `1` Standard (alphabetical)
- `2` Reverse (reverse alphabetical)
- `3` Random (default for headless runs)

**Retry any (non-fatal) errors:**

- `4` Offline (all domains with errors)
- `5` Issues (known Mastodon instances with errors)

**Retry fatal errors:**

- `10` Other (non-Mastodon platforms)

**Retry errors by type:**

- `20` DNS (name resolution failures)
- `21` SSL (certificate errors)
- `22` TCP (connection errors)
- `23` Type (content type errors)
- `24` Size (response size errors)
- `25` API (API errors)
- `26` JSON (JSON parsing errors)
- `27` HTTP 2xx status codes
- `28` HTTP 3xx redirects
- `29` HTTP 4xx client errors
- `30` HTTP 5xx server errors
- `31` Hard Fail (HTTP 410/418/451/999)
- `32` Robots (robots.txt prohibited)

**Retry known instances:**

- `50` Unpatched (instances not running latest patches)
- `51` Main (instances on development/main branch)
- `52` Active (instances with active monthly users)
- `53` All (all known instances)

**Retry terminal error states:**

Terminal states are domains that have failed repeatedly and been marked as permanently bad. These options retry them:

- `60` DNS (bad_dns flag)
- `61` SSL (bad_ssl flag)
- `62` TCP (bad_tcp flag)
- `63` Type (bad_type flag)
- `64` File (bad_file flag)
- `65` API (bad_api flag)
- `66` JSON (bad_json flag)
- `67` HTTP 2xx (bad_http2xx flag)
- `68` HTTP 3xx (bad_http3xx flag)
- `69` HTTP 4xx (bad_http4xx flag)
- `70` HTTP 5xx (bad_http5xx flag)
- `71` Hard Fail (bad_hard flag - HTTP 410/418/451/999)
- `72` Robots (bad_robot flag - robots.txt prohibited)

**Menu Navigation (TTY mode):**

- Arrow keys or `j/k` - Navigate options
- Enter - Select option
- `q` or Esc - Quit

### Discovery Flow

The crawler uses a probe-first discovery flow per domain:

1. Check `robots.txt`
2. Probe `/.well-known/nodeinfo` on the original domain with suppressed errors
3. If probe fails, run host-meta and webfinger discovery in parallel
4. Retry nodeinfo on discovered backend domain
5. Resolve NodeInfo data (direct return or follow NodeInfo 2.0 URL)
6. Branch to Mastodon or non-Mastodon processing

#### Discovery Methods

- `host-meta` (`/.well-known/host-meta`) and `webfinger` (`/.well-known/webfinger`) run concurrently.
- host-meta result is preferred when both methods succeed.
- if both fail, crawler falls back to original domain and replays the suppressed probe error.
- if fallback occurs without a captured probe-error object, crawler records `TCP+nodeinfo`.

#### NodeInfo and Platform Handling

- Matrix servers (`m.server` in nodeinfo response) are marked as `matrix` and skipped as non-error.
- Some servers return full NodeInfo directly at the well-known endpoint; this is accepted without another fetch.
- For Mastodon instances:
  - instance API is queried (`/api/v2/instance`, fallback `/api/v1/instance`) to obtain canonical domain.
  - version and MAU are validated before writing to `mastodon_domains`.
- For non-Mastodon instances:
  - software name is stored in `raw_domains.nodeinfo`.
  - errors/reason are cleared because platform mismatch is not an error condition.

#### HTTP Transport Behavior

- Requests use an HTTP/2-enabled `httpx` client by default.
- On `httpx.RemoteProtocolError` (servers that break HTTP/2 sessions), the request is retried once with an HTTP/1.1-only client.

#### Terminal Retry Behavior (60-72)

- Same terminal failure type: preserve existing `bad_*` state and do not rewrite `errors`/`reason`.
- Different terminal failure type: clear previously preserved `bad_*` state so status can transition.

#### Headless Crawling

By default, when the script is run headless it will do a random crawl of instances in the database.

To limit what is crawled in headless mode, use the following arguments:

- `--new` will function like option `0`, and only process new domains recently fetched.

#### Targeting

You can target a specific domain to fetch or crawl with the `target` option:

```bash
./vmcrawl.sh --target vmst.io
```

You can include multiple domains in a comma-separated list:

```bash
./vmcrawl.sh --target mas.to,infosec.exchange
```

You can also process multiple domains using an external file, which contains each domain on a new line:

```bash
./vmcrawl.sh --file ~/domains.txt
```

### Nightly Version Management

The `nightly` subcommand manages tracking of development/nightly versions:

```bash
./vmcrawl.sh nightly
```

This displays current nightly version entries and allows you to add new versions as they are released. Nightly versions are used to identify instances running pre-release software (alpha, beta, rc versions).

**List all nightly versions:**

```bash
./vmcrawl.sh nightly --list
```

**Add a version interactively:**

```bash
./vmcrawl.sh nightly --add
```

**Add a version via command line:**

```bash
./vmcrawl.sh nightly --version 4.9.0-alpha.7 --start-date 2025-01-15
```

**Add with custom end date:**

```bash
./vmcrawl.sh nightly --version 4.9.0-alpha.7 --start-date 2025-01-15 --end-date 2025-02-01
```

**Disable automatic end date update:**

By default, adding a new nightly version automatically updates the previous version's end date. To disable this:

```bash
./vmcrawl.sh nightly --version 4.9.0-alpha.7 --start-date 2025-01-15 --no-auto-update
```

**Update end date for existing version:**

```bash
./vmcrawl.sh nightly --update-end-date 4.9.0-alpha.6 2025-01-14
```

### DNI List Management

The `dni` subcommand fetches and manages the IFTAS DNI (Do Not Interact) list:

**Fetch and import DNI list:**

```bash
./vmcrawl.sh dni
```

**List all DNI domains:**

```bash
./vmcrawl.sh dni --list
```

**Count DNI domains:**

```bash
./vmcrawl.sh dni --count
```

**Use custom CSV URL:**

```bash
./vmcrawl.sh dni --url https://example.com/custom-dni-list.csv
```

The DNI list is sourced from IFTAS (Independent Federated Trust & Safety) and contains domains that have been identified for various trust and safety concerns. The crawler imports both the IFTAS DNI list and the Abandoned/Unmanaged list. All domains are tagged with their source:
- `iftas-dni` - Domains on the Do Not Interact list
- `iftas-abandoned` - Abandoned or unmanaged instances

## Advanced Features

### HTTP/2 Support with Automatic Fallback

The crawler uses HTTP/2 by default for all requests, with automatic fallback to HTTP/1.1 for servers that have protocol compatibility issues. The HTTP client is configured with:
- TLS 1.2+ minimum
- Certificate verification enabled
- Connection pooling for improved performance
- 10MB default response size limit

### DNS Response Caching

DNS lookups are cached in-memory with a 5-minute TTL to reduce repeated DNS queries. The cache:
- Holds up to 10,000 entries
- Uses thread-safe monkey-patching of `socket.getaddrinfo`
- Automatically evicts old entries

### Emoji Domain Support

The crawler supports International Domain Names (IDN) including emoji domains (e.g., 🍕.ws) through IDNA library patching.

### Alias Domain Detection

Domains can be automatically detected as aliases of canonical domains. When a domain is marked as an alias:
- All error state is cleared
- Future crawls skip the alias domain
- The canonical domain is tracked instead

### Terminal State Preservation

When retrying domains with terminal error states (menu options 60-72):
- If the domain fails again with the **same error type**, the existing error count and state are preserved
- If the domain fails with a **different error type**, the previous terminal state is cleared to allow the status to transition

### Multi-Instance Safe Operations

The crawler uses PostgreSQL advisory locks to prevent race conditions when multiple crawler instances run concurrently. This ensures safe cleanup operations and prevents duplicate work.

### Progress Tracking

In TTY mode, the crawler displays:
- Real-time progress with color-coded status
- Per-domain elapsed time
- Slow domain highlighting (configurable threshold)
- Periodic heartbeat updates

## Configuration

### Required Environment Variables

Configure these in your `.env` file:

```bash
# Database connection
VMCRAWL_POSTGRES_DATA="dbname"
VMCRAWL_POSTGRES_USER="username"
VMCRAWL_POSTGRES_PASS="password"
VMCRAWL_POSTGRES_HOST="localhost"
VMCRAWL_POSTGRES_PORT="5432"

# Backport branches to track (comma-separated)
VMCRAWL_BACKPORTS="4.5,4.4,4.3,4.2"
```

### Optional SSH Tunnel Configuration

For remote database access via SSH tunnel:

```bash
VMCRAWL_SSH_HOST="ssh.example.com"
VMCRAWL_SSH_PORT="22"
VMCRAWL_SSH_USER="username"
VMCRAWL_SSH_KEY="~/.ssh/id_rsa"
VMCRAWL_SSH_KEY_PASS="passphrase"  # Optional
```

### Performance & Concurrency Settings

```bash
# Concurrent domain processing tasks (default: 2)
VMCRAWL_MAX_THREADS="4"

# HTTP request timeout in seconds (default: 5)
VMCRAWL_HTTP_TIMEOUT="10"

# Maximum HTTP redirects to follow (default: 2)
VMCRAWL_HTTP_REDIRECT="5"

# Maximum response size in bytes (default: 10485760 = 10MB)
VMCRAWL_MAX_RESPONSE_SIZE="20971520"
```

The crawler uses Python's `asyncio` for concurrent I/O operations, with an `asyncio.Semaphore` limiting concurrent domain processing to the configured value.

### DNS Configuration

DNS resolution results are cached in-memory for 5 minutes (300 seconds) to reduce repeated DNS lookups when crawling domains. The cache holds up to 10,000 entries and is automatically managed.

Configure DNS retry behavior:

```bash
# DNS retry attempts (default: 3)
VMCRAWL_DNS_RETRY_ATTEMPTS="5"

# Base retry delay in milliseconds (default: 80)
VMCRAWL_DNS_RETRY_BASE_DELAY_MS="100"

# Jitter range in milliseconds (default: 40)
VMCRAWL_DNS_RETRY_JITTER_MS="50"

# Maximum total backoff delay in milliseconds (default: 500)
VMCRAWL_DNS_RETRY_MAX_TOTAL_DELAY_MS="1000"
```

### Error Handling

```bash
# Error threshold before marking domain as bad (default: 24)
VMCRAWL_ERROR_BUFFER="30"
```

### Fetch Mode Settings

```bash
# Default number of domains to fetch from (default: 10)
VMCRAWL_FETCH_LIMIT="20"

# Default offset for domain selection (default: 0)
VMCRAWL_FETCH_OFFSET="5"

# Minimum active users required to fetch peers from instance (default: 100)
VMCRAWL_FETCH_MIN_ACTIVE="50"
```

### Progress Display

```bash
# Progress update frequency in seconds (default: 5)
VMCRAWL_PROGRESS_HEARTBEAT_SECONDS="10"

# Threshold to mark domain as slow in seconds (default: 8)
VMCRAWL_SLOW_DOMAIN_SECONDS="15"
```

### Version Management

```bash
# Version data refresh interval in seconds (default: 3600)
VMCRAWL_VERSION_REFRESH_INTERVAL="7200"
```

### Caching

```bash
# Filter data cache TTL in seconds (default: 300)
VMCRAWL_FILTER_CACHE_SECONDS="600"
```

### API Configuration

```bash
# API authentication key (optional, disables auth if not set)
VMCRAWL_API_KEY="your-secret-key-here"
```

## Service Management

For production installations using systemd:

### View Logs

```bash
# Follow crawler logs in real-time
journalctl -u vmcrawl.service -f

# View recent crawler logs
journalctl -u vmcrawl.service -n 100

# View crawler logs since boot
journalctl -u vmcrawl.service -b
```

### Control Services

**Crawler Service:**
```bash
# Stop service
systemctl stop vmcrawl.service

# Restart service
systemctl restart vmcrawl.service

# Disable service
systemctl disable vmcrawl.service
```

## Troubleshooting

### Service fails to start

1. Check logs: `journalctl -u vmcrawl.service -n 50`
2. Verify permissions: `ls -la /opt/vmcrawl`
3. Test script manually: `sudo -u vmcrawl /opt/vmcrawl/vmcrawl.sh`

### Permission errors

```bash
# Fix ownership
chown -R vmcrawl:vmcrawl /opt/vmcrawl

# Fix script permission
chmod +x /opt/vmcrawl/vmcrawl.sh
```

## Contributing

We welcome contributions! Please read our [contributing guidelines](CONTRIBUTING.md) for more details.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.

## Contact

For any questions or feedback, please open an issue on GitHub.
