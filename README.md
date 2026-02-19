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

| Command             | Purpose                                                                                  |
| ------------------- | ---------------------------------------------------------------------------------------- |
| `crawler.py`        | Default crawl mode - processes domains, collects version/user data, generates statistics |
| `crawler.py fetch`  | Fetches new domains from federated instance peer lists                                   |
| `crawler.py manage` | Interactive menu for database and version management                                     |

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
If a server fails to fetch with persistent errors, `mastodon_domains.peers` is set to `false` and it will not be polled in future non-targeted fetch runs.

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

### Database and Version Management

The crawler provides comprehensive database and version management through an interactive manage menu:

```bash
./vmcrawl.sh manage
```

#### Manage Menu Quick Reference

| Option | Category  | Action                         |
| ------ | --------- | ------------------------------ |
| `1`    | DNI       | Fetch and import DNI list      |
| `2`    | DNI       | List all DNI domains           |
| `3`    | DNI       | Count DNI domains              |
| `4`    | DNI       | Add DNI domain manually        |
| `5`    | DNI       | Remove DNI domain              |
| `6`    | Nightly   | List all nightly versions      |
| `7`    | Nightly   | Add a new nightly version      |
| `8`    | Nightly   | Update nightly version end date|
| `9`    | Mastodon  | Update latest Mastodon versions|
| `10`   | Mastodon  | Show current version info      |
| `11`   | Mastodon  | Promote branch to release      |
| `12`   | Mastodon  | Mark branch as EOL             |
| `13`   | Mastodon  | Reorder release branches       |
| `14`   | TLD Cache | Update TLD cache               |

#### DNI Management (Options 1-5)

Manages the IFTAS DNI (Do Not Interact) list and manual DNI entries for trust and safety controls.

- **Option 1: Fetch and import DNI list** - Downloads the latest IFTAS DNI CSV source and imports new domains
- **Option 2: List all DNI domains** - Displays all domains currently in the DNI table with comment/force/timestamp
- **Option 3: Count DNI domains** - Shows total count of DNI domains
- **Option 4: Add DNI domain manually** - Prompts for `domain`, `comment`, and `force` (`hard` or `soft`)
- **Option 5: Remove DNI domain** - Prompts for a domain and removes it from DNI table

Manual DNI entries are useful for local policy overrides without waiting for the upstream feed.

#### Nightly Version Management (Options 6-8)

Manages tracking of development/nightly versions used to identify instances running pre-release software (alpha, beta, rc versions).

**Submenu Options:**

**1. List all nightly versions** - Displays all tracked nightly/development versions with their date ranges

**2. Add new nightly version** - Interactive workflow to add a new pre-release version:
- Enter version string (e.g., 4.9.0-alpha.7)
- Enter start date (when version was released)
- Optionally enter end date (when version was superseded)
- Choose whether to auto-update the previous version's end date

**3. Update end date** - Modify the end date of an existing nightly version

When a new nightly version is added, the system can automatically set the end date of the previous nightly version to maintain a continuous timeline of development releases.

#### Mastodon Release Version Management (Options 9-13)

The crawler provides a comprehensive version management system for tracking Mastodon releases and their lifecycle from main development branch through release to end-of-life.

**Version Tracking Overview:**

The crawler maintains a unified `release_versions` table that tracks:
- **Main branch**: Current development version (n_level = -1)
- **Release branches**: Active stable releases (n_level = 0, 1, 2, ...)
- **EOL branches**: End-of-life releases no longer receiving updates

Version tracking is **manual-only** - all branch lifecycle management is controlled through the manage menu. The crawler automatically updates the latest version within each tracked branch but does not automatically promote or deprecate branches.

**GitHub CLI Integration:**

The crawler uses the `gh` CLI tool for GitHub API calls when available, providing:
- Better rate limits for authenticated users
- More reliable access to release data
- Fallback to HTTP API if `gh` is not authenticated or available

To authenticate the GitHub CLI:
```bash
gh auth login
```

**Option 9: Update Latest Mastodon Versions**

Updates the `latest` version for all tracked branches (main, release, and EOL) by querying the Mastodon GitHub repository. This should be run periodically to keep version data current.

- Fetches up to 500 releases from GitHub to ensure old EOL versions are updated
- Updates only the `latest` column for existing branches
- Does not create new branches or change branch status

**Option 10: Show Current Version Information**

Displays a detailed view of all tracked Mastodon versions:
```
Main Development Version:
  Branch: 4.4    Status: main      n_level: -1    Latest: 4.4.0+nightly-20250215

Active Release Branches:
  Branch: 4.3    Status: release   n_level: 0     Latest: 4.3.3
  Branch: 4.2    Status: release   n_level: 1     Latest: 4.2.15
  Branch: 4.1    Status: release   n_level: 2     Latest: 4.1.22

End-of-Life Branches:
  Branch: 4.0    Status: eol       n_level: 3     Latest: 4.0.15
```

**Option 11: Promote Main Branch to Release**

Promotes the current main development branch to a release branch and creates a new main branch for the next version.

Workflow:
1. Shows current main branch (e.g., 4.4)
2. Confirms promotion to release status
3. Shifts all existing release branches down (increases n_level by 1)
4. Converts main branch to release at n_level = 0
5. Creates new main branch with incremented version (e.g., 4.5)

This should be used when a new stable version is released.

**Option 12: Mark Branch as End-of-Life**

Marks a release branch as EOL when it no longer receives updates.

Workflow:
1. Shows list of current release branches
2. Select branch to mark as EOL
3. Branch status changes to 'eol' and is moved to the end of the tracking list

EOL branches continue to be tracked for statistics but are not considered "supported" releases.

**Option 13: Reorder Release Branches**

Manually adjusts the ordering (n_level) of release branches. This is useful if you need to reorganize the priority of tracked releases.

Workflow:
1. Shows current release branches with current order
2. Enter a full new order as a comma-separated branch list (e.g. `4.6,4.5,4.4`)
3. All release branches are re-assigned `n_level` based on the provided order

#### TLD Cache Management (Option 14)

- **Option 14: Update TLD cache** - Fetches the latest IANA TLD list and refreshes the `tld_cache` table.

**Version Lifecycle Workflow:**

Typical version management workflow:

1. **New Development Begins**: Main branch tracks next version (e.g., 4.5.0+nightly)
2. **Regular Updates**: Run Option 9 periodically to update latest versions
3. **New Release**: Use Option 11 to promote main to release when stable version ships
4. **EOL Declaration**: Use Option 12 to mark old releases as EOL when support ends
5. **Monitoring**: Use Option 10 to review current version status

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
```

**Note:** Version tracking is now managed through the database via the manage menu. The `VMCRAWL_BACKPORTS` environment variable is no longer used.

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
