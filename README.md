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

On your PostgreSQL server, execute the contents of `creation.sql` to create the required tables.

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

**Native:**
```bash
./vmcrawl.sh fetch
```

**Docker:**
```bash
docker exec vmcrawl ./vmcrawl.sh fetch
```

The first time this is launched it will default to polling `vmst.io` for instances to crawl.
If you wish to override this you can target a specific instance:

**Native:**
```bash
./vmcrawl.sh fetch --target example.social
```

**Docker:**
```bash
docker exec vmcrawl ./vmcrawl.sh fetch --target example.social
```

Once you have established a set of known good Mastodon instances, you can use them to fetch new federated instances:

**Native:**
```bash
./vmcrawl.sh fetch
```

**Docker:**
```bash
docker exec vmcrawl ./vmcrawl.sh fetch
```

This will scan the top 10 instances in your database by total users.

You can change the limits or offset the domain list from the top:

**Native:**
```bash
./vmcrawl.sh fetch --limit 100 --offset 50
```

**Docker:**
```bash
docker exec vmcrawl ./vmcrawl.sh fetch --limit 100 --offset 50
```

You can use `limit` and `offset` together, or individually, but neither option can be combined with the `target` argument.

Unless you specifically target a server, `vmcrawl.sh fetch` will only attempt to fetch from instances with over 100 active users.
If a server fails to fetch, it will be added to a `no_peers` table and not attempt to fetch new instances from it in the future.

You can also select a random sampling of servers to fetch from, instead of going by user count:

**Native:**
```bash
./vmcrawl.sh fetch --random
```

**Docker:**
```bash
docker exec vmcrawl ./vmcrawl.sh fetch --random
```

You can combine `random` with the `limit` command, but not with `target` or `offset`.

### Crawling Instances

After you have a list of instances to crawl, run the following command:

**Native:**
```bash
./vmcrawl.sh
```

**Docker:**
```bash
docker exec -it vmcrawl ./vmcrawl.sh
```

Selecting `0` from the interactive menu will begin to process all of your fetched domains.

#### Menu Options

You can customize the crawling process with the following options:

**Process new domains:**

- `0` Recently Fetched

**Change process direction:**

- `1` Standard Alphabetical List
- `2` Reverse Alphabetical List
- `3` Random Order (this is the default option for headless runs)

**Retry fatal errors:**

- `6` Other Platforms (non-Mastodon instances)
- `7` Rejected (HTTP 410/418 errors)
- `8` Failed (NXDOMAIN/emoji domains)
- `9` Crawling Prohibited (robots.txt blocks)

**Retry connection errors:**

- `10` SSL (certificate errors)
- `11` HTTP (general HTTP errors)
- `12` TCP (timeouts, connection issues)
- `13` MAX (maximum redirects exceeded)
- `14` DNS (name resolution failures)

**Retry HTTP errors:**

- `20` 2xx status codes
- `21` 3xx status codes
- `22` 4xx status codes
- `23` 5xx status codes

**Retry specific errors:**

- `30` JSON parsing errors
- `31` TXT/plain text response errors
- `32` API errors

**Retry known instances:**

- `40` Unpatched (instances not running latest patches)
- `41` Main (instances on development/main branch)
- `42` Development (instances running alpha, beta, or rc versions)
- `43` Inactive (0 active monthly users)
- `44` All Good (all known instances)
- `45` Misreporting (instances with invalid version data)

**Retry general errors:**

- `50` Domains with >14 Errors
- `51` Domains with 7-14 Errors

#### Headless Crawling

By default, when the script is run headless it will do a random crawl of instances in the database.

To limit what is crawled in headless mode, use the following arguments:

- `--new` will function like option `0`, and only process new domains recently fetched.

#### Targeting

You can target a specific domain to fetch or crawl with the `target` option:

**Native:**
```bash
./vmcrawl.sh --target vmst.io
```

**Docker:**
```bash
docker exec -it vmcrawl ./vmcrawl.sh --target vmst.io
```

You can include multiple domains in a comma-separated list:

**Native:**
```bash
./vmcrawl.sh --target mas.to,infosec.exchange
```

**Docker:**
```bash
docker exec -it vmcrawl ./vmcrawl.sh --target mas.to,infosec.exchange
```

You can also process multiple domains using an external file, which contains each domain on a new line:

**Native:**
```bash
./vmcrawl.sh --file ~/domains.txt
```

**Docker:**
```bash
docker exec -it vmcrawl ./vmcrawl.sh --file /opt/vmcrawl/domains.txt
```

### Nightly Version Management

The `nightly` subcommand manages tracking of development/nightly versions:

**Native:**
```bash
./vmcrawl.sh nightly
```

**Docker:**
```bash
docker exec -it vmcrawl ./vmcrawl.sh nightly
```

This displays current nightly version entries and allows you to add new versions as they are released. Nightly versions are used to identify instances running pre-release software (alpha, beta, rc versions).

**List all nightly versions:**

**Native:**
```bash
./vmcrawl.sh nightly --list
```

**Docker:**
```bash
docker exec vmcrawl ./vmcrawl.sh nightly --list
```

**Add a version via command line:**

**Native:**
```bash
./vmcrawl.sh nightly --version 4.9.0-alpha.7 --start-date 2025-01-15
```

**Docker:**
```bash
docker exec vmcrawl ./vmcrawl.sh nightly --version 4.9.0-alpha.7 --start-date 2025-01-15
```

### DNI List Management

The `dni` subcommand fetches and manages the IFTAS DNI (Do Not Interact) list:

**Fetch and import DNI list:**

**Native:**
```bash
./vmcrawl.sh dni
```

**Docker:**
```bash
docker exec vmcrawl ./vmcrawl.sh dni
```

**List all DNI domains:**

**Native:**
```bash
./vmcrawl.sh dni --list
```

**Docker:**
```bash
docker exec vmcrawl ./vmcrawl.sh dni --list
```

**Count DNI domains:**

**Native:**
```bash
./vmcrawl.sh dni --count
```

**Docker:**
```bash
docker exec vmcrawl ./vmcrawl.sh dni --count
```

**Use custom CSV URL:**

**Native:**
```bash
./vmcrawl.sh dni --url https://example.com/custom-dni-list.csv
```

**Docker:**
```bash
docker exec vmcrawl ./vmcrawl.sh dni --url https://example.com/custom-dni-list.csv
```

The DNI list is sourced from IFTAS (Independent Federated Trust & Safety) and contains domains that have been identified for various trust and safety concerns. All domains imported from the IFTAS list are tagged with the comment "iftas" in the database.

## Configuration

### Backport Branches

You will need to maintain the environment variable `VMCRAWL_BACKPORTS` in a comma-separated list with the branches you wish to maintain backport information for.

Example:

```bash
VMCRAWL_BACKPORTS="4.5,4.4,4.3,4.2"
```

### Concurrency

You can configure the number of concurrent domain processing tasks via the `VMCRAWL_MAX_THREADS` environment variable (default: 2):

```bash
VMCRAWL_MAX_THREADS="4"
```

The crawler uses Python's `asyncio` for concurrent I/O operations, with an `asyncio.Semaphore` limiting concurrent domain processing to the configured value.

### DNS Caching

DNS resolution results are cached in-memory for 5 minutes (300 seconds) to reduce repeated DNS lookups when crawling domains. The cache holds up to 10,000 entries and is automatically managed.

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
