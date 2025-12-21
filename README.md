# vmcrawl

## Overview

`vmcrawl` is a Mastodon-focused version reporting crawler.
It is written in Python, with a Postgres database backend.
It performs periodic polling of known Mastodon instances.

## Installation

To install `vmcrawl`, clone the repository and install the dependencies.
It is reccomended to use a dedicated Python virtual envionment within the cloned folder.

```bash
git clone https://github.com/vmstio/vmcrawl.git
cd vmcrawl
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install .
```

You will then need an `.env` file in the `vmcrawl` folder with your custom values set:

```bash
VMCRAWL_POSTGRES_DATA="dbname"
VMCRAWL_POSTGRES_USER="username"
VMCRAWL_POSTGRES_PASS="password"
VMCRAWL_POSTGRES_HOST="localhost"
VMCRAWL_POSTGRES_PORT="5432"
```

On your Postgres server, execute the contents of `creation.sql` to create the required tables.

## Usage

To start using `vmcrawl` you will need to populate your database with instances to crawl, you can fetch a list of fediverse instances from an existing Mastodon instance:

```bash
python fetch.py
```

The first time this is launched it will default to polling `vmst.io` for instances to crawl.
If you wish to override this you can target a specific instance.

```bash
python fetch.py --target example.social
```

After you have a list of of instances to crawl, run the following command:

```bash
python crawler.py
```

Selecting `0` from the interactive menu will begin to process all of your fetched domains.

### Menu Options

You can customize the crawling process with the following options:

Process new domains:

- `0` Recently Fetched

Change process direction:

- `1` Standard Alphabetical List
- `2` Reverse Alphabetical List
- `3` Random Order (this is the default option for headless runs)

Retry fatal errors:

- `6` Other Platforms (non-Mastodon instances)
- `7` Rejected (HTTP 410/418 errors)
- `8` Failed (NXDOMAIN/emoji domains)
- `9` Crawling Prohibited (robots.txt blocks)

Retry connection errors:

- `10` SSL (certificate errors)
- `11` HTTP (general HTTP errors)
- `12` TCP (timeouts, connection issues)
- `13` MAX (maximum redirects exceeded)
- `14` DNS (name resolution failures)

Retry HTTP errors:

- `20` 2xx status codes
- `21` 3xx status codes
- `22` 4xx status codes
- `23` 5xx status codes

Retry specific errors:

- `30` JSON parsing errors
- `31` TXT/plain text response errors
- `32` API errors

Retry known instances:

- `40` Unpatched (instances not running latest patches)
- `41` Main (instances on development/main branch)
- `42` Development (instances running alpha, beta, or rc versions)
- `43` Inactive (0 active monthly users)
- `44` All Good (all known instances)
- `45` Misreporting (instances with invalid version data)

Retry general errors:

- `50` Domains with >14 Errors
- `51` Domains with 7-14 Errors

### Headless Crawling

By default, when the script is run headless it will do a random crawl of instances in the database.

To limit what is crawled in headless mode, use the following arguments.

- `--new` will function like option `0`, and only process new domains recently fetched.

### Targeting

You can target a specific domain to fetch or crawl with the `target` option:

```bash
python crawler.py --target vmst.io
```

You can include multiple domains in a comma seperated list:

```bash
python crawler.py --target mas.to,infosec.exchange
```

You can also process multiple domains using an external file, with contains each domain on a new line:

```bash
python crawler.py --file ~/domains.txt
```

### Other Fetching Options

Once you have established a set of known good Mastodon instances, you can use them to fetch new federated instances.

```bash
python fetch.py
```

This will scan the top 10 instances in your database by total users.

You can change the limits or offset the domain list from the top, using something like:

```bash
python fetch.py --limit 100 --offset 50
```

You can use `limit` and `offset` together, or individually, but neither option can be combined with the `target` argument.

Unless you specifically target a server, `fetch.py` will only attempt to fetch from instances with over 100 active users.
If a server fails to fetch, it will be added to a `no_peers` table and not attempt to fetch new instances from it in the future.

You can also select a random sampling of servers to fetch from, instead of going by user count.

```bash
python fetch.py --random
```

You can combine `random` with the `limit` command, but not with `target` or `offset`.

## Nightly Versions

You will need to manually maintain the `nightly_versions` table as new development release versions drop.
This may be automated in the future.

## Backport Branches

You will need to maintain the environment variable `VMCRAWL_BACKPORTS` in a comma seperated list with the branches you wish to maintain backport information for.

Example:

```bash
4.5,4.4,4.3,4.2
```

## Contributing

We welcome contributions! Please read our [contributing guidelines](CONTRIBUTING.md) for more details.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.

## Contact

For any questions or feedback, please open an issue on GitHub.
