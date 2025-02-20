# vmcrawl

## Overview

`vmcrawl` is a Mastodon-focused version of a reporting crawler.
It is written in Python, with a Postgres database backend.
It performs periodic polling of known Mastodon instances.

## Installation

To install `vmcrawl`, clone the repository and install the dependencies.
It is reccomended to use a dedicated Python virtual envionment within the cloned folder.

```bash
git clone https://github.com/vmstio/vmcrawl.git
cd vmcrawl
python -m venv .venv
pip install --upgrade pip
pip install .
```

You will then need an `.env` file in the `vmcrawl` folder with your custom values set:

```
POSTGRES_DB="dbname"
POSTGRES_USER="username"
POSTGRES_PASSWORD="password"
POSTGRES_HOST="localhost"
POSTGRES_PORT="5432"
```

On your Postgres server, execute the contents of `creation.sql` to create the required tables.

## Usage

To start using `vmcrawl` you will need to populate your database with instances to crawl, you can fetch a list of fediverse instances from an existing Mastodon instance:

```bash
python fetch.py --target mastodon.social
```

After you have a list of of instances to crawl, run the following command:

```bash
python crawler.py
```

Selecting `0` from the interactive menu will begin to process all of your fetched domains.

### Menu Options

You can customize the crawling process with the following options:

Change process direction:
1. Standard Alphabetical List
2. Reverse Alphabetical List
3. Random Order (this is the only option for headless runs)

Retry general errors:
4. Error Counts ≥8
5. Error Counts ≤7

Retry fatal errors:
6. Not Mastodon
7. Failed
8. NXDOMAIN
9. NoRobots

Retry connection errors:
10. SSL
11. HTTP
12. TIMEOUT

Retry HTTP errors:
20. 2xx
21. 3xx
22. 4xx
23. 5xx

Retry specific errors:
30. Invalid User Counts (###)
31. JSON
32. TXT
33. XML

Retry good data:
40. Refresh Stale Instances
41. Refresh Outdated Instances
42. Refresh Instances Running Main
43. Refresh Inactive Instances (0 Active Users)
44. Refresh All Known Good Instances

### Targeting

You can target a specific domain to fetch or crawl with the `target` option:

```bash
python crawler.py --target vmst.io
```

You can include multiple domains in a comma seperated list:

```bash
python crawler.py --target mas.to,infosec.exchange
```

You can process multiple domains from an external file, with each domain on a new line:

```bash
python crawler.py --file ~/domains.txt
```

### Fetching Options

Once you have established a set of known good Mastodon instances, you can use them to fetch new federated instances.

```bash
python fetch.py
```

This will scan the top 100 instances in your database by total users.
You can change the limits or offset the domain list from the top, using the following options:

```bash
python fetch.py --limit 10 --offset 50
```

You can use `limit` and `offset` together, or individually, but neither option can be combined with the `target` argument.

## Contributing

We welcome contributions! Please read our [contributing guidelines](CONTRIBUTING.md) for more details.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.

## Contact

For any questions or feedback, please open an issue on GitHub.