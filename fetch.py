#!/usr/bin/env python3

# Import required modules
try:
    import argparse
    import ipaddress
    import os
    import random
    import re
    import sys

    from crawler import (
        appname,
        appversion,
        conn,
        vmc_output,
        is_running_headless,
        http_client,
        get_httpx,
        get_domain_endings,
        has_emoji_chars,
    )
except ImportError as e:
    print(f"Error importing module: {e}")
    sys.exit(1)

# Detect the current filename
current_filename = os.path.basename(__file__)

parser = argparse.ArgumentParser(description="Fetch peer data from Mastodon instances.")
parser.add_argument(
    "-l",
    "--limit",
    type=int,
    help=f'limit the number of domains requested from database (default: {int(os.getenv("VMCRAWL_FETCH_LIMIT", "10"))})',
)
parser.add_argument(
    "-o",
    "--offset",
    type=int,
    help=f'offset the top of the domains requested from database (default: {int(os.getenv("VMCRAWL_FETCH_OFFSET", "0"))})',
)
parser.add_argument(
    "-r",
    "--random",
    action="store_true",
    help="randomize the order of the domains returned (default: disabled)",
)
parser.add_argument(
    "-t",
    "--target",
    type=str,
    help="target only a specific domain and ignore the database (ex: vmst.io)",
)

args = parser.parse_args()

if (args.limit or args.offset) and args.target:
    vmc_output("You cannot set both limit/offset and target arguments", "pink")
    sys.exit(1)

if args.offset and args.random:
    vmc_output("You cannot set both offset and random arguments", "pink")
    sys.exit(1)

if args.limit is not None:
    db_limit = args.limit
else:
    db_limit = int(os.getenv("VMCRAWL_FETCH_LIMIT", "10"))

if args.offset is not None:
    db_offset = args.offset
else:
    db_offset = int(os.getenv("VMCRAWL_FETCH_OFFSET", "0"))


def fetch_exclude_domains(conn):
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT string_agg('''' || domain || '''', ',') FROM no_peers")
        exclude_domains_sql = cursor.fetchone()[0]
        return exclude_domains_sql if exclude_domains_sql else ""
    except Exception as e:
        print(f"Failed to obtain excluded domain list: {e}")
        conn.rollback()
        return None
    finally:
        cursor.close()


def fetch_domain_list(conn, exclude_domains_sql):
    cursor = conn.cursor()
    try:
        if exclude_domains_sql:
            query = f"""
                SELECT domain FROM mastodon_domains
                WHERE active_users_monthly > {int(os.getenv("VMCRAWL_FETCH_MIN_ACTIVE", "100"))}
                AND domain NOT IN ({exclude_domains_sql})
                ORDER BY active_users_monthly DESC
            """
        else:
            query = f"""
                SELECT domain FROM mastodon_domains
                WHERE active_users_monthly > {int(os.getenv("VMCRAWL_FETCH_MIN_ACTIVE", "100"))}
                ORDER BY active_users_monthly DESC
            """
        cursor.execute(query)
        result = [row[0] for row in cursor.fetchall() if not has_emoji_chars(row[0])]

        if args.random is True:
            random.shuffle(result)

        # Apply offset and limit to the results
        start = int(db_offset)
        end = start + int(db_limit)
        result = result[start:end]

        return result if result else ["vmst.io"]
    except Exception as e:
        print(f"Failed to obtain primary domain list: {e}")
        conn.rollback()
        return None
    finally:
        cursor.close()


def is_valid_domain(domain):
    domain_pattern = re.compile(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", re.IGNORECASE)
    return (
        (domain_pattern.match(domain) or "xn--" in domain)
        and not is_ip_address(domain)
        and not detect_vowels(domain)
    )


def is_ip_address(domain):
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def detect_vowels(domain):
    try:
        pattern = r"\.[aeiou]{4}"
        matches = re.findall(pattern, domain)
        return True if len(matches) > 0 else False
    except Exception as e:
        vmc_output(f"Error detecting vowels: {e}", "orange")
        return False


def import_domains(domains):
    cursor = conn.cursor()
    try:
        if domains:
            values = [(domain.lower(), 0) for domain in domains]
            args_str = ",".join(["(%s,%s)" for _ in values])
            flattened_values = [item for sublist in values for item in sublist]
            cursor.execute(
                "INSERT INTO raw_domains (domain, errors) VALUES " + args_str,
                flattened_values,
            )
            vmc_output(f"Imported {len(domains)} domains", "green")
            conn.commit()
    except Exception as e:
        vmc_output(f"Failed to import domain list: {e}", "orange")
        conn.rollback()
        return None
    finally:
        cursor.close()


def get_junk_keywords():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT keywords FROM junk_words")
        keywords = [row[0] for row in cursor.fetchall()]
        conn.commit()
        return keywords
    except Exception as e:
        vmc_output(f"Failed to obtain junk domain list: {e}", "orange")
        conn.rollback()
        return None
    finally:
        cursor.close()


def get_bad_tld():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT tld FROM bad_tld")
        tlds = [row[0] for row in cursor.fetchall()]
        conn.commit()
        return tlds
    except Exception as e:
        vmc_output(f"Failed to obtain bad TLD list: {e}", "orange")
        conn.rollback()
        return None
    finally:
        cursor.close()


def add_to_no_peers(domain):
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO no_peers (domain) VALUES (%s)", (domain,))
        conn.commit()
        vmc_output(f"{domain} added to no_peers table", "red")
    except Exception as e:
        vmc_output(f"Failed to add domain to no_peers list: {e}", "orange")
        conn.rollback()
        return None
    finally:
        cursor.close()


def get_existing_domains():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT domain FROM raw_domains")
        existing_domains = [row[0] for row in cursor.fetchall()]
        conn.commit()
        return existing_domains
    except Exception as e:
        vmc_output(f"Failed to get list of existing domains: {e}", "orange")
        conn.rollback()
        return None
    finally:
        cursor.close()


def get_domains(api_url, domain, domain_endings):
    keywords = get_junk_keywords() or []
    bad_tlds = get_bad_tld() or []

    try:
        api_response = get_httpx(api_url, http_client)
        data = api_response.json()
        filtered_domains = [
            item
            for item in data
            if is_valid_domain(item)
            and not has_emoji_chars(item)
            and not any(keyword in item for keyword in keywords)
            and not any(item.endswith(f".{tld}") for tld in bad_tlds)
            and any(
                item.endswith(f".{domain_ending}") for domain_ending in domain_endings
            )
            and item.islower()
        ]
        return filtered_domains
    except Exception as e:
        vmc_output(f"{e}", "orange")
        add_to_no_peers(domain)  # Add domain to no_peers if any other error occurs
    return []


def process_domain(domain, counter, total):
    vmc_output(f"Fetching peers @ {domain} ({counter}/{total})…", "bold")

    api_url = f"https://{domain}/api/v1/instance/peers"

    existing_domains = get_existing_domains()
    domains = get_domains(api_url, domain, domain_endings)
    unique_domains = [
        domain
        for domain in domains
        if domain not in existing_domains and domain.isascii()
    ]

    print(f"Found {len(domains)} domains, {len(unique_domains)} new domains")

    import_domains(unique_domains)


if __name__ == "__main__":
    try:
        vmc_output(f"{appname} v{appversion} ({current_filename})", "bold")
        if is_running_headless():
            vmc_output("Running in headless mode", "pink")
        else:
            vmc_output("Running in interactive mode", "pink")

        exclude_domains_sql = fetch_exclude_domains(conn)
        domain_endings = get_domain_endings()

        if exclude_domains_sql is None:
            vmc_output("Failed to fetch excluded list, exiting…", "pink")
            sys.exit(1)

        if args.target is not None:
            domain_list = [args.target]
        else:
            domain_list = fetch_domain_list(conn, exclude_domains_sql)

        if not domain_list:
            vmc_output("No domains fetched, exiting…", "pink")
            sys.exit(1)

        print(f"Fetching peer data from {len(domain_list)} instances…")

        total = len(domain_list)
        for counter, domain in enumerate(domain_list, start=1):
            try:
                process_domain(domain, counter, total)
            except Exception as e:
                vmc_output(f"Error processing domain {domain}: {e}", "orange")
                continue

        vmc_output("Fetching complete!", "bold")
    except KeyboardInterrupt:
        vmc_output(f"\n{appname} interrupted by user", "bold")
    finally:
        conn.close()
