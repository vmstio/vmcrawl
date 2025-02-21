#!/usr/bin/env python3

# Import common modules
from common import *
# Import additional modules
try:
    import ipaddress
    import argparse
except ImportError as e:
    print(f"Error importing module: {e}")
    sys.exit(1)

# Detect the current filename
current_filename = os.path.basename(__file__)

db_limit = 100
db_offset = 0

parser = argparse.ArgumentParser(description="Fetch peer data from Mastodon instances.")
parser.add_argument('-l', '--limit', type=int, help=f'limit the number of domains requested from database (default: {db_limit})')
parser.add_argument('-o', '--offset', type=int, help=f'offset the top of the domains requested from database (default: {db_offset})')
parser.add_argument('-t', '--target', type=str, help='target only a specific domain and ignore the database (ex: vmst.io)')

args = parser.parse_args()

if (args.limit or args.offset) and args.target:
    print_colored("You cannot set both limit/offset and target arguments", "pink")
    sys.exit(1)

if args.limit is not None:
    db_limit = args.limit

if args.offset is not None:
    db_offset = args.offset

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
                WHERE domain NOT IN ({exclude_domains_sql})
                ORDER BY active_users_monthly DESC
                LIMIT {db_limit} OFFSET {db_offset}
            """
        else:
            query = f"""
                SELECT domain FROM mastodon_domains
                ORDER BY active_users_monthly DESC
                LIMIT {db_limit} OFFSET {db_offset}
            """
        cursor.execute(query)
        return [row[0] for row in cursor.fetchall()]
    except Exception as e:
        print(f"Failed to obtain primary domain list: {e}")
        conn.rollback()
        return None
    finally:
        cursor.close()

def is_valid_domain(domain):
    domain_pattern = re.compile(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', re.IGNORECASE)
    return (domain_pattern.match(domain) or "xn--" in domain) and not is_ip_address(domain) and not detect_vowels(domain)

def is_ip_address(domain):
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False

def detect_vowels(domain):
    try:
        pattern = r'\.[aeiou]{4}'
        matches = re.findall(pattern, domain)
        return True if len(matches) > 0 else False
    except Exception as e:
        print_colored(f"Error detecting vowels: {e}", "orange")
        return False

def import_domains(domains):
    cursor = conn.cursor()
    try:
        if domains:
            values = [(domain.lower(), 0) for domain in domains]
            args_str = ','.join(['(%s,%s)' for _ in values])
            flattened_values = [item for sublist in values for item in sublist]
            cursor.execute("INSERT INTO raw_domains (domain, errors) VALUES " + args_str, flattened_values)
            print_colored(f"Imported {len(domains)} domains", "green")
            conn.commit()
    except Exception as e:
        print_colored(f"Failed to import domain list: {e}", "orange")
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
        print_colored(f"Failed to obtain junk domain list: {e}", "orange")
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
        print_colored(f"Failed to obtain bad TLD list: {e}", "orange")
        conn.rollback()
        return None
    finally:
        cursor.close()

def add_to_no_peers(domain):
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO no_peers (domain) VALUES (%s)", (domain,))
        conn.commit()
        print_colored(f"{domain} added to no_peers table", "red")
    except Exception as e:
        print_colored(f"Failed to add domain to no_peers list: {e}", "orange")
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
        print_colored(f"Failed to get list of existing domains: {e}", "orange")
        conn.rollback()
        return None
    finally:
        cursor.close()

def get_domains(api_url, domain, domain_endings):
    keywords = get_junk_keywords() or []
    bad_tlds = get_bad_tld() or []

    try:
        api_response = http_client.get(api_url)
        data = api_response.json()
        filtered_domains = [
            item for item in data
            if is_valid_domain(item) and not any(keyword in item for keyword in keywords)
            and not any(item.endswith(f'.{tld}') for tld in bad_tlds)
            and any(item.endswith(f'.{domain_ending}') for domain_ending in domain_endings)
            and item.islower()
        ]
        return filtered_domains
    except Exception as e:
        print_colored(f"{e}", "orange")
        add_to_no_peers(domain)  # Add domain to no_peers if any other error occurs
    return []

def process_domain(domain, counter, total):
    print_colored(f"Fetching peers @ {domain} ({counter}/{total})…", "bold")

    api_url = f"https://{domain}/api/v1/instance/peers"

    existing_domains = get_existing_domains()
    domains = get_domains(api_url, domain, domain_endings)
    unique_domains = [domain for domain in domains if domain not in existing_domains and domain.isascii()]

    print(f"Found {len(domains)} domains, {len(unique_domains)} new domains")

    import_domains(unique_domains)

if __name__ == "__main__":
    try:
        print_colored(f"{appname} v{appversion} ({current_filename})", "bold")
        if is_running_headless():
            print_colored("Running in headless mode", "pink")
        else:
            print_colored("Running in interactive mode", "pink")

        exclude_domains_sql = fetch_exclude_domains(conn)
        domain_endings = get_domain_endings()

        if exclude_domains_sql is None:
            print_colored("Failed to fetch excluded list, exiting…", "pink")
            sys.exit(1)

        if args.target is not None:
            domain_list = [args.target]
        else:
            domain_list = fetch_domain_list(conn, exclude_domains_sql)

        if not domain_list:
            print_colored("No domains fetched, exiting…", "pink")
            sys.exit(1)

        print(f"Fetching peer data from {len(domain_list)} instances…")

        total = len(domain_list)
        for counter, domain in enumerate(domain_list, start=1):
            try:
                process_domain(domain, counter, total)
            except Exception as e:
                print_colored(f"Error processing domain {domain}: {e}", "orange")
                continue

        print_colored("Fetching complete!", "bold")
    except KeyboardInterrupt:
        print_colored(f"\n{appname} interrupted by user", "bold")
    finally:
        conn.close()
        http_client.close()
