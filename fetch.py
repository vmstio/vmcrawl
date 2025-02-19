#!/usr/bin/env python3

# Import common modules
from common import *
# Import additional modules
try:
    import ipaddress
except ImportError as e:
    print(f"Error importing module: {e}")
    sys.exit(1)

# Detect the current filename
current_filename = os.path.basename(__file__)

db_limit = 100
db_offset = 0

if len(sys.argv) > 1:
    try:
        db_limit = int(sys.argv[1])
    except ValueError:
        print(f"Invalid limit value provided. Must be a valid integer.")
        sys.exit(1)

if len(sys.argv) > 2:
    try:
        db_offset = int(sys.argv[2])
    except ValueError:
        print(f"Invalid offset value provided. Must be a valid integer.")
        sys.exit(1)

def fetch_exclude_domains(conn):
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT GROUP_CONCAT('''' || Domain || '''', ',') FROM NoPeers")
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
        query = f"""
            SELECT Domain FROM MastodonDomains
            WHERE Domain NOT IN ({exclude_domains_sql})
            ORDER BY "Active Users (Monthly)" DESC
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
        for domain in domains:
            lowercase_domain = domain.lower()
            cursor.execute("INSERT INTO RawDomains (Domain, Errors) VALUES (?, 0)", (lowercase_domain,))
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
        cursor.execute("SELECT Keywords FROM JunkWords")
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
        cursor.execute("SELECT TLD FROM BadTLD")
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
        cursor.execute("INSERT INTO NoPeers (Domain) VALUES (?)", (domain,))
        conn.commit()
        print_colored(f"{domain} added to NoPeers table", "red")
    except Exception as e:
        print_colored(f"Failed to add domain to NoPeers list: {e}", "orange")
        conn.rollback()
        return None
    finally:
        cursor.close()

def get_existing_domains():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT Domain FROM RawDomains")
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
        add_to_no_peers(domain)  # Add domain to NoPeers if any other error occurs
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

        exclude_domains_sql = fetch_exclude_domains(conn)
        domain_endings = get_domain_endings()

        if exclude_domains_sql is None:
            print_colored("Failed to fetch excluded list, exiting…", "red")
            sys.exit(1)

        domain_list = fetch_domain_list(conn, exclude_domains_sql)

        if not domain_list:
            print_colored("No domains fetched, exiting…", "red")
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
