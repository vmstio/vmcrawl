try:
    import httpx
    import sys
    import sqlite3
    import ipaddress
    import re
    from dotenv import load_dotenv
    import os
except ImportError as e:
    print(f"Error importing module: {e}")
    sys.exit(1)

from common import *
load_dotenv()

db_path = os.getenv("db_path")
conn = sqlite3.connect(db_path) # type: ignore

def is_valid_domain(domain):
    domain_pattern = re.compile(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', re.IGNORECASE)
    return (domain_pattern.match(domain) or "xn--" in domain) and not is_ip_address(domain)

def is_ip_address(domain):
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False

def import_domains(domains):
    cursor = conn.cursor()
    try:
        for domain in domains:
            lowercase_domain = domain.lower()
            cursor.execute("INSERT INTO RawDomains (Domain) VALUES (?)", (lowercase_domain,))
        conn.commit()
        print(f"{len(domains)} domains imported successfully")
    except Exception as e:
        print(f"Failed to import domain list: {e}")
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
        print(f"Failed to obtain junk domain list: {e}")
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
        print(f"Failed to obtain bad TLD list: {e}")
        conn.rollback()
        return None
    finally:
        cursor.close()

def add_to_no_peers(domain):
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO NoPeers (Domain) VALUES (?)", (domain,))
        conn.commit()
        print(f"{domain} added to NoPeers table")
    except Exception as e:
        print(f"Failed to add domain to NoPeers list: {e}")
        conn.rollback()
        return None
    finally:
        cursor.close()

def write_to_file(domains, output_file):
    try:
        with open(output_file, "w") as file:
            for domain in domains:
                file.write(f"{domain}\n")
        print(f"{len(domains)} unique domains written to {output_file}")
    except Exception as e:
        print(f"An error occurred while writing to the file: {e}")

def get_existing_domains():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT Domain FROM RawDomains")
        existing_domains = [row[0] for row in cursor.fetchall()]
        conn.commit()
        return existing_domains
    except Exception as e:
        print(f"Failed to get list of existing domains: {e}")
        conn.rollback()
        return None
    finally:
        cursor.close()

def get_domains(api_url, domain):
    keywords = get_junk_keywords() or []
    bad_tlds = get_bad_tld() or []

    try:
        api_response = http_client.get(api_url)
        data = api_response.json()
        filtered_domains = [
            item for item in data
            if is_valid_domain(item) and not any(keyword in item for keyword in keywords)
            and not any(item.endswith(tld) for tld in bad_tlds)
            and any(item.endswith(f'.{domain_ending}') for domain_ending in domain_endings)
        ]
        return filtered_domains
    except Exception as e:
        print(f"{e}")
        add_to_no_peers(domain)  # Add domain to NoPeers if any other error occurs
    return []

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ./import.py [domain]")
        sys.exit(1)

    domain = sys.argv[1]
    api_url = f"https://{domain}/api/v1/instance/peers"
    db_path = os.getenv("db_path")
    output_file = f"target/import_{domain}.txt"
    domain_endings = get_domain_endings()

    existing_domains = get_existing_domains()
    domains = get_domains(api_url, domain)  # Pass the domain and db_path to get_domains
    unique_domains = [domain for domain in domains if domain not in existing_domains and domain.isascii()]

    if unique_domains == []:
        print("No new unique domains found")
        sys.exit(0)

    write_to_file(unique_domains, output_file)
    import_domains(unique_domains)