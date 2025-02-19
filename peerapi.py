try:
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

# def write_to_file(domains, output_file):
#     try:
#         with open(output_file, "w") as file:
#             for domain in domains:
#                 file.write(f"{domain}\n")
#         print(f"Unique domains written to {output_file}")
#     except Exception as e:
#         print_colored(f"An error occurred while writing to the file: {e}", "orange")

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

def get_domains(api_url, domain):
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

if __name__ == "__main__":
    try:
        if len(sys.argv) < 2:
            print("Usage: ./import.py [domain]")
            sys.exit(1)

        domain = sys.argv[1]
        api_url = f"https://{domain}/api/v1/instance/peers"
        db_path = os.getenv("db_path")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        output_file = os.path.join(script_dir, f"target/import_{domain}.txt")
        domain_endings = get_domain_endings()

        existing_domains = get_existing_domains()
        existing_domains_count = len(existing_domains) if existing_domains is not None else 0
        domains = get_domains(api_url, domain)  # Pass the domain and db_path to get_domains
        unique_domains = [domain for domain in domains if domain not in existing_domains and domain.isascii()]

        print(f"Found {len(domains)} domains, {len(unique_domains)} new domains")
        if unique_domains == []:
            # print("No new unique domains found")
            sys.exit(0)

        # write_to_file(unique_domains, output_file)
        import_domains(unique_domains)
    except KeyboardInterrupt:
        conn.close()
