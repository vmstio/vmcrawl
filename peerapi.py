import requests
import sys
import sqlite3
import ipaddress
import re

def is_valid_domain(domain):
    # Regular expression pattern for valid domain format (case-insensitive)
    domain_pattern = re.compile(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', re.IGNORECASE)

    # Check if the domain matches the valid domain format or contains "xn--"
    # Also, check if it's not an IP address
    return (domain_pattern.match(domain) or "xn--" in domain) and not is_ip_address(domain)

def is_ip_address(domain):
    try:
        ipaddress.ip_address(domain)
        return True  # It's an IP address
    except ValueError:
        return False  # It's not an IP address

def import_domains(domains, db_path):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        for domain in domains:
            # Force domain to lowercase before inserting into the database
            lowercase_domain = domain.lower()
            cursor.execute("INSERT INTO RawDomains (Domain) VALUES (?)", (lowercase_domain,))
        conn.commit()
        conn.close()
        print(f"{len(domains)} domains imported successfully")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def get_junk_keywords(db_path):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT Keywords FROM JunkWords")
        keywords = [row[0] for row in cursor.fetchall()]
        conn.close()
        return keywords
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    return []

def get_bad_tld(db_path):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT TLD FROM BadTLD")
        keywords = [row[0] for row in cursor.fetchall()]
        conn.close()
        return keywords
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    return []

def add_to_no_peers(domain, db_path):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        # Insert the domain into the NoPeers table
        cursor.execute("INSERT INTO NoPeers (Domain) VALUES (?)", (domain,))
        conn.commit()
        conn.close()
        print(f"{domain} added to NoPeers table")
    except sqlite3.Error as e:
        print(f"Database error while adding to NoPeers: {e}")
    except Exception as e:
        print(f"An unexpected error occurred while adding to NoPeers: {e}")

def write_to_file(domains, output_file):
    try:
        with open(output_file, "w") as file:
            for domain in domains:
                file.write(f"{domain}\n")
        print(f"{len(domains)} unique domains written to {output_file}")
    except Exception as e:
        print(f"An error occurred while writing to the file: {e}")

def get_existing_domains(db_path):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT Domain FROM RawDomains")
        existing_domains = [row[0] for row in cursor.fetchall()]
        conn.close()
        return existing_domains
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def get_domains(api_url, domain, db_path):
    keywords = get_junk_keywords(db_path)
    bad_tlds = get_bad_tld(db_path)

    try:
        response = requests.get(api_url, timeout=5)
        response.raise_for_status()  # Raises an HTTPError if the response status code is 4XX or 5XX
        data = response.json()
        filtered_domains = [
            item for item in data
            if is_valid_domain(item) and not any(keyword in item for keyword in keywords)
            and not any(item.endswith(tld) for tld in bad_tlds)
        ]
        return filtered_domains
    except requests.HTTPError as e:
        print(f"HTTP error occurred while making the request: {e}")
        add_to_no_peers(domain, db_path)  # Add domain to NoPeers if HTTP error occurs
    except requests.RequestException as e:
        print(f"Non-HTTP error occurred while making the request: {e}")
        add_to_no_peers(domain, db_path)  # Add domain to NoPeers if request error occurs
    except ValueError as e:
        print(f"An error occurred while decoding the JSON response: {e}")
        add_to_no_peers(domain, db_path)  # Add domain to NoPeers if JSON decoding fails
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        add_to_no_peers(domain, db_path)  # Add domain to NoPeers if any other error occurs
    return []

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ./import.py [domain]")
        sys.exit(1)

    domain = sys.argv[1]
    api_url = f"https://{domain}/api/v1/instance/peers"
    db_path = "/Users/vmstan/Documents/MastodonDomains.sqlite"
    output_file = f"target/import_{domain}.txt"

    existing_domains = get_existing_domains(db_path)
    domains = get_domains(api_url, domain, db_path)  # Pass the domain and db_path to get_domains
    unique_domains = [domain for domain in domains if domain not in existing_domains and domain.isascii()]

    if unique_domains == []:
        print("No new unique domains found")
        sys.exit(0)

    write_to_file(unique_domains, output_file)
    import_domains(unique_domains, db_path)