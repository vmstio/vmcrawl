#!/usr/bin/env python3

import sqlite3
import os
import subprocess

# Define ANSI escape codes for bold text
BOLD_START = "\033[1m"
BOLD_END = "\033[0m"

# Path to your SQLite database file
DATABASE_PATH = "/Users/vmstan/Documents/MastodonDomains.sqlite"

DB_LIMIT = 1000
DB_OFFSET = 0

def fetch_exclude_domains(conn):
    """Fetch the list of excluded domains from the NoPeers table."""
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT GROUP_CONCAT('''' || Domain || '''', ',') FROM NoPeers")
        exclude_domains_sql = cursor.fetchone()[0]
        return exclude_domains_sql if exclude_domains_sql else ""
    except sqlite3.Error as e:
        print(f"Error fetching excluded domains from SQLite database: {e}")
        return None

def fetch_domain_list(conn, exclude_domains_sql):
    """Fetch the list of domains excluding those in NoPeers."""
    try:
        cursor = conn.cursor()
        query = f"""
            SELECT Domain FROM MastodonDomains
            WHERE Domain NOT IN ({exclude_domains_sql})
            ORDER BY "Active Users (Monthly)" DESC
            LIMIT {DB_LIMIT} OFFSET {DB_OFFSET}
        """
        cursor.execute(query)
        return [row[0] for row in cursor.fetchall()]
    except sqlite3.Error as e:
        print(f"Error fetching domains from SQLite database: {e}")
        return None

def process_domain(domain, counter, total):
    """Process each domain by running peerapi.py and crawler.py."""
    print(f"{BOLD_START}Processing {domain} ({counter}/{total})...{BOLD_END}")

    # Execute peerapi.py for the domain
    subprocess.run(["python3", "peerapi.py", domain])

    # If target/import_<domain>.txt exists, process it with crawler.py
    import_file = f"target/import_{domain}.txt"
    if os.path.isfile(import_file):
        subprocess.run(["python3", "crawler.py", import_file])
        os.remove(import_file)
    else:
        print(f"Finished processing {domain}")

def main():
    # Connect to the SQLite database
    conn = sqlite3.connect(DATABASE_PATH)

    print(f"{BOLD_START}Fetching list of excluded domains from SQLite database...{BOLD_END}")
    exclude_domains_sql = fetch_exclude_domains(conn)

    if exclude_domains_sql is None:
        print("Exiting due to error.")
        return

    print(f"{BOLD_START}Fetching top peers from the database...{BOLD_END}")
    domain_list = fetch_domain_list(conn, exclude_domains_sql)

    if not domain_list:
        print("No instances found in the database. Exiting...")
        return

    print(f"Number of instances fetched: {len(domain_list)}")

    # Process each domain
    total = len(domain_list)
    for counter, domain in enumerate(domain_list, start=1):
        process_domain(domain, counter, total)

    print(f"{BOLD_START}All domains processed!{BOLD_END}")

if __name__ == "__main__":
    main()
