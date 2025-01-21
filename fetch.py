#!/usr/bin/env python3

try:
    import sqlite3
    import os
    import subprocess
    import sys
    from dotenv import load_dotenv
except ImportError as e:
    print(f"Error importing module: {e}")
    sys.exit(1)

from common import *
load_dotenv()

current_filename = os.path.basename(__file__)
db_path = os.getenv("db_path")
conn = sqlite3.connect(db_path) # type: ignore

db_limit = 10
db_offset = 0

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

def process_domain(domain, counter, total):
    print_colored(f"Fetching peers @ {domain} ({counter}/{total})…", "bold")

    subprocess.run(["python3", "peerapi.py", domain])

    import_file = f"target/import_{domain}.txt"
    if os.path.isfile(import_file):
        subprocess.run(["python3", "crawler.py", import_file])
        os.remove(import_file)

def main():
    print_colored(f"{appname} v{appversion} ({current_filename})", "bold")

    try:
        exclude_domains_sql = fetch_exclude_domains(conn)

        if exclude_domains_sql is None:
            print_colored("Failed to fetch excluded list, exiting…", "red")
            return

        domain_list = fetch_domain_list(conn, exclude_domains_sql)

        if not domain_list:
            print_colored("No domains fetched, exiting…", "red")
            return

        print(f"Fetching peer data from {len(domain_list)} instances…")

        total = len(domain_list)
        for counter, domain in enumerate(domain_list, start=1):
            process_domain(domain, counter, total)
    except KeyboardInterrupt:
        conn.close()
        print(f"\n{appname} interrupted by user. Exiting gracefully…")
    finally:
        print("Fetching complete!")

if __name__ == "__main__":
    main()
