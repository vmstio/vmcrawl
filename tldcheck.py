#!/usr/bin/env python3

try:
    import sqlite3
    import sys
    import os
    from dotenv import load_dotenv
except ImportError as e:
    print(f"Error importing module: {e}")
    sys.exit(1)

from common import *
load_dotenv()

current_filename = os.path.basename(__file__)
db_path = os.getenv("db_path")
conn = sqlite3.connect(db_path) # type: ignore

cursor = conn.cursor()

domain_endings = get_domain_endings()

def chunked_query(domain_endings, chunk_size=50):
    # results = []
    all_domains_query = "SELECT Domain FROM RawDomains"
    cursor.execute(all_domains_query)
    all_domains = set(cursor.fetchall())

    for i in range(0, len(domain_endings), chunk_size):
        chunk = domain_endings[i:i + chunk_size]
        query_parts = ["Domain LIKE ?" for _ in chunk]
        query = f"SELECT Domain FROM RawDomains WHERE {' OR '.join(query_parts)}"
        params = tuple(f'%.{ending}' for ending in chunk)
        cursor.execute(query, params)
        # Collect domains to exclude
        for domain in cursor.fetchall():
            if domain in all_domains:
                all_domains.remove(domain)

    return list(all_domains)

# Print the application information
print_colored(f"{appname} v{appversion} ({current_filename})", "bold")

# Execute the query in chunks
print_colored(f"Querying {len(domain_endings)} domain endings…", "pink")
results = chunked_query(domain_endings)
conn.close()

# Print or process the results as needed
print("Domains without valid TLDs:")
for result in results:
    print(result[0])
