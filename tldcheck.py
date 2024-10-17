#!/usr/bin/env python3

try:
    import sqlite3
    import requests
    import httpx
    import sys
    import os
    from dotenv import load_dotenv
except ImportError as e:
    print(f"Error importing module: {e}")
    sys.exit(1)

from common import *
load_dotenv()

db_path = os.getenv("db_path")
conn = sqlite3.connect(db_path) # type: ignore

domain_endings_url = 'http://data.iana.org/TLD/tlds-alpha-by-domain.txt'

domain_endings_response = http_client.get(domain_endings_url)
if domain_endings_response.status_code == 200:
    domain_endings = [line.strip().lower() for line in domain_endings_response.text.splitlines() if not line.startswith('#')]
else:
    raise Exception(f"Failed to fetch domain endings. HTTP Status Code: {domain_endings_response.status_code}")

cursor = conn.cursor()

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

# Execute the query in chunks
results = chunked_query(domain_endings)

# Close the connection
conn.close()

# Print or process the results as needed
for result in results:
    print(result[0])
