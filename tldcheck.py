#!/usr/bin/env python3

import sqlite3
import requests

# Path to your SQLite database
db_path = '/Users/vmstan/Documents/MastodonDomains.sqlite'

# URL for domain endings from IANA
domain_endings_url = 'http://data.iana.org/TLD/tlds-alpha-by-domain.txt'

# Fetch domain endings from the URL and convert to lowercase
response = requests.get(domain_endings_url)
if response.status_code == 200:
    domain_endings = [line.strip().lower() for line in response.text.splitlines() if not line.startswith('#')]
else:
    raise Exception(f"Failed to fetch domain endings. HTTP Status Code: {response.status_code}")

# Connect to the database
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

def chunked_query(domain_endings, chunk_size=50):
    """Run queries in chunks to avoid hitting SQLite expression tree limits and to properly exclude domains."""
    results = []
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
