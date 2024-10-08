#!/usr/bin/env python3

try:
    import datetime
    import dns.resolver
    import json
    import os
    import random
    import re
    import requests
    import select
    import socket
    import sqlite3
    import sys
    from bs4 import BeautifulSoup
    from OpenSSL import SSL
    from urllib.parse import urlparse, urlunparse
except ImportError as e:
    print(f"Error importing module: {e}")
    sys.exit(1)

APPNAME = 'vmcrawl'
VERSION = '0.1'

# Add your color constants here
BOLD = '\033[1m'
RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
MAGENTA = '\033[35m'
CYAN = '\033[36m'
ORANGE = '\033[38;5;208m'
PINK = '\033[38;5;198m'
RESET = '\033[0m'

print(f'{BOLD}{APPNAME} v{VERSION}{RESET}')
print(f'{PINK}Alter direction:{RESET} 2=Reverse 3=Random')
print(f'{PINK}Retry general errors:{RESET} 4=Overflow 5=Underflow')
print(f'{PINK}Retry specific errors:{RESET} 9=SSL 10=DNS 11=### 12=HTTP 13=400-599 15=??? 16=API 17=JSON 18=XML 23=TXT')
print(f'{PINK}Retry fatal errors:{RESET} 7=Ignored 14=Failed')
print(f'{PINK}Retry good data:{RESET} 6=Stale 8=Outdated 21=Inactive 22=Main')
print(f'{CYAN}Enter your choice (1, 2, 3, etc):{RESET} ', end='', flush=True)
ready, _, _ = select.select([sys.stdin], [], [], 5)  # Wait for input for 5 seconds

if ready:
    user_choice = sys.stdin.readline().strip()
else:
    print("\nDefaulting to standard crawl")
    user_choice = "1"

print(f"Choice selected: {user_choice}")

db_path = '/Users/vmstan/Documents/MastodonDomains.sqlite'

def resolve_dns_with_dnspython(domain):
    record_types = ['A', 'AAAA', 'CNAME']
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type, lifetime=10)
            if answers:
                return True  # Record of type record_type found
        except dns.resolver.NoAnswer:
            continue  # No record of this type, try the next one
        except dns.resolver.NXDOMAIN:
            return False  # Domain does not exist
        except dns.resolver.NoNameservers:
            return False  # No nameservers available for this domain
        except dns.resolver.NoRootSOA:
            return False  # No root SOA available for this domain
        except dns.resolver.Timeout:
            return None  # DNS query failed due to timeout or other DNS issues
        except dns.exception.DNSException:
            return None

    # If the loop completes without finding a record or encountering a DNS issue, then no desired records were found
    return False  # Neither A, AAAA, nor CNAME records found

def check_ssl_expiry(domain):
    # Create an SSL context that doesn't verify certificates
    context = SSL.Context(SSL.SSLv23_METHOD)
    context.set_verify(SSL.VERIFY_NONE, lambda *args: True)  # Disable verification

    with socket.create_connection((domain, 443)) as sock:
        # Wrap the socket and specify the server hostname for SNI support
        conn = SSL.Connection(context, sock)
        conn.set_tlsext_host_name(domain.encode())
        conn.set_connect_state()
        conn.do_handshake()

        cert = conn.get_peer_certificate()
        if cert:
            # Convert ASN1_TIME to a readable format using datetime.datetime.strptime
            expires_naive = datetime.datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
            expires = expires_naive.replace(tzinfo=datetime.timezone.utc)
            now = datetime.datetime.now(datetime.timezone.utc)
            if now > expires:
                delta = now - expires
                return f"{delta.days}"
            else:
                return "0"
        else:
            return "0"

def is_valid_email(email):
    pattern = r'^[\w\.-]+(?:\+[\w\.-]+)?@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None

def normalize_email(email):
    email = re.sub(r'(\[at\]|\(at\)|\{at\}| at | @ |\[@\]| \[at\] | \(at\) | \{at\} )', '@', email, flags=re.IGNORECASE)
    email = re.sub(r'(\[dot\]|\(dot\)|\{dot\}| dot | \[dot\] | \(dot\) | \{dot\} )', '.', email, flags=re.IGNORECASE)
    return email

def increment_domain_error(domain, conn, error_reason):
    cursor = conn.cursor()
    cursor.execute('SELECT Errors FROM RawDomains WHERE Domain = ?', (domain,))
    result = cursor.fetchone()
    if result:
        current_errors = result[0] if result[0] is not None else 0
        new_errors = current_errors + 1
    else:
        # If the domain is not found, initialize errors count to 1
        new_errors = 1

    # Insert or update the domain with the new errors count
    cursor.execute('''
        INSERT INTO RawDomains (Domain, Failed, Ignore, Errors, Reason)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(Domain) DO UPDATE SET
        Failed = excluded.Failed,
        Ignore = excluded.Ignore,
        Errors = excluded.Errors,
        Reason = excluded.Reason
    ''', (domain, None, None, new_errors, error_reason))
    conn.commit()

def clear_domain_error(domain, conn):
    cursor = conn.cursor()
    # Insert or update the domain with the new errors count
    cursor.execute('''
        INSERT INTO RawDomains (Domain, Failed, Ignore, Errors, Reason)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(Domain) DO UPDATE SET
        Failed = excluded.Failed,
        Ignore = excluded.Ignore,
        Errors = excluded.Errors,
        Reason = excluded.Reason
    ''', (domain, None, None, None, None))
    conn.commit()

def mark_ignore_domain(domain, conn):
    cursor = conn.cursor()
    # Insert or update the domain with the new errors count
    cursor.execute('''
        INSERT INTO RawDomains (Domain, Failed, Ignore, Errors, Reason)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(Domain) DO UPDATE SET
        Failed = excluded.Failed,
        Ignore = excluded.Ignore,
        Errors = excluded.Errors,
        Reason = excluded.Reason
    ''', (domain, None, 1, None, None))
    conn.commit()

def mark_failed_domain(domain, conn):
    cursor = conn.cursor()
    # Insert or update the domain with the new errors count
    cursor.execute('''
        INSERT INTO RawDomains (Domain, Failed, Ignore, Errors, Reason)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(Domain) DO UPDATE SET
        Failed = excluded.Failed,
        Ignore = excluded.Ignore,
        Errors = excluded.Errors,
        Reason = excluded.Reason
    ''', (domain, 1, None, None, None))
    conn.commit()

def find_code_repository(backend_domain):
    # URL of the site you want to parse
    url = f'https://{backend_domain}/about'

    # List of code repository domains to look for
    repo_domains = ['github.com', 'gitlab.com', 'bitbucket.org', 'sourcehut.org', 'codeberg.org', 'code.as', 'git.qoto.org', 'git.sr.ht', 'gitlab.ejone.co', 'gitea.treehouse.systems', 'git.closed.social', 'git.asonix.dog', 'git.pixie.town']

    # Send a GET request to the site
    response = requests.get(url)

    # Check if the request was successful
    if response.status_code == 200:
        # Parse the HTML content of the page
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find all links in the page
        links = soup.find_all('a', href=True)

        # Iterate over each link and check if it contains any of the repo domains
        for link in links:
            if any(domain in link['href'] for domain in repo_domains):
                return link['href']
    else:
        return None

def limit_url_depth(source_url, depth=2):
    parsed_url = urlparse(source_url)
    # Split the path into parts
    path_parts = parsed_url.path.split('/')
    # Filter out empty strings and limit the depth
    limited_path = '/' + '/'.join([part for part in path_parts if part][:depth])
    # Reconstruct the URL with the limited depth path
    new_url = urlunparse(parsed_url._replace(path=limited_path))
    return new_url

def delete_domain_if_known(domain, conn):
    cursor = conn.cursor()
    cursor.execute('''
        DELETE FROM MastodonDomains WHERE "Domain" = ?
        ''', (domain,))
    conn.commit()

def clean_version_suffix(software_version_full):
    # Remove any unwanted or invalid suffixes from the version string
    software_version = software_version_full \
        .split('+')[0] \
        .split('~')[0] \
        .split('_')[0] \
        .split(' ')[0] \
        .split('/')[0] \
        .split('patch')[0]

    return software_version

def clean_version_suffix_more(software_version):
    if "alpha" not in software_version and "beta" not in software_version and "rc" not in software_version and "nightly" not in software_version:
        software_version = re.split(r'-[a-zA-Z]', software_version)[0]
    if "nightly" not in software_version:
        software_version = re.split(r'-\d', software_version)[0]

    return software_version

def clean_version_date(software_version):
    # Regular expression to match the pattern "-YYMMDD"
    match = re.search(r"-(\d{2})(\d{2})(\d{2})$", software_version)

    if match:
        yy, mm, dd = match.groups()
        # Assuming the year starts with '20'
        formatted_date = f"-nightly.20{yy}-{mm}-{dd}"
        # Replace the matched part with the formatted date
        return re.sub(r"-(\d{6})$", formatted_date, software_version)

    # Return the original version if the pattern is not found
    return software_version

def clean_version_development(software_version):
    if "rc1" in software_version:
        software_version = software_version.replace("rc1", "-rc.1")
    elif "rc2" in software_version:
        software_version = software_version.replace("rc2", "-rc.2")
    elif "rc3" in software_version:
        software_version = software_version.replace("rc3", "-rc.3")
    elif "beta1" in software_version:
        software_version = software_version.replace("beta1", "-beta.1")
    elif "beta2" in software_version:
        software_version = software_version.replace("beta2", "-beta.2")
    elif "beta3" in software_version:
        software_version = software_version.replace("beta3", "-beta.3")

    return software_version

def clean_version_hometown(software_version):
    if software_version == "1.0.6":
        software_version = "3.5.3"
    elif software_version == "1.0.7":
        software_version = "3.5.5"

    return software_version

def clean_version_doubledash(software_version):
    if "--" in software_version:
        software_version = software_version.replace("--", "-")

    return software_version

def check_version_wrongpatch(software_version):
    # Regular expression to match the version format X.Y.Z optionally followed by a dash and additional data
    match = re.match(r'^(\d+)\.(\d+)\.(\d+)(-.+)?$', software_version)

    if match:
        # Extract X, Y, Z from the version, and additional data if present
        x, y, z = int(match.group(1)), int(match.group(2)), int(match.group(3))
        additional_data = match.group(4)  # This will be None if no dash and additional data is present

        # Check if Y is 3 or 4
        if y in (3, 4):
            # If Z is not 0, change it to 0
            if z != 0:
                z = 0
                # Rebuild the version string with the modified Z and preserve the additional data if present
                return f"{x}.{y}.{z}{additional_data or ''}"
            return software_version  # Return original version if no change needed
        else:
            return software_version  # Return original version if Y is not 3 or 4
    else:
        # If version format doesn't match
        return software_version

def get_junk_keywords(db_path):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT Keywords FROM JunkWords")
        junk_domains = [row[0] for row in cursor.fetchall()]
        conn.close()
        return junk_domains
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

def check_and_record_domains(domain_list, ignored_domains, failed_domains, user_choice):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    error_directory = 'error'  # Name of the error subfolder
    if not os.path.exists(error_directory):
        os.makedirs(error_directory)
    error_file = os.path.join(error_directory, f'errors_{timestamp}.txt')

    default_user_agent = requests.utils.default_user_agent()
    appended_user_agent = 'vmcrawl/0.1 (https://docs.vmst.io/projects/crawler)'
    custom_headers = {
        'User-Agent': appended_user_agent,
    }

    open(error_file, 'w').close()

    total_domains = len(domain_list)
    for index, domain in enumerate(domain_list, start=1):
        print(f'Attempting to query {domain} ({index}/{total_domains})')

        if user_choice != "7":
            if domain in ignored_domains:
                print(f'{MAGENTA}{domain} is an already ignored domain{RESET}')
                delete_domain_if_known(domain, conn)
                continue

        if user_choice != "14":
            if domain in failed_domains:
                print(f'{RED}{domain} is an already failed domain{RESET}')
                delete_domain_if_known(domain, conn)
                continue

        loopback = False  # Reset the loopback variable
        junk_domains = get_junk_keywords(db_path)
        for junk_domain in junk_domains:
            if junk_domain in domain:
                print(f'{MAGENTA}{domain} is known junk domain{RESET}')
                mark_failed_domain(domain, conn)
                delete_domain_if_known(domain, conn)
                loopback = True
                continue
        if loopback is True:
            continue

        loopback = False  # Reset the loopback variable
        for bad_tld in get_bad_tld(db_path):
            if domain.endswith(bad_tld):
                print(f'{MAGENTA}{domain} is known bad TLD{RESET}')
                mark_failed_domain(domain, conn)
                delete_domain_if_known(domain, conn)
                loopback = True
                continue
        if loopback is True:
            continue

        webfinger_url = f'https://{domain}/.well-known/webfinger?resource=acct:{domain}@{domain}'
        robots_url = f'https://{domain}/robots.txt'
        try:
            with requests.get(robots_url, headers=custom_headers, timeout=5) as robots_response:
                if robots_response.status_code == 200:
                    if robots_response.headers.get('Content-Type', '') == 'application/octet-stream':
                        error_to_print = f'{domain} returned binary file @ {robots_url}'
                        print(f'{YELLOW}{error_to_print}{RESET}')
                        with open(error_file, 'a') as file:
                            file.write(error_to_print + '\n')
                        error_reason = 'BIN'
                        increment_domain_error(domain, conn, error_reason)
                        continue

                    robots_txt = robots_response.text
                    lines = robots_txt.split('\n')
                    user_agent = None
                    disallow = []
                    disallow_found = False

                    for line in lines:
                        line = line.strip()
                        if line.lower().startswith('user-agent:'):
                            user_agent = line.split(':', 1)[1].strip().lower()
                        if user_agent == 'vmcrawl' and line.lower().startswith('disallow:'):
                            disallow_path = line.split(':', 1)[1].strip()
                            if disallow_path == '/' or disallow_path == '*':
                                disallow_found = True  # Bot is disallowed
                            disallow.append(disallow_path)

                    if disallow_found is True:
                        error_to_print = f'{domain} is blocked by robots.txt'
                        print(f'{ORANGE}{error_to_print}{RESET}')
                        with open(error_file, 'a') as file:
                            file.write(error_to_print + '\n')
                        error_reason = 'TXT'
                        increment_domain_error(domain, conn, error_reason)
                        continue

                elif robots_response.status_code == 202:
                    if 'sgcaptcha' in robots_response.text:
                        print(f'{RED}{domain} returned CAPTCHA{RESET}')
                        mark_failed_domain(domain, conn)
                        delete_domain_if_known(domain, conn)
                        continue
                elif robots_response.status_code == 403:
                    custom_headers = {
                        'User-Agent': default_user_agent,
                    }
                elif robots_response.status_code == 410:
                    print(f'{RED}{domain} returned HTTP {robots_response.status_code}{RESET}')
                    mark_failed_domain(domain, conn)
                    delete_domain_if_known(domain, conn)
                    continue

            with requests.get(webfinger_url, headers=custom_headers, timeout=5) as webfinger_response:
                if webfinger_response.status_code == 200:
                    try:
                        # Try to parse the webfinger_response content as JSON
                        data = json.loads(webfinger_response.text)
                        data = webfinger_response.json()
                    except json.JSONDecodeError:
                        content_type = webfinger_response.headers.get('Content-Type', '')
                        if 'application/jrd+json' in content_type or 'application/json' in content_type or 'application/activity+json' in content_type :
                            webfinger_url_trimmed = webfinger_url.split('?')[0]
                            error_to_print = f'{domain} JSON is invalid @ {webfinger_url_trimmed}'
                            print(f'{YELLOW}{error_to_print}{RESET}')
                            with open(error_file, 'a') as file:
                                file.write(error_to_print + '\n')
                            error_reason = 'JSON'
                            increment_domain_error(domain, conn, error_reason)
                            continue
                        elif not webfinger_response.content:
                            webfinger_url_trimmed = webfinger_url.split('?')[0]
                            error_to_print = f'{domain} JSON is empty @ {webfinger_url_trimmed}'
                            print(f'{YELLOW}{error_to_print}{RESET}')
                            with open(error_file, 'a') as file:
                                file.write(error_to_print + '\n')
                            error_reason = 'JSON'
                            increment_domain_error(domain, conn, error_reason)
                            continue
                        elif content_type != '':
                            webfinger_url_trimmed = webfinger_url.split('?')[0]
                            content_type_strip = content_type.split(';')[0].strip()
                            error_to_print = f'{domain} JSON is {content_type_strip} @ {webfinger_url_trimmed}'
                            print(f'{YELLOW}{error_to_print}{RESET}')
                            with open(error_file, 'a') as file:
                                file.write(error_to_print + '\n')
                            error_reason = 'JSON'
                            increment_domain_error(domain, conn, error_reason)
                            continue
                        else:
                            webfinger_url_trimmed = webfinger_url.split('?')[0]
                            error_to_print = f'{domain} JSON is fucked @ {webfinger_url_trimmed}'
                            print(f'{YELLOW}{error_to_print}{RESET}')
                            with open(error_file, 'a') as file:
                                file.write(error_to_print + '\n')
                            error_reason = 'JSON'
                            increment_domain_error(domain, conn, error_reason)
                            continue

                    webfinger_data = webfinger_response.json()
                    webfinger_alias = webfinger_data.get('aliases', [])
                    if webfinger_alias:  # Check if the list is not empty
                        first_webfinger_alias = next((alias for alias in webfinger_alias if 'https' in alias), None)
                    else:
                        print(f'{MAGENTA}{domain} is not using Mastodon{RESET}')
                        mark_ignore_domain(domain, conn)
                        delete_domain_if_known(domain, conn)
                        continue
                    webfinger_domain = urlparse(first_webfinger_alias)
                    real_domain = webfinger_domain.netloc
                else:
                    real_domain = domain

            wk_nodeinfo_url = f'https://{real_domain}/.well-known/nodeinfo'
            with requests.get(wk_nodeinfo_url, headers=custom_headers, timeout=5) as wk_nodeinfo_response:
                if wk_nodeinfo_response.status_code == 200:
                    try:
                        data = json.loads(wk_nodeinfo_response.text)
                        data = wk_nodeinfo_response.json()
                    except json.JSONDecodeError:
                        content_type = wk_nodeinfo_response.headers.get('Content-Type', '')
                        if 'application/jrd+json' in content_type or 'application/json' in content_type or 'application/activity+json' in content_type :
                            error_to_print = f'{domain} JSON is invalid @ {wk_nodeinfo_url}'
                            print(f'{YELLOW}{error_to_print}{RESET}')
                            with open(error_file, 'a') as file:
                                file.write(error_to_print + '\n')
                            error_reason = 'JSON'
                            increment_domain_error(domain, conn, error_reason)
                            continue
                        elif not wk_nodeinfo_response.content:
                            error_to_print = f'{domain} JSON is empty @ {wk_nodeinfo_url}'
                            print(f'{YELLOW}{error_to_print}{RESET}')
                            with open(error_file, 'a') as file:
                                file.write(error_to_print + '\n')
                            error_reason = 'JSON'
                            increment_domain_error(domain, conn, error_reason)
                            continue
                        elif content_type != '':
                            content_type_strip = content_type.split(';')[0].strip()
                            error_to_print = f'{domain} JSON is {content_type_strip} @ {wk_nodeinfo_url}'
                            print(f'{YELLOW}{error_to_print}{RESET}')
                            with open(error_file, 'a') as file:
                                file.write(error_to_print + '\n')
                            error_reason = 'JSON'
                            increment_domain_error(domain, conn, error_reason)
                            continue
                        else:
                            error_to_print = f'{domain} JSON is fucked @ {wk_nodeinfo_url}'
                            print(f'{YELLOW}{error_to_print}{RESET}')
                            with open(error_file, 'a') as file:
                                file.write(error_to_print + '\n')
                            error_reason = 'JSON'
                            increment_domain_error(domain, conn, error_reason)
                            continue
                else:
                    error_to_print = f'{domain} returned HTTP {wk_nodeinfo_response.status_code} @ {wk_nodeinfo_url}'
                    print(f'{YELLOW}{error_to_print}{RESET}')
                    with open(error_file, 'a') as file:
                        file.write(error_to_print + '\n')
                    error_reason = wk_nodeinfo_response.status_code
                    increment_domain_error(domain, conn, error_reason)
                    continue

                if ('code' in data and data['code'] in ['rest_no_route', 'rest_not_logged_in', 'rest_forbidden', 'rest_user_invalid', 'rest_login_required']) or ('error' in data and data['error'] == 'Restricted'):
                    error_to_print = f'{domain} has restricted nodeinfo'
                    print(f'{MAGENTA}{error_to_print}{RESET}')
                    mark_ignore_domain(domain, conn)
                    delete_domain_if_known(domain, conn)
                    continue

                if 'links' in data and len(data['links']) > 0 and 'href' in data['links'][0]:
                    discovered_nodeinfo_url = data['links'][0]['href']

                    if 'wp-json' in discovered_nodeinfo_url:
                        error_to_print = f'{domain} is not using Mastodon'
                        print(f'{MAGENTA}{error_to_print}{RESET}')
                        mark_ignore_domain(domain, conn)
                        delete_domain_if_known(domain, conn)
                        continue

                    with requests.get(discovered_nodeinfo_url, headers=custom_headers, timeout=5) as discovered_nodeinfo_response:
                        if discovered_nodeinfo_response.status_code == 200:
                            content_type = discovered_nodeinfo_response.headers.get('Content-Type', '')
                            if 'application/json' not in content_type:
                                if 'application/activity+json' in content_type:
                                    error_to_print = f'{domain} is not using Mastodon'
                                    print(f'{MAGENTA}{error_to_print}{RESET}')
                                    mark_ignore_domain(domain, conn)
                                    delete_domain_if_known(domain, conn)
                                    continue
                                else:
                                    error_to_print = f'{domain} did not return JSON @ {discovered_nodeinfo_url}'
                                    print(f'{YELLOW}{error_to_print}{RESET}')
                                    with open(error_file, 'a') as file:
                                        file.write(error_to_print + '\n')
                                    error_reason = 'JSON'
                                    increment_domain_error(domain, conn, error_reason)
                                    continue
                            discovered_nodeinfo_data = discovered_nodeinfo_response.json()

                            if discovered_nodeinfo_data['software']['name'].lower() == 'mastodon' or discovered_nodeinfo_data['software']['name'].lower() == 'hometown' or discovered_nodeinfo_data['software']['name'].lower() == 'kmyblue' or discovered_nodeinfo_data['software']['name'].lower() == 'glitchcafe':
                                parsed_url = urlparse(discovered_nodeinfo_url)
                                backend_domain = parsed_url.netloc

                                software_version_full = discovered_nodeinfo_data['software']['version']
                                if isinstance(software_version_full, str):
                                    # Remove any unwanted or invalid suffixes from the version string
                                    software_version = clean_version_suffix(software_version_full)

                                software_version = clean_version_date(software_version)
                                software_version = clean_version_suffix_more(software_version)
                                software_version = clean_version_hometown(software_version)
                                software_version = clean_version_development(software_version)
                                software_version = check_version_wrongpatch(software_version)
                                software_version = clean_version_doubledash(software_version)
                                # rewrite dumb data
                                # if software_version.startswith("4.2.10"):
                                #     software_version = "4.2.10"

                                total_users = discovered_nodeinfo_data['usage']['users']['total']
                                active_month_users = discovered_nodeinfo_data['usage']['users']['activeMonth']

                                if active_month_users > max(total_users + 6, total_users + (total_users * 0.25)):
                                    error_to_print = f'{domain} is running Mastodon v{software_version} with invalid counts ({active_month_users}:{total_users})'
                                    print(f'{PINK}{error_to_print}{RESET}')
                                    with open(error_file, 'a') as file:
                                        file.write(error_to_print + '\n')
                                    error_reason = '###'
                                    increment_domain_error(domain, conn, error_reason)
                                    delete_domain_if_known(domain, conn)
                                    continue

                                if software_version.startswith("4"):
                                    backend_url = f'https://{backend_domain}/api/v2/instance'
                                else:
                                    backend_url = f'https://{backend_domain}/api/v1/instance'

                                with requests.get(backend_url, headers=custom_headers, timeout=5) as backend_response:
                                    content_type = backend_response.headers.get('Content-Type', '')
                                    if 'application/json' not in content_type:
                                        if backend_response.status_code != 200:
                                            error_to_print = f'{domain} API is unhealthy'
                                            print(f'{YELLOW}{error_to_print}{RESET}')
                                            with open(error_file, 'a') as file:
                                                file.write(error_to_print + '\n')
                                            error_reason = 'API'
                                            increment_domain_error(domain, conn, error_reason)
                                            continue
                                        error_to_print = f'{domain} API did not return JSON @ {backend_url}'
                                        print(f'{YELLOW}{error_to_print}{RESET}')
                                        with open(error_file, 'a') as file:
                                            file.write(error_to_print + '\n')
                                        error_reason = 'JSON'
                                        increment_domain_error(domain, conn, error_reason)
                                        continue
                                    backend_data = backend_response.json()
                                    if 'error' in backend_data:
                                        if backend_data['error'] == "This method requires an authenticated user":
                                            error_to_print = f'{domain} API requires authentication'
                                            print(f'{MAGENTA}{error_to_print}{RESET}')
                                            mark_ignore_domain(domain, conn)
                                            delete_domain_if_known(domain, conn)
                                            continue
                                    if software_version.startswith("4"):
                                        actual_domain_raw = backend_data['domain']
                                        actual_domain = actual_domain_raw.lower()
                                        contact_account_raw = backend_data['contact']['email']
                                        contact_account = normalize_email(contact_account_raw).lower()
                                        source_url = backend_data['source_url']
                                    else:
                                        actual_domain_raw = backend_data['uri']
                                        actual_domain = actual_domain_raw.lower()
                                        contact_account_raw = backend_data['email']
                                        contact_account = normalize_email(contact_account_raw).lower()
                                        source_url = find_code_repository(backend_domain)
                                    if not is_valid_email(contact_account):
                                        # Discard the value since it's not valid
                                        contact_account = None

                                    if source_url:
                                        source_url = limit_url_depth(source_url)

                                    if source_url == '/source.tar.gz':
                                        source_url = 'https://' + actual_domain + source_url

                                    if discovered_nodeinfo_data['software']['name'].lower() == 'hometown':
                                        source_url = 'https://github.com/hometown-fork/hometown'

                                    if actual_domain == "gc2.jp":
                                        source_url = "https://github.com/gc2-jp/freespeech"

                                print(f'{GREEN}{actual_domain} is running Mastodon v{software_version}{RESET}')

                                if domain != actual_domain:
                                        # First, check if a record exists for the initial domain
                                        cursor.execute('''
                                            SELECT COUNT(*) FROM MastodonDomains WHERE "Domain" = ?
                                        ''', (domain,))
                                        record_exists = cursor.fetchone()[0] > 0

                                        if record_exists:
                                            print(f'{MAGENTA}Deleting duplicate record for {domain} which is really {actual_domain}{RESET}')
                                            # Delete the record associated with the initial domain
                                            delete_domain_if_known(domain, conn)

                                cursor.execute('''
                                    INSERT INTO MastodonDomains ("Domain", "Software Version", "Total Users", "Active Users (Monthly)", "Timestamp", "Contact", "Source", "Full Version")
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                                    ON CONFLICT("Domain") DO UPDATE SET
                                    "Software Version" = excluded."Software Version",
                                    "Total Users" = excluded."Total Users",
                                    "Active Users (Monthly)" = excluded."Active Users (Monthly)",
                                    "Timestamp" = excluded."Timestamp",
                                    "Contact" = excluded."Contact",
                                    "Source" = excluded."Source",
                                    "Full Version" = excluded."Full Version"
                                ''', (actual_domain, software_version, total_users, active_month_users, datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), contact_account, source_url, software_version_full))
                                conn.commit()
                                clear_domain_error(domain, conn)
                            else:
                                print(f'{MAGENTA}{domain} is not using Mastodon{RESET}')
                                mark_ignore_domain(domain, conn)
                                delete_domain_if_known(domain, conn)
                        else:
                            error_to_print = f'{domain} returned HTTP {discovered_nodeinfo_response.status_code} @ {discovered_nodeinfo_url}'
                            if 400 <= discovered_nodeinfo_response.status_code <= 499 and discovered_nodeinfo_response.status_code != 404:
                                print(f'{RED}{error_to_print}{RESET}')
                                mark_failed_domain(domain, conn)
                                delete_domain_if_known(domain, conn)
                            else:
                                print(f'{YELLOW}{error_to_print}{RESET}')
                                with open(error_file, 'a') as file:
                                    file.write(error_to_print + '\n')
                                error_reason = discovered_nodeinfo_response.status_code
                                increment_domain_error(domain, conn, error_reason)
                else:
                    print(f'{MAGENTA}{domain} is not using Mastodon{RESET}')
                    mark_ignore_domain(domain, conn)
                    delete_domain_if_known(domain, conn)

        except requests.exceptions.ConnectionError as e:
            dns_result = resolve_dns_with_dnspython(domain)
            if dns_result is False:
                error_to_print = f'{domain} DNS query returned NXDOMAIN'
                print(f'{RED}{error_to_print}{RESET}')
                mark_failed_domain(domain, conn)
                delete_domain_if_known(domain, conn)
                continue
            elif dns_result is None:
                error_to_print = f'{domain} DNS query failed'
                print(f'{CYAN}{error_to_print}{RESET}')
                with open(error_file, 'a') as file:
                    file.write(error_to_print + '\n')
                error_reason = 'DNS'
                increment_domain_error(domain, conn, error_reason)
            else:
                error_message = str(e)
                if 'SSLError' in error_message and 'Hostname mismatch' in error_message:
                    error_to_print = f'{domain} SSL certfificate does not match hostname'
                    print(f'{ORANGE}{error_to_print}{RESET}')
                    error_reason = 'SSL'
                    delete_domain_if_known(domain, conn)
                elif 'SSLError' in error_message and 'self-signed' in error_message:
                    error_to_print = f'{domain} SSL certificate is self signed'
                    print(f'{ORANGE}{error_to_print}{RESET}')
                    error_reason = 'SSL'
                    delete_domain_if_known(domain, conn)
                elif 'SSLError' in error_message and 'certificate key too weak' in error_message:
                    error_to_print = f'{domain} SSL certificate has a weak key'
                    print(f'{ORANGE}{error_to_print}{RESET}')
                    error_reason = 'SSL'
                    delete_domain_if_known(domain, conn)
                elif 'SSLError' in error_message and 'certificate has expired' in error_message:
                    error_to_print = f'{domain} SSL certificate has expired'
                    print(f'{ORANGE}{error_to_print}{RESET}')
                    error_reason = 'SSL'
                    delete_domain_if_known(domain, conn)
                elif 'SSLError' in error_message and 'tlsv1' in error_message:
                    error_to_print = f'{domain} SSL returned was TLSV1'
                    print(f'{ORANGE}{error_to_print}{RESET}')
                    error_reason = 'SSL'
                    delete_domain_if_known(domain, conn)
                elif 'SSLError' in error_message and 'SSLV3_ALERT_HANDSHAKE_FAILURE' in error_message:
                    error_to_print = f'{domain} SSL returned was SSLV3'
                    print(f'{ORANGE}{error_to_print}{RESET}')
                    error_reason = 'SSL'
                    delete_domain_if_known(domain, conn)
                elif 'SSLError' in error_message and 'UNEXPECTED_EOF_WHILE_READING' in error_message:
                    error_to_print = f'{domain} SSL returned an unexpected EOF'
                    print(f'{ORANGE}{error_to_print}{RESET}')
                    error_reason = 'SSL'
                    delete_domain_if_known(domain, conn)
                elif 'SSLError' in error_message and 'unable to get local issuer certificate' in error_message:
                    error_to_print = f'{domain} SSL returned with untrusted CA'
                    print(f'{ORANGE}{error_to_print}{RESET}')
                    error_reason = 'SSL'
                    delete_domain_if_known(domain, conn)
                elif 'SSLError' in error_message and 'record layer failure' in error_message:
                    error_to_print = f'{domain} SSL returned with record layer failure'
                    print(f'{ORANGE}{error_to_print}{RESET}')
                    error_reason = 'SSL'
                    delete_domain_if_known(domain, conn)
                elif 'SSLError' in error_message and 'UNSAFE_LEGACY_RENEGOTIATION_DISABLED' in error_message:
                    error_to_print = f'{domain} SSL returned with unsafe legacy renegotiation'
                    print(f'{ORANGE}{error_to_print}{RESET}')
                    error_reason = 'SSL'
                    delete_domain_if_known(domain, conn)
                elif 'SSLError' in error_message and 'IP address mismatch' in error_message:
                    error_to_print = f'{domain} SSL returned with IP address mismatch'
                    print(f'{ORANGE}{error_to_print}{RESET}')
                    error_reason = 'SSL'
                    delete_domain_if_known(domain, conn)
                elif 'Exceeded 30 redirects' in error_message:
                    print(f'{RED}{error_to_print}{RESET}')
                    mark_failed_domain(domain, conn)
                    delete_domain_if_known(domain, conn)
                elif 'ConnectTimeoutError' in error_message or 'ConnectionResetError' in error_message:
                    error_to_print = f'{domain} HTTP connection was reset'
                    print(f'{CYAN}{error_to_print}{RESET}')
                    error_reason = 'HTTP'
                elif 'InvalidChunkLength' in error_message:
                    error_to_print = f'{domain} HTTP response was an invalid chunk length'
                    print(f'{CYAN}{error_to_print}{RESET}')
                    error_reason = 'HTTP'
                elif 'RemoteDisconnected' in error_message:
                    error_to_print = f'{domain} HTTP request was disconnected remotely'
                    print(f'{CYAN}{error_to_print}{RESET}')
                    error_reason = 'HTTP'
                elif 'NewConnectionError' in error_message:
                    error_to_print = f'{domain} HTTP request failed to connect'
                    print(f'{CYAN}{error_to_print}{RESET}')
                    error_reason = 'HTTP'
                elif 'NameResolutionError' in error_message:
                    error_to_print = f'{domain} HTTP request failed to resolve'
                    print(f'{CYAN}{error_to_print}{RESET}')
                    error_reason = 'HTTP'
                elif 'LineTooLong' in error_message:
                    error_to_print = f'{domain} HTTP response header was too large'
                    print(f'{CYAN}{error_to_print}{RESET}')
                    error_reason = 'HTTP'
                else:
                    error_to_print = f'{domain} failed with unhandled error: {e}'
                    print(f'{CYAN}{error_to_print}{RESET}')
                    error_reason = '???'
                with open(error_file, 'a') as file:
                    file.write(error_to_print + '\n')
                increment_domain_error(domain, conn, error_reason)

        except requests.exceptions.ReadTimeout:
            error_to_print = f'{domain} HTTP connection timed out'
            print(f'{CYAN}{error_to_print}{RESET}')
            with open(error_file, 'a') as file:
                file.write(error_to_print + '\n')
            error_reason = 'HTTP'
            increment_domain_error(domain, conn, error_reason)

        except Exception as e:
            if 'Exceeded 30 redirects' in str(e):
                error_to_print = f'{domain} exceeded 30 redirects'
                print(f'{RED}{error_to_print}{RESET}')
                mark_failed_domain(domain, conn)
                delete_domain_if_known(domain, conn)
            else:
                error_to_print = f'{domain} encountered an unexpected error: {e}'
                print(f'{CYAN}{error_to_print}{RESET}')
                with open(error_file, 'a') as file:
                    file.write(error_to_print + '\n')
                error_reason = '???'
                increment_domain_error(domain, conn, error_reason)

def read_domain_list(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file]

default_source = 'database'  # Default source is set to 'database'
domain_list_file = sys.argv[1] if len(sys.argv) > 1 else None

def load_from_database(user_choice):
    conn = sqlite3.connect(db_path)  # Connect to your SQLite database
    cursor = conn.cursor()
    if user_choice == "4":
        cursor.execute("SELECT Domain FROM RawDomains WHERE Errors > 7 ORDER BY LENGTH(DOMAIN) DESC")
    elif user_choice == "5":
        cursor.execute("SELECT Domain FROM RawDomains WHERE Errors < 6 ORDER BY LENGTH(DOMAIN) DESC")
    elif user_choice == "6":
        cursor.execute('SELECT Domain FROM MastodonDomains WHERE Timestamp < datetime("now", "-3 days") ORDER BY Timestamp ASC')
    elif user_choice == "7":
        cursor.execute("SELECT Domain FROM RawDomains WHERE Ignore = '1' ORDER BY Domain")
    elif user_choice == "8":
        query = """
        SELECT Domain
        FROM MastodonDomains
        WHERE
            "Software Version" NOT LIKE '4.4.0%' AND
            "Software Version" NOT LIKE '4.3.0-nightly.2024-10%' AND
            "Software Version" NOT LIKE '4.3.0-rc.1%' AND
            "Software Version" NOT LIKE '4.2.13%' AND
            "Software Version" NOT LIKE '4.1.20%'
        ORDER BY "Total Users" DESC
        ;
        """
        cursor.execute(query)
    elif user_choice == "9":
        cursor.execute("SELECT Domain FROM RawDomains WHERE Reason = 'SSL' ORDER BY Domain")
    elif user_choice == "10":
        cursor.execute("SELECT Domain FROM RawDomains WHERE Reason = 'DNS' ORDER BY Domain")
    elif user_choice == "11":
        cursor.execute("SELECT Domain FROM RawDomains WHERE Reason = '###' ORDER BY Domain")
    elif user_choice == "12":
        cursor.execute("SELECT Domain FROM RawDomains WHERE Reason = 'HTTP' ORDER BY Domain")
    elif user_choice == "13":
        cursor.execute("SELECT Domain FROM RawDomains WHERE Reason < '399' ORDER BY Domain")
    elif user_choice == "14":
        cursor.execute("SELECT Domain FROM RawDomains WHERE Failed = '1' ORDER BY Domain")
    elif user_choice == "15":
        cursor.execute("SELECT Domain FROM RawDomains WHERE Reason = '???' ORDER BY Domain")
    elif user_choice == "16":
        cursor.execute("SELECT Domain FROM RawDomains WHERE Reason = 'API' ORDER BY Domain")
    elif user_choice == "17":
        cursor.execute("SELECT Domain FROM RawDomains WHERE Reason = 'JSON' ORDER BY Domain")
    elif user_choice == "18":
        cursor.execute("SELECT Domain FROM RawDomains WHERE Reason = 'XML' ORDER BY Domain")
    elif user_choice == "21":
        cursor.execute('SELECT Domain FROM MastodonDomains WHERE "Active Users (Monthly)" = 0 ORDER BY Domain')
    elif user_choice == "22":
        query = """
        SELECT Domain
        FROM MastodonDomains
        WHERE
            "Software Version" LIKE '4.3%' OR "Software Version" LIKE '4.4%'
        ORDER BY "Total Users" DESC
        ;
        """
        cursor.execute(query)
    elif user_choice == "23":
        cursor.execute("SELECT Domain FROM RawDomains WHERE Reason = 'TXT' ORDER BY Domain")
    else:
        cursor.execute("SELECT Domain FROM RawDomains WHERE (Failed IS NULL OR Failed = '' OR Failed = '0') AND (Ignore IS NULL OR Ignore = '' OR Ignore = '0') AND (Errors < 6 OR Errors IS NULL) ORDER BY Domain ASC")
    domain_list = [row[0].strip() for row in cursor.fetchall() if row[0].strip()]
    conn.close()
    return domain_list

def load_from_file(file_name):
    domain_list = []
    with open(file_name, 'r') as file:
        for line in file:
            domain = line.strip()
            if domain:  # Ensure the domain is not empty
                domain_list.append(domain)
                # Check if the domain already exists in the database
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM RawDomains WHERE Domain = ?', (domain,))
                exists = cursor.fetchone()[0] > 0

                # If not, insert the new domain into the database
                if not exists:
                    cursor.execute('INSERT INTO RawDomains (Domain, Errors) VALUES (?, ?)', (domain, None))
                    conn.commit()
    return domain_list

try:
    if domain_list_file:  # File name provided as argument
        domain_list = load_from_file(domain_list_file)
    else:  # Load from database by default
        domain_list = load_from_database(user_choice)

    if user_choice == "2":
        domain_list.reverse()
    elif user_choice == "3":  # Assuming "3" is the option for randomizing
        random.shuffle(domain_list)

except FileNotFoundError:
    print(f"File not found: {domain_list_file}")
    sys.exit(1)
except sqlite3.Error as e:
    print(f"Database error: {e}")
    sys.exit(1)

conn = sqlite3.connect(db_path)  # Connect to your SQLite database
cursor = conn.cursor()
cursor.execute("SELECT Domain FROM RawDomains WHERE Failed = '1'")  # Replace 'domains_table' and 'domain' with your actual table and column names
failed_domains = [row[0].strip() for row in cursor.fetchall() if row[0].strip()]
conn.close()

conn = sqlite3.connect(db_path)  # Connect to your SQLite database
cursor = conn.cursor()
cursor.execute("SELECT Domain FROM RawDomains WHERE Ignore = '1'")  # Replace 'domains_table' and 'domain' with your actual table and column names
ignored_domains = [row[0].strip() for row in cursor.fetchall() if row[0].strip()]
conn.close()

check_and_record_domains(domain_list, ignored_domains, failed_domains, user_choice)