#!/usr/bin/env python3

try:
    from datetime import datetime, timedelta
    import dns.resolver
    import json
    import os
    import random
    import re
    import requests
    import httpx
    import select
    import sqlite3
    import sys
    from bs4 import BeautifulSoup
    from urllib.parse import urlparse, urlunparse
    from dotenv import load_dotenv
    import os
except ImportError as e:
    print(f"Error importing module: {e}")
    sys.exit(1)

from common import *
load_dotenv()

db_path = os.getenv("db_path")
conn = sqlite3.connect(db_path)

httpx_version = httpx.__version__
default_user_agent = 'python-httpx/{httpx_version}'
appended_user_agent = '{appname}/{appversion} (https://docs.vmst.io/projects/{appname})'
custom_headers = {
    'User-Agent': appended_user_agent,
}

http_client = httpx.Client(http2=True, headers=custom_headers, timeout=5)

def perform_dns_query(domain):
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
            return None  # No nameservers available for this domain
        except dns.resolver.NoRootSOA:
            return None  # No root SOA available for this domain
        except dns.resolver.Timeout:
            return None  # DNS query failed due to timeout or other DNS issues
        except dns.exception.DNSException:
            return None

    # If the loop completes without finding a record or encountering a DNS issue, then no desired records were found
    return False  # Neither A, AAAA, nor CNAME records found

def is_valid_email(email):
    pattern = r'^[\w\.-]+(?:\+[\w\.-]+)?@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None

def normalize_email(email):
    email = re.sub(r'(\[at\]|\(at\)|\{at\}| at | @ |\[@\]| \[at\] | \(at\) | \{at\} )', '@', email, flags=re.IGNORECASE)
    email = re.sub(r'(\[dot\]|\(dot\)|\{dot\}| dot | \[dot\] | \(dot\) | \{dot\} )', '.', email, flags=re.IGNORECASE)
    return email

def log_error(domain, error_to_print):
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO ErrorLog (Domain, Error)
            VALUES (?, ?)
        ''', (domain, error_to_print))
        conn.commit()
    except Exception as e:
        print(f"Failed to log error: {e}")
        conn.rollback()
    finally:
        cursor.close()

def increment_domain_error(domain, error_reason):
    cursor = conn.cursor()
    try:
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
    except Exception as e:
        print(f"Failed to increment domain error: {e}")
        conn.rollback()
    finally:
        cursor.close()

def clear_domain_error(domain):
    cursor = conn.cursor()
    try:
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
    except Exception as e:
        print(f"Failed to clear domain error: {e}")
        conn.rollback()
    finally:
        cursor.close()

def mark_ignore_domain(domain):
    cursor = conn.cursor()
    try:
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
    except Exception as e:
        print(f"Failed to mark domain ignored: {e}")
        conn.rollback()
    finally:
        cursor.close()

def mark_failed_domain(domain):
    cursor = conn.cursor()
    try:
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
    except Exception as e:
        print(f"Failed to mark domain failed: {e}")
        conn.rollback()
    finally:
        cursor.close()

def find_code_repository(backend_domain):
    # URL of the site you want to parse
    about_url = f'https://{backend_domain}/about'

    # List of code repository domains to look for
    repo_domains = [
        'bitbucket.org',
        'code.as',
        'codeberg.org',
        'git.closed.social',
        'git.pixie.town',
        'git.qoto.org',
        'git.sr.ht',
        'gitea.treehouse.systems',
        'gitlab.com',
        'gitlab.ejone.co',
        'github.com',
        'sourcehut.org'
    ]

    about_response = http_client.get(about_url)

    if about_response.status_code == 200:
        # Parse the HTML content of the page
        soup = BeautifulSoup(about_response.text, 'html.parser')

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

def delete_domain_if_known(domain):
    cursor = conn.cursor()
    try:
        cursor.execute('''
            DELETE FROM MastodonDomains WHERE "Domain" = ?
            ''', (domain,))
        conn.commit()
    except Exception as e:
        print(f"Failed to delete known domain: {e}")
        conn.rollback()
    finally:
        cursor.close()

def clean_version_suffix(software_version_full):
    # Remove any unwanted or invalid suffixes from the version string
    software_version = software_version_full \
        .split('+')[0] \
        .split('~')[0] \
        .split('_')[0] \
        .split(' ')[0] \
        .split('/')[0] \
        .split('@')[0] \
        .split('&')[0] \
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
    patterns = {
        r'rc(\d+)': r'-rc.\1',
        r'beta(\d+)': r'-beta.\1'
    }

    for pattern, replacement in patterns.items():
        software_version = re.sub(pattern, replacement, software_version)

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
    if software_version.endswith('-'):
        software_version = software_version[:-1]

    return software_version

def clean_version_oddballs(domain, software_version):
    oddballs = [
        'bark.lgbt',
        'drk.st',
        'exquisite.social',
        'glitch.taks.garden',
        'sharlayan.in'
    ]
    if domain in oddballs:
        software_version = software_version + "-odd.0"

    return software_version

def clean_version_wrongpatch(software_version):
    # Regular expression to match the version format X.Y.Z optionally followed by a dash and additional data
    match = re.match(r'^(\d+)\.(\d+)\.(\d+)(-.+)?$', software_version)

    if match:
        # Extract X, Y, Z from the version, and additional data if present
        x, y, z = int(match.group(1)), int(match.group(2)), int(match.group(3))
        additional_data = match.group(4)  # This will be None if no dash and additional data is present

        if x == 4:
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
            return software_version
    else:
        # If version format doesn't match
        return software_version

def clean_version_nightly(software_version):
    # Handle 4.4.0-nightly
    if "4.4.0-nightly" in software_version:
        return "4.4.0-alpha.1"

    # Handle 4.3.0-nightly with date and -security suffix
    match = re.match(r"4\.3\.0-nightly\.(\d{4}-\d{2}-\d{2})(-security)?", software_version)
    if match:
        nightly_date_str, is_security = match.groups()
        nightly_date = datetime.strptime(nightly_date_str, "%Y-%m-%d")

        if is_security:
            nightly_date += timedelta(days=1)

        version_ranges = [
            ("4.3.0-rc.1", datetime(2024, 10, 2), datetime(2024, 10, 7)),
            ("4.3.0-beta.2", datetime(2024, 9, 18), datetime(2024, 10, 1)),
            ("4.3.0-beta.1", datetime(2024, 8, 23), datetime(2024, 9, 17)),
            ("4.3.0-alpha.5", datetime(2024, 7, 5), datetime(2024, 8, 22)),
            ("4.3.0-alpha.4", datetime(2024, 5, 31), datetime(2024, 7, 4)),
            ("4.3.0-alpha.3", datetime(2024, 2, 17), datetime(2024, 5, 30)),
            ("4.3.0-alpha.2", datetime(2024, 2, 15), datetime(2024, 2, 17)),
            ("4.3.0-alpha.1", datetime(2024, 1, 30), datetime(2024, 2, 14)),
            ("4.3.0-alpha.0", datetime(2023, 9, 28), datetime(2024, 1, 29))
        ]

        for version, start_date, end_date in version_ranges:
            if start_date <= nightly_date <= end_date:
                return version

    return software_version

def get_junk_keywords():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT Keywords FROM JunkWords")
        junk_domains = [row[0] for row in cursor.fetchall()]
        conn.commit()
        return junk_domains
    except Exception as e:
        print(f"Failed to obtain junk keywords: {e}")
        conn.rollback()
    finally:
        cursor.close()
    return []

def get_bad_tld():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT TLD FROM BadTLD")
        bad_tlds = [row[0] for row in cursor.fetchall()]
        conn.commit()
        return bad_tlds
    except Exception as e:
        print(f"Failed to obtain bad TLDs: {e}")
        conn.rollback()
    finally:
        cursor.close()
    return []

def get_failed_domains():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT Domain FROM RawDomains WHERE Failed = '1'")
        failed_domains = [row[0].strip() for row in cursor.fetchall() if row[0].strip()]
        conn.commit()
    except Exception as e:
        print(f"Failed to obtain failed domains: {e}")
        conn.rollback()
    finally:
        cursor.close()
    return failed_domains

def get_ignored_domains():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT Domain FROM RawDomains WHERE Ignore = '1'")
        ignored_domains = [row[0].strip() for row in cursor.fetchall() if row[0].strip()]
        conn.commit()
    except Exception as e:
        print(f"Failed to obtain ignored domains: {e}")
        conn.rollback()
    finally:
        cursor.close()
    return ignored_domains

def check_and_record_domains(domain_list, ignored_domains, failed_domains, user_choice, junk_domains, bad_tlds, httpx_client):
    total_domains = len(domain_list)
    for index, domain in enumerate(domain_list, start=1):
        print_colored(f'{domain} ({index}/{total_domains})', 'bold')

        if user_choice != "7":
            if domain in ignored_domains:
                error_to_print = 'Previously ignored!'
                print_colored(f'{error_to_print}', 'cyan')
                delete_domain_if_known(domain)
                continue

        if user_choice != "14":
            if domain in failed_domains:
                error_to_print = 'Previously failed!'
                print_colored(f'{error_to_print}', 'cyan')
                delete_domain_if_known(domain)
                continue

        loopback = False  # Reset the loopback variable
        for junk_domain in junk_domains:
            if junk_domain in domain:
                error_to_print = 'Known junk domain, ignoring...'
                print_colored(f'{error_to_print}', 'magenta')
                mark_failed_domain(domain)
                delete_domain_if_known(domain)
                loopback = True
                continue
        if loopback is True:
            continue

        loopback = False  # Reset the loopback variable
        for bad_tld in bad_tlds:
            if domain.endswith(bad_tld):
                error_to_print = 'Known bad TLD, ignoring...'
                print_colored(f'{error_to_print}', 'magenta')
                mark_failed_domain(domain)
                delete_domain_if_known(domain)
                loopback = True
                continue
        if loopback is True:
            continue

        dns_result = perform_dns_query(domain)
        if dns_result is False:
            error_to_print = 'DNS query returned NXDOMAIN, marking as failed...'
            print_colored(f'{error_to_print}', 'red')
            mark_failed_domain(domain)
            delete_domain_if_known(domain)
            continue
        elif dns_result is None:
            error_to_print = 'DNS query failed to resolve'
            error_reason = 'DNS'
            print_colored(f'{error_to_print}', 'yellow')
            log_error(domain, error_to_print)
            increment_domain_error(domain, error_reason)
            continue

        webfinger_url = f'https://{domain}/.well-known/webfinger?resource=acct:{domain}@{domain}'
        robots_url = f'https://{domain}/robots.txt'
        try:
            robots_response = http_client.get(robots_url)
            if robots_response.status_code == 200:
                if robots_response.headers.get('Content-Type', '') == 'application/octet-stream':
                    error_to_print = f'Responded with binary data to robots.txt request'
                    error_reason = 'BIN'
                    print_colored(f'{error_to_print}', 'yellow')
                    log_error(domain, error_to_print)
                    increment_domain_error(domain, error_reason)
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
                    if user_agent == appname and line.lower().startswith('disallow:'):
                        disallow_path = line.split(':', 1)[1].strip()
                        if disallow_path == '/' or disallow_path == '*':
                            disallow_found = True  # Bot is disallowed
                        disallow.append(disallow_path)

                if disallow_found is True:
                    error_to_print = f'Crawling is prohibited by robots.txt'
                    error_reason = 'TXT'
                    print_colored(f'{error_to_print}', 'yellow')
                    log_error(domain, error_to_print)
                    increment_domain_error(domain, error_reason)
                    continue
            elif robots_response.status_code == 202:
                if 'sgcaptcha' in robots_response.text:
                    error_to_print = f'Responded with CAPTCHA to robots.txt request, marking as ignored...'
                    print_colored(f'{error_to_print}', 'magenta')
                    mark_ignore_domain(domain)
                    delete_domain_if_known(domain)
                    continue
            elif robots_response.status_code in [403, 418]:
                custom_headers = {
                    'User-Agent': default_user_agent,
                }
            elif robots_response.status_code == 410:
                error_to_print = f'Responded with HTTP {robots_response.status_code} to robots.txt request, marking as failed...'
                print_colored(f'{error_to_print}', 'red')
                mark_failed_domain(domain)
                delete_domain_if_known(domain)
                continue

            json_content_types = (
                'application/jrd+json', 'application/json', 'application/activity+json',
                'application/problem+json', 'application/ld+json', 'application/activitystreams+json',
                'application/activitypub+json'
            )

            webfinger_response = http_client.get(webfinger_url)

            webfinger_content_type = webfinger_response.headers.get('Content-Type', '')
            webfinger_content_length = webfinger_response.headers.get('Content-Length', '')
            webfinger_content = webfinger_response.text
            if webfinger_response.status_code in [405, 404, 400]:
                if any(ct in webfinger_content_type for ct in json_content_types):
                    if webfinger_content == '':
                        error_to_print = f'Not using Mastodon, marking as ignored...'
                        print_colored(f'{error_to_print}', 'magenta')
                        mark_ignore_domain(domain)
                        delete_domain_if_known(domain)
                        continue
                    else:
                        try:
                            # Try to parse the webfinger_response content as JSON
                            data = json.loads(webfinger_response.text)
                            data = webfinger_response.json()

                            error_to_print = f'Not using Mastodon, marking as ignored...'
                            print_colored(f'{error_to_print}', 'magenta')
                            mark_ignore_domain(domain)
                            delete_domain_if_known(domain)
                            continue
                        except json.JSONDecodeError:
                            error_to_print = f'JSON response to WebFinger request was invalid (HTTP {webfinger_response.status_code})'
                            error_reason = 'JSON'
                            print_colored(f'{error_to_print}', 'yellow')
                            log_error(domain, error_to_print)
                            increment_domain_error(domain, error_reason)
                            continue
                if 'text/plain' in webfinger_content_type:
                    error_to_print = f'Not using Mastodon, marking as ignored...'
                    print_colored(f'{error_to_print}', 'magenta')
                    mark_ignore_domain(domain)
                    delete_domain_if_known(domain)
                    continue
                if 'text/html' in webfinger_content_type:
                    if webfinger_content == '' or 'Bad Request' in webfinger_content or 'Bad request' in webfinger_content or 'Not Found' in webfinger_content or 'Nextcloud' in webfinger_content:
                        error_to_print = f'Not using Mastodon, marking as ignored...'
                        print_colored(f'{error_to_print}', 'magenta')
                        mark_ignore_domain(domain)
                        delete_domain_if_known(domain)
                        continue
                if webfinger_content_type is None or webfinger_content_type == '':
                    error_to_print = f'Not using Mastodon, marking as ignored...'
                    print_colored(f'{error_to_print}', 'magenta')
                    mark_ignore_domain(domain)
                    delete_domain_if_known(domain)
                    continue
                if webfinger_content_length == '0':
                    error_to_print = f'Not using Mastodon, marking as ignored...'
                    print_colored(f'{error_to_print}', 'magenta')
                    mark_ignore_domain(domain)
                    delete_domain_if_known(domain)
                    continue
                else:
                    error_to_print = f'Responded HTTP {webfinger_response.status_code} to WebFinger request'
                    error_reason = webfinger_response.status_code
                    print_colored(f'{error_to_print}', 'yellow')
                    log_error(domain, error_to_print)
                    increment_domain_error(domain, error_reason)
                    continue
            elif webfinger_response.status_code == 200:
                try:
                    # Try to parse the webfinger_response content as JSON
                    data = json.loads(webfinger_response.text)
                    data = webfinger_response.json()
                except json.JSONDecodeError:
                    if any(ct in webfinger_content_type for ct in json_content_types):
                        error_to_print = f'JSON response to WebFinger was invalid (HTTP {webfinger_response.status_code})'
                        error_reason = 'JSON'
                        print_colored(f'{error_to_print}', 'yellow')
                        log_error(domain, error_to_print)
                        increment_domain_error(domain, error_reason)
                        continue
                    elif not webfinger_response.content:
                        error_to_print = f'JSON response to WebFinger was empty (HTTP {webfinger_response.status_code})'
                        error_reason = 'JSON'
                        print_colored(f'{error_to_print}', 'yellow')
                        log_error(domain, error_to_print)
                        increment_domain_error(domain, error_reason)
                        continue
                    elif webfinger_content_type != '':
                        webfinger_content_type_strip = webfinger_content_type.split(';')[0].strip()
                        error_to_print = f'JSON response to WebFinger was {webfinger_content_type_strip} (HTTP {webfinger_response.status_code})'
                        error_reason = 'JSON'
                        print_colored(f'{error_to_print}', 'yellow')
                        log_error(domain, error_to_print)
                        increment_domain_error(domain, error_reason)
                        continue
                    else:
                        error_to_print = f'JSON response to WebFinger was all jacked up (HTTP {webfinger_response.status_code})'
                        error_reason = 'JSON'
                        print_colored(f'{error_to_print}', 'yellow')
                        log_error(domain, error_to_print)
                        increment_domain_error(domain, error_reason)
                        continue

                webfinger_data = webfinger_response.json()
                if isinstance(webfinger_data, dict):
                    webfinger_alias = webfinger_data.get('aliases', [])
                    first_webfinger_alias = next((alias for alias in webfinger_alias if 'https' in alias), None)
                    webfinger_domain = urlparse(first_webfinger_alias)
                    backend_domain = webfinger_domain.netloc
                else:
                    error_to_print = f'Not using Mastodon, marking as ignored...'
                    print_colored(f'{error_to_print}', 'magenta')
                    mark_ignore_domain(domain)
                    delete_domain_if_known(domain)
                    continue

            elif webfinger_response.status_code == 202:
                if 'sgcaptcha' in webfinger_response.text:
                    error_to_print = f'Responded with CAPTCHA to WebFinger request, marking as ignored...'
                    print_colored(f'{error_to_print}', 'magenta')
                    mark_ignore_domain(domain)
                    delete_domain_if_known(domain)
                    continue
            elif webfinger_response.status_code in [451, 422, 418, 401, 402, 403]:
                error_to_print = f'Responded HTTP {webfinger_response.status_code} to WebFinger request, marking as ignored...'
                print_colored(f'{error_to_print}', 'magenta')
                mark_ignore_domain(domain)
                delete_domain_if_known(domain)
                continue
            elif webfinger_response.status_code == 410:
                error_to_print = f'Responded HTTP {webfinger_response.status_code} to WebFinger request, marking as failed...'
                print_colored(f'{error_to_print}', 'red')
                mark_failed_domain(domain)
                delete_domain_if_known(domain)
                continue
            else:
                error_to_print = f'Responded HTTP {webfinger_response.status_code} to WebFinger request'
                print_colored(f'{error_to_print}', 'yellow')
                log_error(domain, error_to_print)
                error_reason = webfinger_response.status_code
                increment_domain_error(domain, error_reason)
                continue

            nodeinfo_url = f'https://{backend_domain}/.well-known/nodeinfo'
            nodeinfo_response = http_client.get(nodeinfo_url)
            if nodeinfo_response.status_code == 200:
                try:
                    data = json.loads(nodeinfo_response.text)
                    data = nodeinfo_response.json()
                except json.JSONDecodeError:
                    nodeinfo_content_type = nodeinfo_response.headers.get('Content-Type', '')
                    if any(ct in nodeinfo_content_type for ct in json_content_types):
                        error_to_print = f'JSON response at {nodeinfo_url} was invalid (HTTP {nodeinfo_response.status_code})'
                        error_reason = 'JSON'
                        print_colored(f'{error_to_print}', 'yellow')
                        log_error(domain, error_to_print)
                        increment_domain_error(domain, error_reason)
                        continue
                    elif not nodeinfo_response.content:
                        error_to_print = f'JSON response at {nodeinfo_url} was empty (HTTP {nodeinfo_response.status_code})'
                        error_reason = 'JSON'
                        print_colored(f'{error_to_print}', 'yellow')
                        log_error(domain, error_to_print)
                        increment_domain_error(domain, error_reason)
                        continue
                    elif nodeinfo_content_type != '':
                        nodeinfo_content_type_strip = nodeinfo_content_type.split(';')[0].strip()
                        error_to_print = f'JSON response at {nodeinfo_url} was {nodeinfo_content_type_strip} (HTTP {nodeinfo_response.status_code})'
                        error_reason = 'JSON'
                        print_colored(f'{error_to_print}', 'yellow')
                        log_error(domain, error_to_print)
                        increment_domain_error(domain, error_reason)
                        continue
                    else:
                        error_to_print = f'JSON response at {nodeinfo_url} was all jacked up (HTTP {nodeinfo_response.status_code})'
                        error_reason = 'JSON'
                        print_colored(f'{error_to_print}', 'yellow')
                        log_error(domain, error_to_print)
                        increment_domain_error(domain, error_reason)
                        continue
            elif nodeinfo_response.status_code == 202:
                if 'sgcaptcha' in nodeinfo_response.text:
                    error_to_print = f'Responded with CAPTCHA to nodeinfo request, marking as ignored...'
                    print_colored(f'{error_to_print}', 'magenta')
                    mark_ignore_domain(domain)
                    delete_domain_if_known(domain)
                    continue
            elif nodeinfo_response.status_code == 403:
                error_to_print = f'Responded HTTP {nodeinfo_response.status_code} at {nodeinfo_url}, marking as ignored...'
                print_colored(f'{error_to_print}', 'magenta')
                mark_ignore_domain(domain)
                delete_domain_if_known(domain)
                continue
            elif nodeinfo_response.status_code == 404:
                error_to_print = f'Not using Mastodon, marking as ignored...'
                print_colored(f'{error_to_print}', 'magenta')
                mark_ignore_domain(domain)
                delete_domain_if_known(domain)
                continue
            elif nodeinfo_response.status_code == 410:
                error_to_print = f'Responded HTTP {nodeinfo_response.status_code} at {nodeinfo_url}, marking as failed...'
                print_colored(f'{error_to_print}', 'red')
                mark_failed_domain(domain)
                delete_domain_if_known(domain)
                continue
            else:
                error_to_print = f'Responded HTTP {nodeinfo_response.status_code} at {nodeinfo_url}'
                error_reason = nodeinfo_response.status_code
                print_colored(f'{error_to_print}', 'yellow')
                log_error(domain, error_to_print)
                increment_domain_error(domain, error_reason)
                continue

            if ('code' in data and data['code'] in ['rest_no_route', 'rest_not_logged_in', 'rest_forbidden', 'rest_user_invalid', 'rest_login_required']) or ('error' in data and data['error'] == 'Restricted'):
                error_to_print = f'Not using Mastodon, marking as ignored...'
                print_colored(f'{error_to_print}', 'magenta')
                mark_ignore_domain(domain)
                delete_domain_if_known(domain)
                continue

            if 'links' in data and len(data['links']) > 0 and 'href' in data['links'][0]:
                linked_nodeinfo_url = data['links'][0]['href']

                if 'wp-json' in linked_nodeinfo_url:
                    error_to_print = f'Not using Mastodon, marking as ignored...'
                    print_colored(f'{error_to_print}', 'magenta')
                    mark_ignore_domain(domain)
                    delete_domain_if_known(domain)
                    continue

                linked_nodeinfo_response = http_client.get(linked_nodeinfo_url)
                if linked_nodeinfo_response.status_code == 200:
                    linked_nodeinfo_content_type = linked_nodeinfo_response.headers.get('Content-Type', '')
                    if 'application/json' not in linked_nodeinfo_content_type:
                        if 'application/activity+json' in linked_nodeinfo_content_type:
                            error_to_print = f'Not using Mastodon, marking as ignored...'
                            print_colored(f'{error_to_print}', 'magenta')
                            mark_ignore_domain(domain)
                            delete_domain_if_known(domain)
                            continue
                        else:
                            error_to_print = f'JSON response at {linked_nodeinfo_url} was invalid (HTTP {linked_nodeinfo_response.status_code})'
                            error_reason = 'JSON'
                            print_colored(f'{error_to_print}', 'yellow')
                            log_error(domain, error_to_print)
                            increment_domain_error(domain, error_reason)
                            continue
                    linked_nodeinfo_data = linked_nodeinfo_response.json()

                    if linked_nodeinfo_data['software']['name'].lower() == 'mastodon' or linked_nodeinfo_data['software']['name'].lower() == 'hometown' or linked_nodeinfo_data['software']['name'].lower() == 'kmyblue' or linked_nodeinfo_data['software']['name'].lower() == 'glitchcafe':
                        software_version_full = linked_nodeinfo_data['software']['version']
                        if isinstance(software_version_full, str):
                            # Remove any unwanted or invalid suffixes from the version string
                            software_version = clean_version_suffix(software_version_full)

                        software_version = clean_version_date(software_version)
                        software_version = clean_version_suffix_more(software_version)
                        software_version = clean_version_hometown(software_version)
                        software_version = clean_version_development(software_version)
                        software_version = clean_version_wrongpatch(software_version)
                        software_version = clean_version_doubledash(software_version)
                        software_version = clean_version_oddballs(domain, software_version)
                        software_version = clean_version_nightly(software_version)
                        # rewrite dumb data
                        # if software_version.startswith("4.2.10"):
                        #     software_version = "4.2.10"

                        total_users = linked_nodeinfo_data['usage']['users']['total']
                        active_month_users = linked_nodeinfo_data['usage']['users']['activeMonth']

                        if software_version.startswith("4"):
                            instance_api_url = f'https://{backend_domain}/api/v2/instance'
                        else:
                            instance_api_url = f'https://{backend_domain}/api/v1/instance'

                        instance_api_response = http_client.get(instance_api_url)
                        instance_api_content_type = instance_api_response.headers.get('Content-Type', '')
                        if 'application/json' not in instance_api_content_type:
                            if instance_api_response.status_code != 200 and instance_api_response.status_code != 410:
                                error_to_print = f'Responded HTTP {instance_api_response.status_code} to instance API request'
                                error_reason = 'API'
                                print_colored(f'{error_to_print}', 'yellow')
                                log_error(domain, error_to_print)
                                increment_domain_error(domain, error_reason)
                                continue
                            elif instance_api_response.status_code == 410:
                                error_to_print = f'Responded HTTP {instance_api_response.status_code} to instance API request, marking as failed...'
                                print_colored(f'{error_to_print}', 'red')
                                mark_failed_domain(domain)
                                delete_domain_if_known(domain)
                                continue

                            error_to_print = f'JSON response to instance API request was invalid (HTTP {instance_api_response.status_code})'
                            error_reason = 'JSON'
                            print_colored(f'{error_to_print}', 'yellow')
                            log_error(domain, error_to_print)
                            increment_domain_error(domain, error_reason)
                            continue
                        instance_api_data = instance_api_response.json()
                        if 'error' in instance_api_data:
                            if instance_api_data['error'] == "This method requires an authenticated user":
                                error_to_print = f'Instance API requires authentication, marking as ignored...'
                                print_colored(f'{error_to_print}', 'magenta')
                                mark_ignore_domain(domain)
                                delete_domain_if_known(domain)
                                continue
                        if software_version.startswith("4"):
                            actual_domain_raw = instance_api_data['domain']
                            actual_domain = actual_domain_raw.lower()
                            contact_account_raw = instance_api_data['contact']['email']
                            contact_account = normalize_email(contact_account_raw).lower()
                            source_url = instance_api_data['source_url']
                        else:
                            actual_domain_raw = instance_api_data['uri']
                            actual_domain = actual_domain_raw.lower()
                            contact_account_raw = instance_api_data['email']
                            contact_account = normalize_email(contact_account_raw).lower()
                            source_url = find_code_repository(backend_domain)
                        if not is_valid_email(contact_account):
                            # Discard the value since it's not valid
                            contact_account = None

                        if source_url:
                            source_url = limit_url_depth(source_url)

                        if source_url == '/source.tar.gz':
                            source_url = 'https://' + actual_domain + source_url

                        if linked_nodeinfo_data['software']['name'].lower() == 'hometown':
                            source_url = 'https://github.com/hometown-fork/hometown'

                        if actual_domain == "gc2.jp":
                            source_url = "https://github.com/gc2-jp/freespeech"

                        cursor = conn.cursor()
                        try:
                            if domain != actual_domain:
                                    # First, check if a record exists for the initial domain
                                    cursor.execute('''
                                        SELECT COUNT(*) FROM MastodonDomains WHERE "Domain" = ?
                                    ''', (domain,))
                                    record_exists = cursor.fetchone()[0] > 0

                                    if record_exists:
                                        print_colored(f'Deleting duplicate record for {domain} which is really {actual_domain}', 'pink')
                                        # Delete the record associated with the initial domain
                                        delete_domain_if_known(domain)

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
                            ''', (actual_domain, software_version, total_users, active_month_users, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), contact_account, source_url, software_version_full))
                            conn.commit()
                        except Exception as e:
                            print(f"Failed to write domain data: {e}")
                            conn.rollback()
                        finally:
                            cursor.close()

                        if active_month_users > max(total_users + 6, total_users + (total_users * 0.25)):
                            error_to_print = f'Mastodon v{software_version} with invalid counts ({active_month_users}:{total_users})'
                            error_reason = '###'
                            print_colored(f'{error_to_print}', 'pink')
                            log_error(domain, error_to_print)
                            increment_domain_error(domain, error_reason)
                            delete_domain_if_known(domain)
                            continue

                        clear_domain_error(domain)

                        if software_version == software_version_full:
                            print_colored(f'Mastodon v{software_version}', 'green')
                        else:
                            print_colored(f'Mastodon v{software_version} ({software_version_full})', 'green')

                    else:
                        error_to_print = f'Not using Mastodon, marking as ignored...'
                        print_colored(f'{error_to_print}', 'magenta')
                        mark_ignore_domain(domain)
                        delete_domain_if_known(domain)
                        continue
                else:
                    error_to_print = f'Responded HTTP {linked_nodeinfo_response.status_code} at {linked_nodeinfo_url}'
                    if linked_nodeinfo_response.status_code == 403:
                        print_colored(f'{error_to_print}', 'magenta')
                        mark_ignore_domain(domain)
                        delete_domain_if_known(domain)
                    elif linked_nodeinfo_response.status_code == 410:
                        print_colored(f'{error_to_print}', 'red')
                        mark_failed_domain(domain)
                        delete_domain_if_known(domain)
                    else:
                        error_reason = linked_nodeinfo_response.status_code
                        print_colored(f'{error_to_print}', 'yellow')
                        log_error(domain, error_to_print)
                        increment_domain_error(domain, error_reason)
            else:
                error_to_print = f'Not using Mastodon, marking as ignored...'
                print_colored(f'{error_to_print}', 'magenta')
                mark_ignore_domain(domain)
                delete_domain_if_known(domain)
                continue

        except httpx.RequestError or httpx.HTTPStatusError as e:
            error_message = str(e)
            if 'SSL' in error_message:
                error_reason = 'SSL'
                delete_domain_if_known(domain)
            else:
                error_reason = 'HTTP'
            error_to_print = error_message
            print_colored(f'{error_message}', 'orange')
            log_error(domain, error_to_print)
            increment_domain_error(domain, error_reason)
        except Exception as e:
            error_message = str(e)
            error_to_print = error_message
            error_reason = '???'
            print_colored(f'{error_message}', 'orange')
            log_error(domain, error_to_print)
            increment_domain_error(domain, error_reason)

def read_domain_list(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file]

def load_from_database(user_choice):
    cursor = conn.cursor()
    try:
        if user_choice == "4":
            cursor.execute("SELECT Domain FROM RawDomains WHERE Errors > 7 ORDER BY LENGTH(DOMAIN) ASC")
        elif user_choice == "5":
            cursor.execute("SELECT Domain FROM RawDomains WHERE Errors < 6 ORDER BY LENGTH(DOMAIN) ASC")
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
                "Software Version" NOT LIKE '4.3.0'
            ORDER BY "Total Users" DESC
            ;
            """
            cursor.execute(query)
        elif user_choice == "9":
            cursor.execute("SELECT Domain FROM RawDomains WHERE Reason = 'SSL' ORDER BY Errors ASC")
        elif user_choice == "10":
            cursor.execute("SELECT Domain FROM RawDomains WHERE Reason = 'DNS' ORDER BY Errors ASC")
        elif user_choice == "11":
            cursor.execute("SELECT Domain FROM RawDomains WHERE Reason = '###' ORDER BY Errors ASC")
        elif user_choice == "12":
            cursor.execute("SELECT Domain FROM RawDomains WHERE Reason = 'HTTP' ORDER BY Errors ASC")
        elif user_choice == "13":
            cursor.execute("SELECT Domain FROM RawDomains WHERE Reason > 399 AND Reason < 500 ORDER BY Errors ASC;")
        elif user_choice == "14":
            cursor.execute("SELECT Domain FROM RawDomains WHERE Failed = '1' ORDER BY Domain")
        elif user_choice == "15":
            cursor.execute("SELECT Domain FROM RawDomains WHERE Reason = '???' ORDER BY Errors ASC")
        elif user_choice == "16":
            cursor.execute("SELECT Domain FROM RawDomains WHERE Reason = 'API' ORDER BY Errors ASC")
        elif user_choice == "17":
            cursor.execute("SELECT Domain FROM RawDomains WHERE Reason = 'JSON' ORDER BY Errors ASC")
        elif user_choice == "18":
            cursor.execute("SELECT Domain FROM RawDomains WHERE Reason > 499 AND Reason < 600 ORDER BY Errors ASC;")
        elif user_choice == "21":
            cursor.execute('SELECT Domain FROM MastodonDomains WHERE "Active Users (Monthly)" = 0 ORDER BY Timestamp ASC')
        elif user_choice == "22":
            query = """
            SELECT Domain
            FROM MastodonDomains
            WHERE
                "Software Version" LIKE '4.4%'
            ORDER BY "Total Users" DESC
            ;
            """
            cursor.execute(query)
        elif user_choice == "23":
            cursor.execute("SELECT Domain FROM RawDomains WHERE Reason = 'TXT' ORDER BY Errors ASC")
        elif user_choice == "400":
            cursor.execute("SELECT Domain FROM RawDomains WHERE Reason LIKE '%400%' ORDER BY Errors ASC")
        elif user_choice == "404":
            cursor.execute("SELECT Domain FROM RawDomains WHERE Reason LIKE '%404%' ORDER BY Errors ASC")
        elif user_choice == "406":
            cursor.execute("SELECT Domain FROM RawDomains WHERE Reason LIKE '%406%' ORDER BY Errors ASC")
        else:
            cursor.execute("SELECT Domain FROM RawDomains WHERE (Failed IS NULL OR Failed = '' OR Failed = '0') AND (Ignore IS NULL OR Ignore = '' OR Ignore = '0') AND (Errors < 6 OR Errors IS NULL) ORDER BY Domain ASC")
        domain_list = [row[0].strip() for row in cursor.fetchall() if row[0].strip()]
        conn.commit()
    except Exception as e:
        print(f"Failed to obtain selected domain list: {e}")
        conn.rollback()
    finally:
        cursor.close()
    return domain_list

def load_from_file(file_name):
    cursor = conn.cursor()
    domain_list = []
    with open(file_name, 'r') as file:
        for line in file:
            domain = line.strip()
            if domain:  # Ensure the domain is not empty
                domain_list.append(domain)
                # Check if the domain already exists in the database
                cursor.execute('SELECT COUNT(*) FROM RawDomains WHERE Domain = ?', (domain,))
                exists = cursor.fetchone()[0] > 0

                # If not, insert the new domain into the database
                if not exists:
                    cursor.execute('INSERT INTO RawDomains (Domain, Errors) VALUES (?, ?)', (domain, None))
                    cursor.close()
                conn.commit()
    return domain_list

def print_colored(text: str, color: str, **kwargs) -> None:
    print(f"{colors.get(color, '')}{text}{colors['reset']}", **kwargs)

def print_menu() -> None:
    menu_options = {
        "Alter direction": {"2": "Reverse", "3": "Random"},
        "Retry general errors": {"4": "Overflow", "5": "Underflow"},
        "Retry specific errors": {"9": "SSL", "10": "DNS", "11": "###", "15": "???", "16": "API", "17": "JSON", "23": "TXT"},
        "Retry HTTP errors": {"12": "HTTP", "13": "400s", "18": "500s", "400": "400", "404": "404", "406": "406"},
        "Retry fatal errors": {"7": "Ignored", "14": "Failed"},
        "Retry good data": {"6": "Stale", "8": "Outdated", "21": "Inactive", "22": "Main"},
    }

    print_colored(f"{appname} v{appversion}", "bold")
    for category, options in menu_options.items():
        options_str = " ".join(f"{key}={value}" for key, value in options.items())
        print_colored(f"{category}: {options_str}", "bold")
    print_colored("Enter your choice (1, 2, 3, etc):", "bold", end=" ")
    sys.stdout.flush()

def get_user_choice() -> str:
    ready, _, _ = select.select([sys.stdin], [], [], 5)  # Wait for input for 5 seconds
    if ready:
        return sys.stdin.readline().strip()
    print_colored("\nDefaulting to standard crawl", "cyan")
    return "1"

# Main program starts here

try:
    print_menu()
    user_choice = get_user_choice()
    print_colored(f"Choice selected: {user_choice}", "magenta")

    domain_list_file = sys.argv[1] if len(sys.argv) > 1 else None

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

    junk_domains = get_junk_keywords()
    bad_tlds = get_bad_tld()
    failed_domains = get_failed_domains()
    ignored_domains = get_ignored_domains()

    check_and_record_domains(domain_list, ignored_domains, failed_domains, user_choice, junk_domains, bad_tlds, http_client)
except KeyboardInterrupt:
    conn.close()
    http_client.close()  # Close the httpx client
    print(f"\n{appname} interrupted by user. Exiting gracefully...")
finally:
    print("Goodbye!")