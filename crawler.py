#!/usr/bin/env python3

try:
    from datetime import datetime, timedelta
    import dns.resolver
    import json
    import os
    import random
    import re
    import httpx
    import select
    import sqlite3
    import sys
    import mimetypes
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
conn = sqlite3.connect(db_path) # type: ignore

def perform_dns_query(domain):
    record_types = ['A', 'AAAA', 'CNAME']
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type, lifetime=5)
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

def clean_version(software_version_full):
    software_version = clean_version_suffix(software_version_full)
    software_version = clean_version_date(software_version)
    software_version = clean_version_suffix_more(software_version)
    software_version = clean_version_hometown(software_version)
    software_version = clean_version_development(software_version)
    software_version = clean_version_wrongpatch(software_version)
    software_version = clean_version_doubledash(software_version)
    software_version = clean_version_nightly(software_version)
    return software_version

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
    for index, domain in enumerate(domain_list, start=1):
        print_colored(f'{domain} ({index}/{len(domain_list)})', 'bold')

        if should_skip_domain(domain, ignored_domains, failed_domains, user_choice):
            continue

        if is_junk_or_bad_tld(domain, junk_domains, bad_tlds):
            continue

        if not check_dns(domain):
            continue

        try:
            process_domain(domain, httpx_client)
        except Exception as e:
            handle_http_exception(domain, e)

def should_skip_domain(domain, ignored_domains, failed_domains, user_choice):
    if user_choice != "7" and domain in ignored_domains:
        print_colored('Previously ignored!', 'cyan')
        delete_domain_if_known(domain)
        return True
    if user_choice != "14" and domain in failed_domains:
        print_colored('Previously failed!', 'cyan')
        delete_domain_if_known(domain)
        return True
    return False

def is_junk_or_bad_tld(domain, junk_domains, bad_tlds):
    if any(junk in domain for junk in junk_domains):
        print_colored('Known junk domain, ignoring...', 'magenta')
        mark_failed_domain(domain)
        delete_domain_if_known(domain)
        return True
    if any(domain.endswith(tld) for tld in bad_tlds):
        print_colored('Known bad TLD, ignoring...', 'magenta')
        mark_failed_domain(domain)
        delete_domain_if_known(domain)
        return True
    return False

def check_dns(domain):
    dns_result = perform_dns_query(domain)
    if dns_result is False:
        print_colored('DNS query returned NXDOMAIN, marking as failed...', 'red')
        mark_failed_domain(domain)
        delete_domain_if_known(domain)
        return False
    elif dns_result is None:
        print_colored('DNS query failed to resolve', 'yellow')
        log_error(domain, 'DNS query failed to resolve')
        increment_domain_error(domain, 'DNS')
        return False
    return True

def process_domain(domain, httpx_client):
    if not check_robots_txt(domain, httpx_client):
        return  # Stop processing this domain

    webfinger_data = check_webfinger(domain, httpx_client)
    if not webfinger_data:
        return

    nodeinfo_data = check_nodeinfo(domain, webfinger_data['backend_domain'], httpx_client)
    if not nodeinfo_data:
        return

    if is_mastodon_instance(nodeinfo_data):
        process_mastodon_instance(domain, webfinger_data, nodeinfo_data, httpx_client)
    else:
        mark_as_non_mastodon(domain)

def check_robots_txt(domain, httpx_client):
    robots_url = f'https://{domain}/robots.txt'
    try:
        response = httpx_client.get(robots_url)
        # Check for valid HTTP status code
        if response.status_code in [200]:
            content_type = response.headers.get('Content-Type', '')
            if content_type in mimetypes.types_map.values() and not content_type.startswith('text/'):
                error_message = 'robots.txt is not a text file'
                print_colored(f'{error_message}', 'yellow')
                log_error(domain, error_message)
                increment_domain_error(domain, 'TXT')
                return False

            robots_txt = response.text
            lines = robots_txt.split('\n')
            user_agent = None
            for line in lines:
                line = line.strip().lower()
                if line.startswith('user-agent:'):
                    user_agent = line.split(':', 1)[1].strip()
                elif line.startswith('disallow:'):
                    disallow_path = line.split(':', 1)[1].strip()
                    if user_agent in ['*', appname.lower()] and (disallow_path == '/' or disallow_path == '*'):
                        print_colored('Crawling is prohibited by robots.txt, marking as ignored...', 'magenta')
                        mark_ignore_domain(domain)
                        delete_domain_if_known(domain)
                        return False
        # Check for specific HTTP status codes
        elif response.status_code in [202]:
            if 'sgcaptcha' in response.text:
                print_colored('Responded with CAPTCHA to robots.txt request, marking as ignored...', 'magenta')
                mark_ignore_domain(domain)
                delete_domain_if_known(domain)
                return False
        elif response.status_code in [410]:
            print_colored(f'Responded HTTP {response.status_code} to robots.txt request, marking as failed...', 'red')
            mark_failed_domain(domain)
            delete_domain_if_known(domain)
            return False

    except httpx.RequestError as e:
        handle_http_exception(domain, e)
        return False

    return True

def check_webfinger(domain, httpx_client):
    webfinger_url = f'https://{domain}/.well-known/webfinger?resource=acct:{domain}@{domain}'
    try:
        response = httpx_client.get(webfinger_url)
        if response.status_code in [200]:
            content_type = response.headers.get('Content-Type', '')
            content = response.content
            if 'json' not in content_type:
                error_message = 'WebFinger reply is not a JSON file'
                print_colored(f'{error_message}', 'yellow')
                log_error(domain, error_message)
                increment_domain_error(domain, 'JSON')
                return None
            if not content:
                error_message = 'WebFinger reply is empty'
                print_colored(f'{error_message}', 'yellow')
                log_error(domain, error_message)
                increment_domain_error(domain, 'JSON')
                return None
            else:
                data = response.json()
            aliases = data.get('aliases', [])
            if not aliases:
                mark_as_non_mastodon(domain)
                return None
            first_alias = next((alias for alias in aliases if 'https' in alias), None)
            if first_alias:
                backend_domain = urlparse(first_alias).netloc
                return {'backend_domain': backend_domain}
        elif response.status_code in [429, 418, 405, 404, 403, 400, 300]:
            print_colored(f'Responded HTTP {response.status_code} to WebFinger request, marking as ignored...', 'magenta')
            mark_ignore_domain(domain)
            delete_domain_if_known(domain)
        elif response.status_code in [410]:
            print_colored(f'Responded HTTP {response.status_code} to WebFinger request, marking as failed...', 'red')
            mark_failed_domain(domain)
            delete_domain_if_known(domain)
        else:
            error_message = f'Responded HTTP {response.status_code} to WebFinger request'
            print_colored(f'{error_message}', 'yellow')
            log_error(domain, f'{error_message}')
            increment_domain_error(domain, str(response.status_code))
    except httpx.RequestError as e:
        handle_http_exception(domain, e)
    except json.JSONDecodeError as e:
        handle_json_exception(domain, e)
    return None

def check_nodeinfo(domain, backend_domain, httpx_client):
    nodeinfo_url = f'https://{backend_domain}/.well-known/nodeinfo'
    try:
        response = httpx_client.get(nodeinfo_url)
        if response.status_code in [200]:
            content_type = response.headers.get('Content-Type', '')
            if 'json' not in content_type:
                error_message = 'NodeInfo reply is not a JSON file'
                print_colored(f'{error_message}', 'yellow')
                log_error(domain, error_message)
                increment_domain_error(domain, 'JSON')
                return None
            data = response.json()
            if 'links' in data and len(data['links']) > 0:
                nodeinfo_2_url = next((link['href'] for link in data['links'] if link.get('rel') == 'http://nodeinfo.diaspora.software/ns/schema/2.0'), None)
                if nodeinfo_2_url:
                    nodeinfo_response = httpx_client.get(nodeinfo_2_url)
                    if nodeinfo_response.status_code in [200]:
                        nodeinfo_response_content_type = nodeinfo_response.headers.get('Content-Type', '')
                        if 'json' not in nodeinfo_response_content_type:
                            error_message = 'NodeInfo V2 reply is not a JSON file'
                            print_colored(f'{error_message}', 'yellow')
                            log_error(domain, error_message)
                            increment_domain_error(domain, 'JSON')
                            return None
                        return nodeinfo_response.json()
                    else:
                        error_message = f'Responded HTTP {nodeinfo_response.status_code} @ {nodeinfo_2_url}'
                        print_colored(f'{error_message}', 'yellow')
                        log_error(domain, f'{error_message}')
                        increment_domain_error(domain, str(nodeinfo_response.status_code))
                else:
                    mark_as_non_mastodon(domain)
        elif response.status_code in [429, 418, 405, 404, 403, 400, 300]:
            print_colored(f'Responded HTTP {response.status_code} to NodeInfo request, marking as ignored...', 'magenta')
            mark_ignore_domain(domain)
            delete_domain_if_known(domain)
        elif response.status_code in [410]:
            print_colored(f'Responded HTTP {response.status_code} to NodeInfo request, marking as failed...', 'red')
            mark_failed_domain(domain)
            delete_domain_if_known(domain)
        else:
            error_message = f'Responded HTTP {response.status_code} to NodeInfo request'
            print_colored(f'{error_message}', 'yellow')
            log_error(domain, f'{error_message}')
            increment_domain_error(domain, str(response.status_code))
    except httpx.RequestError as e:
        handle_http_exception(domain, e)
    except json.JSONDecodeError as e:
        handle_json_exception(domain, e)
    return None

def is_mastodon_instance(nodeinfo_data):
    software_name = nodeinfo_data.get('software', {}).get('name', '').lower()
    return software_name in ['mastodon', 'hometown', 'kmyblue', 'glitchcafe']

def process_mastodon_instance(domain, webfinger_data, nodeinfo_data, httpx_client):
    software_name = nodeinfo_data['software']['name'].lower()
    software_version = clean_version(nodeinfo_data['software']['version'])
    total_users = nodeinfo_data['usage']['users']['total']
    active_month_users = nodeinfo_data['usage']['users']['activeMonth']

    if software_version.startswith("4"):
        instance_api_url = f'https://{webfinger_data["backend_domain"]}/api/v2/instance'
    else:
        instance_api_url = f'https://{webfinger_data["backend_domain"]}/api/v1/instance'

    try:
        response = httpx_client.get(instance_api_url)
        if response.status_code in [200]:
            content_type = response.headers.get('Content-Type', '')
            if 'json' not in content_type:
                error_message = 'Instance reply is not a JSON file'
                print_colored(f'{error_message}', 'yellow')
                log_error(domain, error_message)
                increment_domain_error(domain, 'JSON')
                return None
            instance_api_data = response.json()

            if 'error' in instance_api_data:
                if instance_api_data['error'] == "This method requires an authenticated user":
                    print_colored('Instance API requires authentication, marking as ignored...', 'magenta')
                    mark_ignore_domain(domain)
                    delete_domain_if_known(domain)
                    return

            if software_version.startswith("4"):
                actual_domain = instance_api_data['domain'].lower()
                contact_account = normalize_email(instance_api_data['contact']['email']).lower()
                source_url = instance_api_data['source_url']
            else:
                actual_domain = instance_api_data['uri'].lower()
                contact_account = normalize_email(instance_api_data['email']).lower()
                source_url = find_code_repository(webfinger_data["backend_domain"])

            if not is_valid_email(contact_account):
                contact_account = None

            if source_url:
                source_url = limit_url_depth(source_url)

            if source_url == '/source.tar.gz':
                source_url = f'https://{actual_domain}{source_url}'

            if software_name == 'hometown':
                source_url = 'https://github.com/hometown-fork/hometown'

            if actual_domain == "gc2.jp":
                source_url = "https://github.com/gc2-jp/freespeech"

            # Check for invalid user counts
            if active_month_users > max(total_users + 6, total_users + (total_users * 0.25)):
                error_to_print = f'Mastodon v{software_version} with invalid counts ({active_month_users}:{total_users})'
                print_colored(error_to_print, 'pink')
                log_error(domain, error_to_print)
                increment_domain_error(domain, '###')
                delete_domain_if_known(domain)
                return

            # Update database
            update_mastodon_domain(actual_domain, software_version, total_users, active_month_users, contact_account, source_url)

            clear_domain_error(domain)

            if software_version == nodeinfo_data['software']['version']:
                print_colored(f'Mastodon v{software_version}', 'green')
            else:
                print_colored(f'Mastodon v{software_version} ({nodeinfo_data["software"]["version"]})', 'green')

        elif response.status_code in [429, 418, 405, 404, 403, 400, 300]:
            print_colored(f'Responded HTTP {response.status_code} to API request, marking as ignored...', 'magenta')
            mark_ignore_domain(domain)
            delete_domain_if_known(domain)
        elif response.status_code in [410]:
            print_colored(f'Responded HTTP {response.status_code} to API request, marking as failed...', 'red')
            mark_failed_domain(domain)
            delete_domain_if_known(domain)
        elif response.status_code in [500]:
            error_message = f'Responded HTTP {response.status_code} to API request'
            print_colored(f'{error_message}', 'yellow')
            log_error(domain, f'{error_message}')
            increment_domain_error(domain, str(response.status_code))
        else:
            error_message = f'Responded HTTP {response.status_code} to API request'
            print_colored(f'{error_message}', 'yellow')
            log_error(domain, f'{error_message}')
            increment_domain_error(domain, str(response.status_code))

    except httpx.RequestError as e:
        handle_http_exception(domain, e)
    except json.JSONDecodeError as e:
        handle_json_exception(domain, e)

def update_mastodon_domain(domain, software_version, total_users, active_month_users, contact_account, source_url):
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO MastodonDomains
            ("Domain", "Software Version", "Total Users", "Active Users (Monthly)", "Timestamp", "Contact", "Source", "Full Version")
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT("Domain") DO UPDATE SET
            "Software Version" = excluded."Software Version",
            "Total Users" = excluded."Total Users",
            "Active Users (Monthly)" = excluded."Active Users (Monthly)",
            "Timestamp" = excluded."Timestamp",
            "Contact" = excluded."Contact",
            "Source" = excluded."Source",
            "Full Version" = excluded."Full Version"
        ''', (domain, software_version, total_users, active_month_users,
              datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
              contact_account, source_url, software_version))
        conn.commit()
    except Exception as e:
        print(f"Failed to update Mastodon domain data: {e}")
        conn.rollback()
    finally:
        cursor.close()

def mark_as_non_mastodon(domain):
    print_colored('Not using Mastodon, marking as ignored...', 'magenta')
    mark_ignore_domain(domain)
    delete_domain_if_known(domain)

def handle_http_exception(domain, exception):
    error_message = str(exception)
    if error_message in ['SSL', 'ssl']:
        error_reason = 'SSL'
        delete_domain_if_known(domain)
    else:
        error_reason = 'HTTP'
    print_colored(error_message, 'orange')
    log_error(domain, error_message)
    increment_domain_error(domain, error_reason)

def handle_json_exception(domain, exception):
    error_message = str(exception)
    error_reason = 'JSON'
    print_colored(error_message, 'orange')
    log_error(domain, error_message)
    increment_domain_error(domain, error_reason)

# Other helper functions (like delete_domain_if_known, mark_failed_domain, etc.) remain unchanged

def read_domain_list(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file]

def load_from_database(user_choice):
    query_map = {
        "1": "SELECT Domain FROM RawDomains WHERE (Failed IS NULL OR Failed = '' OR Failed = '0') AND (Ignore IS NULL OR Ignore = '' OR Ignore = '0') AND (Errors < 6 OR Errors IS NULL) ORDER BY Domain ASC",
        "4": f"SELECT Domain FROM RawDomains WHERE Errors >= {error_threshold + 1} ORDER BY LENGTH(DOMAIN) ASC",
        "5": f"SELECT Domain FROM RawDomains WHERE Errors <= {error_threshold} ORDER BY LENGTH(DOMAIN) ASC",
        "6": "SELECT Domain FROM RawDomains WHERE Ignore = '1' ORDER BY Domain",
        "7": "SELECT Domain FROM RawDomains WHERE Failed = '1' ORDER BY Domain",
        "10": "SELECT Domain FROM RawDomains WHERE Reason = 'SSL' ORDER BY Errors ASC",
        "11": "SELECT Domain FROM RawDomains WHERE Reason = 'DNS' ORDER BY Errors ASC",
        "12": "SELECT Domain FROM RawDomains WHERE Reason = 'HTTP' ORDER BY Errors ASC",
        "20": "SELECT Domain FROM RawDomains WHERE Reason > 299 AND Reason < 400 ORDER BY Errors ASC",
        "21": "SELECT Domain FROM RawDomains WHERE Reason > 399 AND Reason < 500 ORDER BY Errors ASC",
        "22": "SELECT Domain FROM RawDomains WHERE Reason > 499 AND Reason < 600 ORDER BY Errors ASC",
        "30": "SELECT Domain FROM RawDomains WHERE Reason = '###' ORDER BY Errors ASC",
        "31": "SELECT Domain FROM RawDomains WHERE Reason = 'JSON' ORDER BY Errors ASC",
        "32": "SELECT Domain FROM RawDomains WHERE Reason = 'TXT' ORDER BY Errors ASC",
        "40": f"SELECT Domain FROM MastodonDomains WHERE Timestamp < datetime('now', '-{error_threshold} days') ORDER BY Timestamp DESC",
        "41": f"SELECT Domain FROM MastodonDomains WHERE \"Software Version\" NOT LIKE '{version_main_branch}%' AND \"Software Version\" NOT LIKE '{version_latest_release}' ORDER BY \"Total Users\" DESC",
        "42": "SELECT Domain FROM MastodonDomains WHERE \"Active Users (Monthly)\" = 0 ORDER BY Timestamp ASC",
        "43": f"SELECT Domain FROM MastodonDomains WHERE \"Software Version\" LIKE '{version_main_branch}%' ORDER BY \"Total Users\" DESC",
    }

    query = query_map.get(user_choice)
    if not query:
        print(f"Invalid choice: {user_choice}. Using default query.")
        query = query_map["1"]  # Default query

    cursor = conn.cursor()
    try:
        cursor.execute(query)
        domain_list = [row[0].strip() for row in cursor.fetchall() if row[0].strip()]
        conn.commit()
    except Exception as e:
        print(f"Failed to obtain selected domain list: {e}")
        conn.rollback()
        domain_list = []
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
        "Change process direction": {"1": "Standard", "2": "Reverse", "3": "Random"},
        "Retry general errors": {"4": f"Errors >={error_threshold + 1}", "5": f"Errors <={error_threshold}"},
        "Retry fatal errors": {"6": "Ignored", "7": "Failed"},
        "Retry connection errors": {"10": "SSL", "11": "DNS", "12": "HTTP"},
        "Retry HTTP errors": {"20": "300s", "21": "400s", "22": "500s"},
        "Retry specific errors": {"30": "###", "31": "JSON", "32": "TXT"},
        "Retry good data": {"40": f"Last Contacted >{error_threshold} Days Ago", "41": "Old Versions", "42": "Active Zero", "43": "Main Runners"},
    }

    print_colored(f"{appname} v{appversion}", "bold")
    for category, options in menu_options.items():
        options_str = " ".join(f"({key}) {value}" for key, value in options.items())
        print_colored(f"{category}: ", "bold", end="")
        print_colored(options_str, "")  # Print options without bold
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
    print_colored(f"\n{appname} interrupted by user", "bold")
finally:
    print_colored("Crawling complete!", "bold")