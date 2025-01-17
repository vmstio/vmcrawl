#!/usr/bin/env python3

try:
    from datetime import datetime, timedelta
    import httpx
    import unicodedata
    import json
    import os
    import random
    import re
    import select
    import sqlite3
    import sys
    import mimetypes
    from packaging import version
    from bs4 import BeautifulSoup
    from urllib.parse import urlparse, urlunparse
    from dotenv import load_dotenv
    from lxml import etree
except ImportError as e:
    print(f"Error importing module: {e}")
    sys.exit(1)

from common import *
load_dotenv()

current_filename = os.path.basename(__file__)
db_path = os.getenv("db_path")
conn = sqlite3.connect(db_path) # type: ignore

def is_valid_email(email):
    pattern = r'^[\w\.-]+(?:\+[\w\.-]+)?@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None

def normalize_email(email):
    email = re.sub(r'(\[at\]|\(at\)|\{at\}| at | @ |\[@\]| \[at\] | \(at\) | \{at\} )', '@', email, flags=re.IGNORECASE)
    email = re.sub(r'(\[dot\]|\(dot\)|\{dot\}| dot | \[dot\] | \(dot\) | \{dot\} )', '.', email, flags=re.IGNORECASE)
    return email

def has_emoji_or_special_chars(domain):
    if domain.startswith('xn--'):
        try:
            domain = domain.encode('ascii').decode('idna')
        except Exception as e:
            return True
    try:
        for char in domain:
            if (unicodedata.category(char) in ['So', 'Cf'] or ord(char) >= 0x1F300):
                return True
            if not (char.isalnum() or char in '-_.'):
                return True
    except Exception as e:
        return True
    return False

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
            INSERT INTO RawDomains (Domain, Failed, Ignore, Errors, Reason, NXDOMAIN, Robots)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(Domain) DO UPDATE SET
            Failed = excluded.Failed,
            Ignore = excluded.Ignore,
            Errors = excluded.Errors,
            Reason = excluded.Reason,
            NXDOMAIN = excluded.NXDOMAIN,
            Robots = excluded.Robots
        ''', (domain, None, None, new_errors, error_reason, None, None))
        conn.commit()
    except Exception as e:
        print(f"Failed to increment domain error: {e}")
        conn.rollback()
    finally:
        cursor.close()

def delete_if_error_max(domain):
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT Errors FROM RawDomains WHERE Domain = ?', (domain,))
        result = cursor.fetchone()
        if result and result[0] >= error_threshold:
            cursor.execute('SELECT Timestamp FROM MastodonDomains WHERE Domain = ?', (domain,))
            timestamp = cursor.fetchone()
            if timestamp and (datetime.now() - datetime.strptime(timestamp[0], '%Y-%m-%d %H:%M:%S')).days >= error_threshold:
                delete_domain_if_known(domain)

    except Exception as e:
        print(f"Failed to delete maxed out domain: {e}")
        conn.rollback()
    finally:
        cursor.close()

def clear_domain_error(domain):
    cursor = conn.cursor()
    try:
        # Insert or update the domain with the new errors count
        cursor.execute('''
            INSERT INTO RawDomains (Domain, Failed, Ignore, Errors, Reason, NXDOMAIN, Robots)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(Domain) DO UPDATE SET
            Failed = excluded.Failed,
            Ignore = excluded.Ignore,
            Errors = excluded.Errors,
            Reason = excluded.Reason,
            NXDOMAIN = excluded.NXDOMAIN,
            Robots = excluded.Robots
        ''', (domain, None, None, None, None, None, None))
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
            INSERT INTO RawDomains (Domain, Failed, Ignore, Errors, Reason, NXDOMAIN, Robots)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(Domain) DO UPDATE SET
            Failed = excluded.Failed,
            Ignore = excluded.Ignore,
            Errors = excluded.Errors,
            Reason = excluded.Reason,
            NXDOMAIN = excluded.NXDOMAIN,
            Robots = excluded.Robots
        ''', (domain, None, 1, None, None, None, None))
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
            INSERT INTO RawDomains (Domain, Failed, Ignore, Errors, Reason, NXDOMAIN, Robots)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(Domain) DO UPDATE SET
            Failed = excluded.Failed,
            Ignore = excluded.Ignore,
            Errors = excluded.Errors,
            Reason = excluded.Reason,
            NXDOMAIN = excluded.NXDOMAIN,
            Robots = excluded.Robots
        ''', (domain, 1, None, None, None, None, None))
        conn.commit()
    except Exception as e:
        print(f"Failed to mark domain failed: {e}")
        conn.rollback()
    finally:
        cursor.close()

def mark_nxdomain_domain(domain):
    cursor = conn.cursor()
    try:
        # Insert or update the domain with the new errors count
        cursor.execute('''
            INSERT INTO RawDomains (Domain, Failed, Ignore, Errors, Reason, NXDOMAIN, Robots)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(Domain) DO UPDATE SET
            Failed = excluded.Failed,
            Ignore = excluded.Ignore,
            Errors = excluded.Errors,
            Reason = excluded.Reason,
            NXDOMAIN = excluded.NXDOMAIN,
            Robots = excluded.Robots
        ''', (domain, None, None, None, None, 1, None))
        conn.commit()
    except Exception as e:
        print(f"Failed to mark domain NXDOMAIN: {e}")
        conn.rollback()
    finally:
        cursor.close()

def mark_norobots_domain(domain):
    cursor = conn.cursor()
    try:
        # Insert or update the domain with the new errors count
        cursor.execute('''
            INSERT INTO RawDomains (Domain, Failed, Ignore, Errors, Reason, NXDOMAIN, Robots)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(Domain) DO UPDATE SET
            Failed = excluded.Failed,
            Ignore = excluded.Ignore,
            Errors = excluded.Errors,
            Reason = excluded.Reason,
            NXDOMAIN = excluded.NXDOMAIN,
            Robots = excluded.Robots
        ''', (domain, None, None, None, None, None, 1))
        conn.commit()
    except Exception as e:
        print(f"Failed to mark domain NoRobots: {e}")
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

def delete_domain_from_raw(domain):
    cursor = conn.cursor()
    try:
        cursor.execute('''
            DELETE FROM RawDomains WHERE "Domain" = ?
            ''', (domain,))
        conn.commit()
    except Exception as e:
        print(f"Failed to delete known domain: {e}")
        conn.rollback()
    finally:
        cursor.close()

def clean_version(software_version_full):
    software_version = clean_version_suffix(software_version_full)
    software_version = clean_version_oddstring(software_version)
    software_version = clean_version_dumbstring(software_version)
    software_version = clean_version_date(software_version)
    software_version = clean_version_suffix_more(software_version)
    software_version = clean_version_hometown(software_version)
    software_version = clean_version_development(software_version)
    software_version = clean_version_wrongpatch(software_version)
    software_version = clean_version_doubledash(software_version)
    software_version = clean_version_nightly(software_version)
    return software_version

def clean_version_dumbstring(software_version):
    unwanted_strings = ["-pre"]

    for unwanted_string in unwanted_strings:
        software_version = software_version.replace(unwanted_string, "")

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

def clean_version_oddstring(software_version):
    if "mastau" in software_version:
        software_version = software_version.replace("mastau", "alpha")

    return software_version

def clean_version_wrongpatch(software_version):
    match = re.match(r'^(\d+)\.(\d+)\.(\d+)(-.+)?$', software_version)

    if match:
        if version_latest_release:
            a, b, c = int(version_latest_release.split('.')[0]), int(version_latest_release.split('.')[1]), int(version_latest_release.split('.')[2])
        else:
            a, b, c = 0, 0, 0  # Default values or handle the case where version_latest_release is None
        m = int(version_main_branch.split('.')[1])
        x, y, z = int(match.group(1)), int(match.group(2)), int(match.group(3))
        additional_data = match.group(4)  # This will be None if no dash and additional data is present

        if x == a:
            if y == b:
                if z > c:
                    z = 0
                    return f"{x}.{y}.{z}{additional_data or ''}"
                return software_version
            elif y == m:
                if z != 0:
                    z = 0
                    return f"{x}.{y}.{z}{additional_data or ''}"
                return software_version
            else:
                return software_version
        else:
            return software_version
    else:
        return software_version

def clean_version_nightly(software_version):
    # Handle -nightly with date and -security suffix
    match = re.match(r"4\.[34]\.0-nightly\.(\d{4}-\d{2}-\d{2})(-security)?", software_version)
    if match:
        nightly_date_str, is_security = match.groups()
        nightly_date = datetime.strptime(nightly_date_str, "%Y-%m-%d")

        if is_security:
            nightly_date += timedelta(days=1)

        version_ranges = [
            ("4.4.0-alpha.2", datetime(2025, 1, 16), datetime(2025, 12, 31)),
            ("4.4.0-alpha.1", datetime(2024, 10, 8), datetime(2025, 1, 15)),
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

def get_nxdomain_domains():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT Domain FROM RawDomains WHERE NXDOMAIN = '1'")
        nxdomain_domains = [row[0].strip() for row in cursor.fetchall() if row[0].strip()]
        conn.commit()
    except Exception as e:
        print(f"Failed to obtain NXDOMAIN domains: {e}")
        conn.rollback()
    finally:
        cursor.close()
    return nxdomain_domains

def get_norobots_domains():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT Domain FROM RawDomains WHERE Robots = '1'")
        norobots_domains = [row[0].strip() for row in cursor.fetchall() if row[0].strip()]
        conn.commit()
    except Exception as e:
        print(f"Failed to obtain NoRobots domains: {e}")
        conn.rollback()
    finally:
        cursor.close()
    return norobots_domains

def check_and_record_domains(domain_list, ignored_domains, failed_domains, user_choice, junk_domains, bad_tlds, domain_endings, httpx_client, nxdomain_domains, norobots_domains, iftas_domains):
    for index, domain in enumerate(domain_list, start=1):
        print_colored(f'Crawling @ {domain} ({index}/{len(domain_list)})', 'bold')

        if should_skip_domain(domain, ignored_domains, failed_domains, nxdomain_domains, norobots_domains, user_choice):
            continue

        if is_junk_or_bad_tld(domain, junk_domains, bad_tlds, domain_endings):
            continue

        if is_iftas_domain(domain, iftas_domains):
            continue

        try:
            process_domain(domain, httpx_client)
        except Exception as e:
            handle_http_exception(domain, e)

def should_skip_domain(domain, ignored_domains, failed_domains, nxdomain_domains, norobots_domains, user_choice):
    if user_choice != "6" and domain in ignored_domains:
        print_colored('Previously ignored!', 'cyan')
        delete_domain_if_known(domain)
        return True
    if user_choice != "7" and domain in failed_domains:
        print_colored('Previously failed!', 'cyan')
        delete_domain_if_known(domain)
        return True
    if user_choice != "8" and domain in nxdomain_domains:
        print_colored('Previously NXDOMAIN!', 'cyan')
        delete_domain_if_known(domain)
        return True
    if user_choice != "9" and domain in norobots_domains:
        print_colored('Previously NoRobots!', 'cyan')
        delete_domain_if_known(domain)
        return True
    return False

def is_junk_or_bad_tld(domain, junk_domains, bad_tlds, domain_endings):
    if any(junk in domain for junk in junk_domains):
        print_colored('Known junk domain, purging!', 'magenta')
        # mark_failed_domain(domain)
        delete_domain_if_known(domain)
        delete_domain_from_raw(domain)
        return True
    if any(domain.endswith(f'.{tld}') for tld in bad_tlds):
        print_colored('Prohibited TLD, marking as NXDOMAIN!', 'red')
        mark_nxdomain_domain(domain)
        delete_domain_if_known(domain)
        delete_domain_from_raw(domain)
        return True
    if not any(domain.endswith(f'.{domain_ending}') for domain_ending in domain_endings):
        print_colored('Unknown TLD, marking as NXDOMAIN!', 'red')
        mark_nxdomain_domain(domain)
        delete_domain_if_known(domain)
        delete_domain_from_raw(domain)
        return True
    return False

def is_iftas_domain(domain, iftas_domains):
    if any(domain.endswith(f'{dni}') for dni in iftas_domains):
        print_colored('Known IFTAS DNI domain, marking as NXDOMAIN!', 'red')
        mark_nxdomain_domain(domain)
        delete_domain_if_known(domain)
        return True
    return False

def process_domain(domain, httpx_client):
    if has_emoji_or_special_chars(domain):
        print_colored('Domain contains special characters, marking as NXDOMAIN!', 'red')
        mark_nxdomain_domain(domain)
        delete_domain_if_known(domain)
        return

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
                delete_if_error_max(domain)
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
                        print_colored('Crawling is prohibited by robots.txt, marking as NoRobots!', 'red')
                        mark_norobots_domain(domain)
                        delete_domain_if_known(domain)
                        return False
        # Check for specific HTTP status codes
        elif response.status_code in [202]:
            if 'sgcaptcha' in response.text:
                print_colored('Responded with CAPTCHA to robots.txt request, marking as NoRobots!', 'red')
                mark_norobots_domain(domain)
                delete_domain_if_known(domain)
                return False
        elif response.status_code in [410]:
            print_colored(f'Responded HTTP {response.status_code} to robots.txt request, marking as NoRobots!', 'red')
            mark_norobots_domain(domain)
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
        content_type = response.headers.get('Content-Type', '')
        content_length = response.headers.get('Content-Length', '')
        if response.status_code in [200]:
            if 'json' not in content_type:
                print(f'WebFinger reply is not a JSON file, attempting HostMeta lookup…')
                hostmeta_result = check_hostmeta(domain, httpx_client)
                if hostmeta_result:
                    backend_domain = hostmeta_result['backend_domain']
                    return {'backend_domain': backend_domain}
                else:
                    return None
            if not response.content:
                print(f'WebFinger reply is empty, attempting HostMeta lookup…')
                hostmeta_result = check_hostmeta(domain, httpx_client)
                if hostmeta_result:
                    backend_domain = hostmeta_result['backend_domain']
                    return {'backend_domain': backend_domain}
                else:
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
                # Check for specific HTTP status codes
            else:
                print(f'WebFinger reply does not contain a valid alias, attempting HostMeta lookup…')
                hostmeta_result = check_hostmeta(domain, httpx_client)
                if hostmeta_result:
                    backend_domain = hostmeta_result['backend_domain']
                    return {'backend_domain': backend_domain}
                else:
                    return None
        elif response.status_code in [202]:
            if 'sgcaptcha' in response.text:
                print_colored('Responded with CAPTCHA to Webfinger request, marking as failed!', 'pink')
                mark_failed_domain(domain)
                delete_domain_if_known(domain)
                return False
        elif response.status_code in http_codes_to_fail:
            if 'json' in content_type:
                mark_as_non_mastodon(domain)
                return None
            else:
                print(f'Responded HTTP {response.status_code} to WebFinger request, attempting HostMeta lookup…')
                hostmeta_result = check_hostmeta(domain, httpx_client)
                if hostmeta_result:
                    backend_domain = hostmeta_result['backend_domain']
                    return {'backend_domain': backend_domain}
                else:
                    return None
        else:
            error_message = f'Responded HTTP {response.status_code} to WebFinger request'
            print_colored(f'{error_message}', 'yellow')
            log_error(domain, error_message)
            increment_domain_error(domain, str(response.status_code))
            delete_if_error_max(domain)
    except httpx.RequestError as e:
        handle_http_exception(domain, e)
    except json.JSONDecodeError as e:
        handle_json_exception(domain, e)
    return None

def check_hostmeta(domain, httpx_client):
    hostmeta_url = f'https://{domain}/.well-known/host-meta'
    try:
        response = httpx_client.get(hostmeta_url)
        if response.status_code in [200]:
            content_type = response.headers.get('Content-Type', '')
            if 'xml' not in content_type:
                error_message = 'HostMeta reply is not an XML file, attempting raw NodeInfo lookup…'
                print(f'{error_message}')
                return {'backend_domain': domain}
            if 'xhtml' in content_type:
                error_message = 'HostMeta reply is an XHTML file, attempting raw NodeInfo lookup…'
                print(f'{error_message}')
                return {'backend_domain': domain}
            if not response.content:
                error_message = 'HostMeta reply is empty, attempting raw NodeInfo lookup…'
                print(f'{error_message}')
                return {'backend_domain': domain}
            else:
                content = response.content.strip()
                content = content.lower()
                parser = etree.XMLParser(recover=True)
                xmldata = etree.fromstring(content, parser=parser)
                ns = {'xrd': 'http://docs.oasis-open.org/ns/xri/xrd-1.0'}  # Namespace
                link = xmldata.find(".//xrd:link[@rel='lrdd']", namespaces=ns)
                if link is None:
                    print('Unable to find lrdd link in HostMeta, attempting raw NodeInfo lookup…')
                    return {'backend_domain': domain}
                else:
                    parsed_link = urlparse(link.get('template'))
                    backend_domain = parsed_link.netloc
                    return {'backend_domain': backend_domain}
        elif response.status_code in [202]:
            if 'sgcaptcha' in response.text:
                print_colored('Responded with CAPTCHA to HostMeta request, marking as failed!', 'pink')
                mark_failed_domain(domain)
                delete_domain_if_known(domain)
                return False
        elif response.status_code in http_codes_to_fail:
            print(f'Responded HTTP {response.status_code} to HostMeta request, attempting raw NodeInfo lookup…')
            return {'backend_domain': domain}
        else:
            error_message = f'Responded HTTP {response.status_code} to HostMeta request'
            print_colored(f'{error_message}', 'yellow')
            log_error(domain, f'{error_message}')
            increment_domain_error(domain, str(response.status_code))
            delete_if_error_max(domain)
    except httpx.RequestError as e:
        handle_http_exception(domain, e)
    except etree.XMLSyntaxError as e:
        handle_xml_exception(domain, e)

def check_nodeinfo(domain, backend_domain, httpx_client):
    nodeinfo_url = f'https://{backend_domain}/.well-known/nodeinfo'
    try:
        response = httpx_client.get(nodeinfo_url)
        if response.status_code in [200]:
            content_type = response.headers.get('Content-Type', '')
            if 'json' not in content_type:
                error_message = 'NodeInfo reply is not a JSON file, marking as failed!'
                print_colored(f'{error_message}', 'pink')
                mark_failed_domain(domain)
                delete_domain_if_known(domain)
                return None
            if not response.content:
                error_message = 'NodeInfo reply is empty'
                print_colored(f'{error_message}', 'yellow')
                log_error(domain, error_message)
                increment_domain_error(domain, 'JSON')
                delete_if_error_max(domain)
                return None
            else:
                data = response.json()
            if 'links' in data and len(data['links']) > 0:
                nodeinfo_2_url = next((link['href'] for link in data['links'] if link.get('rel') == 'http://nodeinfo.diaspora.software/ns/schema/2.0'), None)
                if nodeinfo_2_url and 'wp-json' not in nodeinfo_2_url:
                    nodeinfo_response = httpx_client.get(nodeinfo_2_url)
                    if nodeinfo_response.status_code in [200]:
                        nodeinfo_response_content_type = nodeinfo_response.headers.get('Content-Type', '')
                        if 'json' not in nodeinfo_response_content_type:
                            error_message = 'NodeInfo V2 reply is not a JSON file, marking as failed!'
                            print_colored(f'{error_message}', 'pink')
                            mark_failed_domain(domain)
                            delete_domain_if_known(domain)
                            return None
                        if not nodeinfo_response.content:
                            error_message = 'NodeInfo V2 reply is empty'
                            print_colored(f'{error_message}', 'yellow')
                            log_error(domain, error_message)
                            increment_domain_error(domain, 'JSON')
                            delete_if_error_max(domain)
                            return None
                        else:
                            return nodeinfo_response.json()
                    elif nodeinfo_response.status_code in http_codes_to_fail and response.status_code != 404:
                        print_colored(f'Responded HTTP {nodeinfo_response.status_code} @ {nodeinfo_2_url}, marking as failed!', 'pink')
                        mark_failed_domain(domain)
                        delete_domain_if_known(domain)
                    else:
                        error_message = f'Responded HTTP {nodeinfo_response.status_code} @ {nodeinfo_2_url}'
                        print_colored(f'{error_message}', 'yellow')
                        log_error(domain, f'{error_message}')
                        increment_domain_error(domain, str(nodeinfo_response.status_code))
                        delete_if_error_max(domain)
                else:
                    mark_as_non_mastodon(domain)
            else:
                mark_as_non_mastodon(domain)
        elif response.status_code in [202]:
            if 'sgcaptcha' in response.text:
                print_colored('Responded with CAPTCHA to NodeInfo request, marking as failed!', 'pink')
                mark_failed_domain(domain)
                delete_domain_if_known(domain)
                return False
        elif response.status_code in http_codes_to_fail and response.status_code != 404:
            print_colored(f'Responded HTTP {response.status_code} to NodeInfo request, marking as failed!', 'pink')
            mark_failed_domain(domain)
            delete_domain_if_known(domain)
        else:
            error_message = f'Responded HTTP {response.status_code} to NodeInfo request'
            print_colored(f'{error_message}', 'yellow')
            log_error(domain, f'{error_message}')
            increment_domain_error(domain, str(response.status_code))
            delete_if_error_max(domain)
    except httpx.RequestError as e:
        handle_http_exception(domain, e)
    except json.JSONDecodeError as e:
        handle_json_exception(domain, e)
    return None

def is_mastodon_instance(nodeinfo_data: dict) -> bool:
    """Check if the given NodeInfo response indicates a Mastodon instance."""
    if not isinstance(nodeinfo_data, dict):
        return False

    software = nodeinfo_data.get('software')
    if software is None:
        return False

    software_name = software.get('name')
    if software_name is None:
        return False

    return software_name.lower() in {'mastodon', 'hometown', 'kmyblue', 'glitchcafe'}

def process_mastodon_instance(domain, webfinger_data, nodeinfo_data, httpx_client):
    software_name = nodeinfo_data['software']['name'].lower()
    software_version_full = nodeinfo_data['software']['version']
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
                error_message = 'Instance API reply is not a JSON file, marking as failed!'
                print_colored(f'{error_message}', 'magenta')
                mark_failed_domain(domain)
                delete_domain_if_known(domain)
                return None
            if not response.content:
                error_message = 'Instance API reply is empty'
                print_colored(f'{error_message}', 'yellow')
                log_error(domain, error_message)
                increment_domain_error(domain, 'JSON')
                delete_if_error_max(domain)
                return None
            else:
                instance_api_data = response.json()

            if 'error' in instance_api_data:
                if instance_api_data['error'] == "This method requires an authenticated user":
                    print_colored('Instance API requires authentication, marking as ignored!', 'magenta')
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
                error_to_print = f'Mastodon v{software_version} but contains invalid active user counts ({active_month_users}/{total_users})'
                print_colored(error_to_print, 'dark_green')
                log_error(domain, error_to_print)
                increment_domain_error(domain, '###')
                delete_domain_if_known(domain)
                return

            # Check for invalid software versions
            if version.parse(software_version.split("-")[0]) > version.parse(version_main_branch):
                error_to_print = f'Mastodon v{software_version.split("-")[0]} is higher than main branch version v{version_main_branch}.0'
                print_colored(error_to_print, 'dark_green')
                log_error(domain, error_to_print)
                increment_domain_error(domain, '###')
                delete_domain_if_known(domain)
                return

            # Update database
            update_mastodon_domain(actual_domain, software_version, software_version_full, total_users, active_month_users, contact_account, source_url)

            clear_domain_error(domain)

            if software_version == nodeinfo_data['software']['version']:
                print_colored(f'Mastodon v{software_version}', 'green')
            else:
                print_colored(f'Mastodon v{software_version} ({nodeinfo_data["software"]["version"]})', 'green')

        elif response.status_code in http_codes_to_fail:
            print_colored(f'Responded HTTP {response.status_code} to API request, marking as failed!', 'pink')
            mark_ignore_domain(domain)
            delete_domain_if_known(domain)
        else:
            error_message = f'Responded HTTP {response.status_code} to API request'
            print_colored(f'{error_message}', 'yellow')
            log_error(domain, f'{error_message}')
            increment_domain_error(domain, str(response.status_code))
            delete_if_error_max(domain)

    except httpx.RequestError as e:
        handle_http_exception(domain, e)
    except json.JSONDecodeError as e:
        handle_json_exception(domain, e)

def update_mastodon_domain(domain, software_version, software_version_full, total_users, active_month_users, contact_account, source_url):
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
              contact_account, source_url, software_version_full))
        conn.commit()
    except Exception as e:
        print(f"Failed to update Mastodon domain data: {e}")
        conn.rollback()
    finally:
        cursor.close()

def mark_as_non_mastodon(domain):
    print_colored('Not using Mastodon, marking as ignored!', 'magenta')
    mark_ignore_domain(domain)
    delete_domain_if_known(domain)

def handle_http_exception(domain, exception):
    error_message = str(exception)
    if 'ssl' in error_message.casefold() and 'timed out' not in error_message.casefold():
        if "TLSV1_ALERT_INTERNAL_ERROR" in error_message or "TLSV1_UNRECOGNIZED_NAME" in error_message:
            print_colored('TLSv1 handshake detected, marking as failed!', 'pink')
            mark_failed_domain(domain)
            delete_domain_if_known(domain)
        elif "SSLV3_ALERT_HANDSHAKE_FAILURE" in error_message:
            print_colored('SSLv3 handshake detected, marking as failed!', 'pink')
            mark_failed_domain(domain)
            delete_domain_if_known(domain)
        elif "CERTIFICATE_VERIFY_FAILED" in error_message and 'masto.host' in domain:
            print_colored('Dead masto.host instance, marking as failed!', 'pink')
            mark_failed_domain(domain)
            delete_domain_if_known(domain)
        else:
            error_reason = 'SSL'
            print_colored(f'{error_message}', 'orange')
            log_error(domain, error_message)
            increment_domain_error(domain, error_reason)
            delete_domain_if_known(domain)
    else:
        if 'Errno 8' in error_message or 'Errno 61' in error_message:
            print_colored('DNS query did not return valid results, marking as NXDOMAIN!', 'red')
            mark_nxdomain_domain(domain)
            delete_domain_if_known(domain)
        elif 'Errno 51' in error_message:
            print_colored('Network is unreachable, marking as failed!', 'pink')
            mark_failed_domain(domain)
            delete_domain_if_known(domain)
        elif 'maximum allowed redirects' in error_message.casefold():
            print_colored('Exceeded maximum allowed redirects, marking as failed!', 'pink')
            mark_failed_domain(domain)
            delete_domain_if_known(domain)
        elif 'stream_id:7' in error_message.casefold() and 'error_code:2' in error_message.casefold():
            print_colored('Received an empty response from the server, marking as failed!', 'pink')
            mark_failed_domain(domain)
            delete_domain_if_known(domain)
        elif 'timed out' in error_message.casefold():
            error_reason = 'TIMEOUT'
            print_colored(f'HTTPX failure: {error_message}', 'orange')
            log_error(domain, error_message)
            increment_domain_error(domain, error_reason)
            delete_if_error_max(domain)
        else:
            error_reason = 'HTTP'
            print_colored(f'HTTPX failure: {error_message}', 'orange')
            log_error(domain, error_message)
            increment_domain_error(domain, error_reason)
            delete_if_error_max(domain)

def handle_json_exception(domain, exception):
    error_message = str(exception)
    error_reason = 'JSON'
    print_colored(error_message, 'orange')
    log_error(domain, error_message)
    increment_domain_error(domain, error_reason)
    delete_if_error_max(domain)

def handle_xml_exception(domain, exception):
    error_message = str(exception)
    error_reason = 'XML'
    print_colored(error_message, 'orange')
    log_error(domain, error_message)
    increment_domain_error(domain, error_reason)
    delete_if_error_max(domain)

def read_domain_list(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file]

def load_from_database(user_choice):
    query_map = {
        "1": f"SELECT Domain FROM RawDomains WHERE (Failed IS NULL OR Failed = '' OR Failed = '0') AND (Ignore IS NULL OR Ignore = '' OR Ignore = '0') AND (NXDOMAIN IS NULL OR NXDOMAIN = '' OR NXDOMAIN = '0') AND (Robots IS NULL OR Robots = '' OR Robots = '0') AND (Errors <= {error_threshold} OR Errors IS NULL) ORDER BY Domain ASC",
        "4": f"SELECT Domain FROM RawDomains WHERE Errors >= {error_threshold + 1} ORDER BY LENGTH(DOMAIN) ASC",
        "5": f"SELECT Domain FROM RawDomains WHERE Errors <= {error_threshold} ORDER BY LENGTH(DOMAIN) ASC",
        "6": "SELECT Domain FROM RawDomains WHERE Ignore = '1' ORDER BY Domain",
        "7": "SELECT Domain FROM RawDomains WHERE Failed = '1' ORDER BY Domain",
        "8": "SELECT Domain FROM RawDomains WHERE NXDOMAIN = '1' ORDER BY Domain",
        "9": "SELECT Domain FROM RawDomains WHERE Robots = '1' ORDER BY Domain",
        "10": "SELECT Domain FROM RawDomains WHERE Reason = 'SSL' ORDER BY Errors ASC",
        "11": "SELECT Domain FROM RawDomains WHERE Reason = 'HTTP' ORDER BY Errors ASC",
        "12": "SELECT Domain FROM RawDomains WHERE Reason = 'TIMEOUT' ORDER BY Errors ASC",
        "20": "SELECT Domain FROM RawDomains WHERE Reason GLOB '[2][0-9][0-9]*' ORDER BY Errors ASC",
        "21": "SELECT Domain FROM RawDomains WHERE Reason GLOB '[3][0-9][0-9]*' ORDER BY Errors ASC",
        "22": "SELECT Domain FROM RawDomains WHERE Reason GLOB '[4][0-9][0-9]*' ORDER BY Errors ASC",
        "23": "SELECT Domain FROM RawDomains WHERE Reason GLOB '[5][0-9][0-9]*' ORDER BY Errors ASC",
        "30": "SELECT Domain FROM RawDomains WHERE Reason = '###' ORDER BY Errors ASC",
        "31": "SELECT Domain FROM RawDomains WHERE Reason = 'JSON' ORDER BY Errors ASC",
        "32": "SELECT Domain FROM RawDomains WHERE Reason = 'TXT' ORDER BY Errors ASC",
        "33": "SELECT Domain FROM RawDomains WHERE Reason = 'XML' ORDER BY Errors ASC",
        "40": f"SELECT Domain FROM MastodonDomains WHERE Timestamp <= datetime('now', '-{error_threshold} days') ORDER BY Timestamp DESC",
        "41": f"SELECT Domain FROM MastodonDomains WHERE \"Software Version\" NOT LIKE '{version_main_branch}%' AND \"Software Version\" NOT LIKE '{version_latest_release}' ORDER BY \"Total Users\" DESC",
        "42": f"SELECT Domain FROM MastodonDomains WHERE \"Software Version\" LIKE '{version_main_branch}%' ORDER BY \"Total Users\" DESC",
        "43": f"SELECT Domain FROM MastodonDomains WHERE \"Active Users (Monthly)\" = '0' ORDER BY \"Total Users\" DESC",
        "44": f"SELECT Domain FROM MastodonDomains ORDER BY \"Total Users\" DESC",
    }

    if user_choice in ["2", "3"]: # Reverse or Random
        query = query_map["1"]  # Default query
    else:
        query = query_map.get(user_choice)

    if not query:
        print_colored(f"Choice {user_choice} was not available, using default query…", "yellow")
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

def print_menu() -> None:
    menu_options = {
        "Change process direction": {"1": "Standard", "2": "Reverse", "3": "Random"},
        "Retry general errors": {"4": f"Errors ≥{error_threshold + 1}", "5": f"Errors ≤{error_threshold}"},
        "Retry fatal errors": {"6": "Not Mastodon", "7": "Failed", "8": "NXDOMAIN", "9": "NoRobots"},
        "Retry connection errors": {"10": "SSL", "11": "HTTP", "12": "TIMEOUT"},
        "Retry HTTP errors": {"20": "2xx", "21": "3xx", "22": "4xx", "23": "5xx"},
        "Retry specific errors": {"30": "###", "31": "JSON", "32": "TXT", "33": "XML"},
        "Retry good data": {"40": f"Stale ≥{error_threshold}", "41": "Outdated", "42": "Main", "43": "Inactive", "44": "All Good"},
    }

    for category, options in menu_options.items():
        options_str = " ".join(f"({key}) {value}" for key, value in options.items())
        print_colored(f"{category}: ", "bold", end="")
        print_colored(options_str, "")  # Print options without bold
    print_colored("Enter your choice (1, 2, 3, etc):", "bold", end=" ")
    sys.stdout.flush()

def get_user_choice() -> str:
    ready, _, _ = select.select([sys.stdin], [], [], 10)
    if ready:
        return sys.stdin.readline().strip()
    print_colored("\nAutomatically loading to random crawl", "cyan")
    return "1"

# Main program starts here
print_colored(f"{appname} v{appversion} ({current_filename})", "bold")
try:
    domain_list_file = sys.argv[1] if len(sys.argv) > 1 else None
    try:
        if domain_list_file:  # File name provided as argument
            user_choice = 1
            domain_list = load_from_file(domain_list_file)
            print("Crawling domains from file…")
        else:  # Load from database by default
            print_menu()
            user_choice = get_user_choice()
            print_colored(f"Crawling domains from database choice {user_choice}…", "pink")
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
    domain_endings = get_domain_endings()
    failed_domains = get_failed_domains()
    ignored_domains = get_ignored_domains()
    nxdomain_domains = get_nxdomain_domains()
    norobots_domains = get_norobots_domains()
    iftas_domains = get_iftas_dni()

    check_and_record_domains(domain_list, ignored_domains, failed_domains, user_choice, junk_domains, bad_tlds, domain_endings, http_client, nxdomain_domains, norobots_domains, iftas_domains)
except KeyboardInterrupt:
    conn.close()
    http_client.close()  # Close the httpx client
    print_colored(f"\n{appname} interrupted by user", "bold")
finally:
    print("Crawling complete!")