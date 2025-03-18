#!/usr/bin/env python3

# Import common modules
from common import *
# Import additional modules
try:
    import json
    import mimetypes
    import unicodedata
    from datetime import datetime, timedelta, timezone
    from lxml import etree
    from urllib.parse import urlparse, urlunparse
except ImportError as e:
    print(f"Error importing module: {e}")
    sys.exit(1)

# Detect the current filename
current_filename = os.path.basename(__file__)

parser = argparse.ArgumentParser(description="Crawl version information from Mastodon instances.")
parser.add_argument('-f', '--file', type=str, help='bypass database and use a file instead (ex: ~/domains.txt)')
parser.add_argument('-r', '--new', action='store_true', help='only process new domains added to the database (same as menu item 0)')
parser.add_argument('-d', '--buffer', action='store_true', help='only process domains which recently reached the error threshold (same as menu item 52)')
parser.add_argument('-t', '--target', type=str, help='target only a specific domain and ignore the database (ex: vmst.io)')

args = parser.parse_args()

if args.file and args.target:
    print_colored("You cannot set both file and target arguments", "red")
    sys.exit(1)

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
        except Exception:
            return True
    try:
        for char in domain:
            if (unicodedata.category(char) in ['So', 'Cf'] or ord(char) >= 0x1F300):
                return True
            if not (char.isalnum() or char in '-_.'):
                return True
    except Exception:
        return True
    return False

def log_error(domain, error_to_print):
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO error_log (domain, error)
            VALUES (%s, %s)
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
        cursor.execute('SELECT errors FROM raw_domains WHERE domain = %s', (domain,))
        result = cursor.fetchone()
        if result:
            current_errors = result[0] if result[0] is not None else 0
            new_errors = current_errors + 1
        else:
            # If the domain is not found, initialize errors count to 1
            new_errors = 1

        # Insert or update the domain with the new errors count
        cursor.execute('''
            INSERT INTO raw_domains (domain, failed, ignore, errors, reason, nxdomain, norobots)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT(domain) DO UPDATE SET
            failed = excluded.failed,
            ignore = excluded.ignore,
            errors = excluded.errors,
            reason = excluded.reason,
            nxdomain = excluded.nxdomain,
            norobots = excluded.norobots
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
        cursor.execute('SELECT errors FROM raw_domains WHERE domain = %s', (domain,))
        result = cursor.fetchone()
        if result and result[0] >= error_threshold:
            cursor.execute('SELECT timestamp FROM mastodon_domains WHERE domain = %s', (domain,))
            timestamp = cursor.fetchone()
            if timestamp and (datetime.now(timezone.utc) - timestamp[0].replace(tzinfo=timezone.utc)).days >= error_threshold:
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
            INSERT INTO raw_domains (domain, failed, ignore, errors, reason, nxdomain, norobots)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT(domain) DO UPDATE SET
            failed = excluded.failed,
            ignore = excluded.ignore,
            errors = excluded.errors,
            reason = excluded.reason,
            nxdomain = excluded.nxdomain,
            norobots = excluded.norobots
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
            INSERT INTO raw_domains (domain, failed, ignore, errors, reason, nxdomain, norobots)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT(domain) DO UPDATE SET
            failed = excluded.failed,
            ignore = excluded.ignore,
            errors = excluded.errors,
            reason = excluded.reason,
            nxdomain = excluded.nxdomain,
            norobots = excluded.norobots
        ''', (domain, None, True, None, None, None, None))
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
            INSERT INTO raw_domains (domain, failed, ignore, errors, reason, nxdomain, norobots)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT(domain) DO UPDATE SET
            failed = excluded.failed,
            ignore = excluded.ignore,
            errors = excluded.errors,
            reason = excluded.reason,
            nxdomain = excluded.nxdomain,
            norobots = excluded.norobots
        ''', (domain, True, None, None, None, None, None))
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
            INSERT INTO raw_domains (domain, failed, ignore, errors, reason, nxdomain, norobots)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT(domain) DO UPDATE SET
            failed = excluded.failed,
            ignore = excluded.ignore,
            errors = excluded.errors,
            reason = excluded.reason,
            nxdomain = excluded.nxdomain,
            norobots = excluded.norobots
        ''', (domain, None, None, None, None, True, None))
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
            INSERT INTO raw_domains (domain, failed, ignore, errors, reason, nxdomain, norobots)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT(domain) DO UPDATE SET
            failed = excluded.failed,
            ignore = excluded.ignore,
            errors = excluded.errors,
            reason = excluded.reason,
            nxdomain = excluded.nxdomain,
            norobots = excluded.norobots
        ''', (domain, None, None, None, None, None, True))
        conn.commit()
    except Exception as e:
        print(f"Failed to mark domain NoRobots: {e}")
        conn.rollback()
    finally:
        cursor.close()

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
            DELETE FROM mastodon_domains WHERE domain = %s
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
            DELETE FROM raw_domains WHERE domain = %s
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
    software_version = clean_version_main_missing_prerelease(software_version)
    software_version = clean_version_release_with_prerelease(software_version)
    return software_version

def clean_version_dumbstring(software_version):
    # List of unwanted strings from versions to filter out
    unwanted_strings = ["-pre", "-theconnector"]

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

        for version, start_date, end_date in nightly_version_ranges:
            if start_date <= nightly_date <= end_date:
                return version

    return software_version

def clean_version_main_missing_prerelease(software_version):
    if software_version.startswith(version_main_branch) and "-" not in software_version:
        software_version = f"{software_version}-alpha.1"
    return software_version

def clean_version_release_with_prerelease(software_version):
    if version_latest_release and software_version.startswith(version_latest_release) and "-" in software_version and not version_latest_release.endswith('.0'):
        software_version = software_version.split('-')[0]
    return software_version

def get_junk_keywords():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT keywords FROM junk_words")
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
        cursor.execute("SELECT tld FROM bad_tld")
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
        cursor.execute("SELECT domain FROM raw_domains WHERE failed = TRUE")
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
        cursor.execute("SELECT domain FROM raw_domains WHERE ignore = TRUE")
        ignored_domains = [row[0].strip() for row in cursor.fetchall() if row[0].strip()]
        conn.commit()
    except Exception as e:
        print(f"Failed to obtain ignored domains: {e}")
        conn.rollback()
    finally:
        cursor.close()
    return ignored_domains

def get_baddata_domains():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT domain FROM raw_domains WHERE baddata = TRUE")
        baddata_domains = [row[0].strip() for row in cursor.fetchall() if row[0].strip()]
        conn.commit()
    except Exception as e:
        print(f"Failed to obtain baddata domains: {e}")
        conn.rollback()
    finally:
        cursor.close()
    return baddata_domains

def get_nxdomain_domains():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT domain FROM raw_domains WHERE nxdomain = TRUE")
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
        cursor.execute("SELECT domain FROM raw_domains WHERE norobots = TRUE")
        norobots_domains = [row[0].strip() for row in cursor.fetchall() if row[0].strip()]
        conn.commit()
    except Exception as e:
        print(f"Failed to obtain NoRobots domains: {e}")
        conn.rollback()
    finally:
        cursor.close()
    return norobots_domains

def check_and_record_domains(domain_list, ignored_domains, baddata_domains, failed_domains, user_choice, junk_domains, bad_tlds, domain_endings, http_client, nxdomain_domains, norobots_domains, iftas_domains):
    for index, domain in enumerate(domain_list, start=1):
        print_colored(f'Crawling @ {domain} ({index}/{len(domain_list)})', 'bold')

        if should_skip_domain(domain, ignored_domains, baddata_domains, failed_domains, nxdomain_domains, norobots_domains, user_choice):
            continue

        if is_junk_or_bad_tld(domain, junk_domains, bad_tlds, domain_endings):
            continue

        if is_iftas_domain(domain, iftas_domains):
            continue

        try:
            process_domain(domain, http_client)
        except Exception as e:
            handle_http_exception(domain, e)

def should_skip_domain(domain, ignored_domains, baddata_domains, failed_domains, nxdomain_domains, norobots_domains, user_choice):
    if user_choice != "6" and domain in ignored_domains:
        print_colored('Previously IGNORED', 'cyan')
        delete_domain_if_known(domain)
        return True
    if user_choice != "7" and domain in failed_domains:
        print_colored('Previously FAILED', 'cyan')
        delete_domain_if_known(domain)
        return True
    if user_choice != "8" and domain in nxdomain_domains:
        print_colored('Previously NXDOMAIN', 'cyan')
        delete_domain_if_known(domain)
        return True
    if user_choice != "9" and domain in norobots_domains:
        print_colored('Previously NOROBOTS', 'cyan')
        delete_domain_if_known(domain)
        return True
    if domain in baddata_domains:
        print_colored('Previous BADDATA', 'cyan')
        delete_domain_if_known(domain)
        return True
    return False

def is_junk_or_bad_tld(domain, junk_domains, bad_tlds, domain_endings):
    if any(junk in domain for junk in junk_domains):
        print_colored('Purging known junk domain', 'red')
        # mark_failed_domain(domain)
        delete_domain_if_known(domain)
        delete_domain_from_raw(domain)
        return True
    if any(domain.endswith(f'.{tld}') for tld in bad_tlds):
        print_colored('Purging prohibited TLD', 'red')
        mark_nxdomain_domain(domain)
        delete_domain_if_known(domain)
        delete_domain_from_raw(domain)
        return True
    if not any(domain.endswith(f'.{domain_ending}') for domain_ending in domain_endings):
        print_colored('Purging unknown TLD', 'red')
        mark_nxdomain_domain(domain)
        delete_domain_if_known(domain)
        delete_domain_from_raw(domain)
        return True
    return False

def is_iftas_domain(domain, iftas_domains):
    if any(domain.endswith(f'{dni}') for dni in iftas_domains):
        print_colored('Known IFTAS DNI domain', 'red')
        mark_nxdomain_domain(domain)
        delete_domain_if_known(domain)
        return True
    return False

def process_domain(domain, http_client):
    if has_emoji_or_special_chars(domain):
        print_colored('Domain contains special characters', 'red')
        mark_nxdomain_domain(domain)
        delete_domain_if_known(domain)
        return

    if not check_robots_txt(domain, http_client):
        return  # Stop processing this domain

    webfinger_data = check_webfinger(domain, http_client)
    if not webfinger_data:
        return

    nodeinfo_data = check_nodeinfo(domain, webfinger_data['backend_domain'], http_client)
    if not nodeinfo_data:
        return

    if is_mastodon_instance(nodeinfo_data):
        process_mastodon_instance(domain, webfinger_data, nodeinfo_data, http_client)
    else:
        mark_as_non_mastodon(domain)

def check_robots_txt(domain, http_client):
    robots_url = f'https://{domain}/robots.txt'
    try:
        response = http_client.get(robots_url)
        # Check for valid HTTP status code
        if response.status_code in [200]:
            content_type = response.headers.get('Content-Type', '')
            if content_type in mimetypes.types_map.values() and not content_type.startswith('text/'):
                error_message = 'robots.txt is not a text file'
                print_colored(f'{error_message}', 'magenta')
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
                        print_colored('Crawling prohibited by robots.txt', 'red')
                        mark_norobots_domain(domain)
                        delete_domain_if_known(domain)
                        return False
        # Check for specific HTTP status codes
        elif response.status_code in http_codes_to_hardfail:
            print_colored(f'Responded HTTP {response.status_code} to robots.txt request', 'red')
            mark_nxdomain_domain(domain)
            delete_domain_if_known(domain)
            return False
    except httpx.RequestError as e:
        handle_http_exception(domain, e)
        return False
    return True

def check_webfinger(domain, http_client):
    webfinger_url = f'https://{domain}/.well-known/webfinger?resource=acct:{domain}@{domain}'
    try:
        response = http_client.get(webfinger_url)
        content_type = response.headers.get('Content-Type', '')
        content_length = response.headers.get('Content-Length', '')
        if response.status_code in [200]:
            if 'json' not in content_type:
                print('WebFinger reply is not a JSON file…')
                hostmeta_result = check_hostmeta(domain, http_client)
                if hostmeta_result:
                    backend_domain = hostmeta_result['backend_domain']
                    return {'backend_domain': backend_domain}
                else:
                    return None
            if not response.content:
                print('WebFinger reply is empty…')
                hostmeta_result = check_hostmeta(domain, http_client)
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
                print('WebFinger reply does not contain a valid alias…')
                hostmeta_result = check_hostmeta(domain, http_client)
                if hostmeta_result:
                    backend_domain = hostmeta_result['backend_domain']
                    return {'backend_domain': backend_domain}
                else:
                    return None
        elif response.status_code in http_codes_to_hardfail:
            print_colored(f'Responded HTTP {response.status_code} to Webfinger request', 'red')
            mark_failed_domain(domain)
            delete_domain_if_known(domain)
            return False
        elif response.status_code in http_codes_to_softfail:
            if 'json' in content_type:
                mark_as_non_mastodon(domain)
                return None
            else:
                print(f'Responded HTTP {response.status_code} to WebFinger request…')
                hostmeta_result = check_hostmeta(domain, http_client)
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

def check_hostmeta(domain, http_client):
    hostmeta_url = f'https://{domain}/.well-known/host-meta'
    try:
        response = http_client.get(hostmeta_url)
        if response.status_code in [200]:
            content_type = response.headers.get('Content-Type', '')
            if 'xml' not in content_type:
                error_message = 'HostMeta reply is not an XML file…'
                print(f'{error_message}')
                return {'backend_domain': domain}
            if 'xhtml' in content_type:
                error_message = 'HostMeta reply is an XHTML file…'
                print(f'{error_message}')
                return {'backend_domain': domain}
            if not response.content:
                error_message = 'HostMeta reply is empty…'
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
                    print('Unable to find lrdd link in HostMeta…')
                    return {'backend_domain': domain}
                else:
                    parsed_link = urlparse(link.get('template'))
                    backend_domain = parsed_link.netloc
                    return {'backend_domain': backend_domain}
        elif response.status_code in http_codes_to_hardfail:
            print_colored(f'Responded HTTP {response.status_code} to HostMeta request', 'red')
            mark_failed_domain(domain)
            delete_domain_if_known(domain)
            return False
        elif response.status_code in http_codes_to_softfail:
            print(f'Responded HTTP {response.status_code} to HostMeta request…')
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

def check_nodeinfo(domain, backend_domain, http_client):
    nodeinfo_url = f'https://{backend_domain}/.well-known/nodeinfo'
    try:
        response = http_client.get(nodeinfo_url)
        if response.status_code in [200]:
            content_type = response.headers.get('Content-Type', '')
            if 'json' not in content_type:
                error_message = 'NodeInfo reply is not a JSON file'
                print_colored(f'{error_message}', 'magenta')
                log_error(domain, error_message)
                increment_domain_error(domain, 'JSON')
                delete_if_error_max(domain)
                return None
            if not response.content:
                error_message = 'NodeInfo reply is empty'
                print_colored(f'{error_message}', 'magenta')
                log_error(domain, error_message)
                increment_domain_error(domain, 'JSON')
                delete_if_error_max(domain)
                return None
            else:
                data = response.json()
            if 'links' in data and len(data['links']) > 0:
                nodeinfo_2_url = next((link['href'] for link in data['links'] if link.get('rel') == 'http://nodeinfo.diaspora.software/ns/schema/2.0'), None)
                if nodeinfo_2_url and 'wp-json' not in nodeinfo_2_url:
                    nodeinfo_response = http_client.get(nodeinfo_2_url)
                    if nodeinfo_response.status_code in [200]:
                        nodeinfo_response_content_type = nodeinfo_response.headers.get('Content-Type', '')
                        if 'json' not in nodeinfo_response_content_type:
                            error_message = 'NodeInfo V2 reply is not a JSON file'
                            print_colored(f'{error_message}', 'magenta')
                            log_error(domain, error_message)
                            increment_domain_error(domain, 'JSON')
                            delete_if_error_max(domain)
                            return None
                        if not nodeinfo_response.content:
                            error_message = 'NodeInfo V2 reply is empty'
                            print_colored(f'{error_message}', 'magenta')
                            log_error(domain, error_message)
                            increment_domain_error(domain, 'JSON')
                            delete_if_error_max(domain)
                            return None
                        else:
                            return nodeinfo_response.json()
                    elif nodeinfo_response.status_code in http_codes_to_hardfail:
                        print_colored(f'Responded HTTP {response.status_code} to NodeInfo request', 'red')
                        mark_failed_domain(domain)
                        delete_domain_if_known(domain)
                        return False
                    else:
                        error_message = f'Responded HTTP {nodeinfo_response.status_code} to NodeInfo request'
                        print_colored(f'{error_message}', 'yellow')
                        log_error(domain, f'{error_message}')
                        increment_domain_error(domain, str(nodeinfo_response.status_code))
                        delete_if_error_max(domain)
                else:
                    mark_as_non_mastodon(domain)
            else:
                mark_as_non_mastodon(domain)
        elif response.status_code in http_codes_to_hardfail:
            print_colored(f'Responded HTTP {response.status_code} to NodeInfo request', 'red')
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

def process_mastodon_instance(domain, webfinger_data, nodeinfo_data, http_client):
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
        response = http_client.get(instance_api_url)
        if response.status_code in [200]:
            content_type = response.headers.get('Content-Type', '')
            if 'json' not in content_type:
                error_message = 'Instance API reply is not a JSON file'
                print_colored(f'{error_message}', 'magenta')
                log_error(domain, error_message)
                increment_domain_error(domain, 'API')
                delete_if_error_max(domain)
                return None
            if not response.content:
                error_message = 'Instance API reply is empty'
                print_colored(f'{error_message}', 'magenta')
                log_error(domain, error_message)
                increment_domain_error(domain, 'API')
                delete_if_error_max(domain)
                return None
            else:
                instance_api_data = response.json()

            if 'error' in instance_api_data:
                if instance_api_data['error'] == "This method requires an authenticated user":
                    error_message = 'Instance API requires authentication'
                    print_colored(f'{error_message}', 'magenta')
                    log_error(domain, error_message)
                    increment_domain_error(domain, 'API')
                    delete_if_error_max(domain)
                    return None

            if software_version.startswith("4"):
                actual_domain = instance_api_data['domain'].lower()
                contact_account = normalize_email(instance_api_data['contact']['email']).lower()
                source_url = instance_api_data['source_url']
            else:
                actual_domain = instance_api_data['uri'].lower()
                contact_account = normalize_email(instance_api_data['email']).lower()
                source_url = ''

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
                print_colored(error_to_print, 'magenta')
                log_error(domain, error_to_print)
                increment_domain_error(domain, '###')
                delete_domain_if_known(domain)
                return

            # Check for invalid software versions
            if version.parse(software_version.split("-")[0]) > version.parse(version_main_branch):
                error_to_print = f'Mastodon v{software_version.split("-")[0]} is higher than main branch version v{version_main_branch}.0'
                print_colored(error_to_print, 'magenta')
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
            INSERT INTO mastodon_domains
            (domain, software_version, total_users, active_users_monthly, timestamp, contact, source, full_version)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT(domain) DO UPDATE SET
            software_version = excluded.software_version,
            total_users = excluded.total_users,
            active_users_monthly = excluded.active_users_monthly,
            timestamp = excluded.timestamp,
            contact = excluded.contact,
            source = excluded.source,
            full_version = excluded.full_version
        ''', (domain, software_version, total_users, active_month_users,
              datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
              contact_account, source_url, software_version_full))
        conn.commit()
    except Exception as e:
        print(f"Failed to update Mastodon domain data: {e}")
        conn.rollback()
    finally:
        cursor.close()

def mark_as_non_mastodon(domain):
    print_colored('Not using Mastodon', 'red')
    mark_ignore_domain(domain)
    delete_domain_if_known(domain)

def handle_http_exception(domain, exception):
    error_message = str(exception)
    if '_ssl.c' in error_message.casefold():
        error_reason = 'SSL'
        print_colored(f'{error_message}', 'orange')
        log_error(domain, error_message)
        increment_domain_error(domain, error_reason)
        delete_if_error_max(domain)
    elif 'maximum allowed redirects' in error_message.casefold():
        error_reason = 'MAX'
        print_colored(f'HTTPX failure: {error_message}', 'orange')
        log_error(domain, error_message)
        increment_domain_error(domain, error_reason)
        delete_if_error_max(domain)
    elif 'timed out' in error_message.casefold():
        error_reason = 'TIME'
        print_colored(f'HTTPX failure: {error_message}', 'orange')
        log_error(domain, error_message)
        increment_domain_error(domain, error_reason)
        delete_if_error_max(domain)
    elif 'nodename nor servname provided' in error_message.casefold() or 'name or service not known' in error_message.casefold() or 'no address associated with hostname' in error_message.casefold() or 'temporary failure in name resolution' in error_message.casefold():
        error_reason = 'DNS'
        print_colored(f'DNS failure: {error_message}', 'orange')
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
    print_colored(error_message, 'magenta')
    log_error(domain, error_message)
    increment_domain_error(domain, error_reason)
    delete_if_error_max(domain)

def handle_xml_exception(domain, exception):
    error_message = str(exception)
    error_reason = 'XML'
    print_colored(error_message, 'magenta')
    log_error(domain, error_message)
    increment_domain_error(domain, error_reason)
    delete_if_error_max(domain)

def read_domain_list(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file]

def load_from_database(user_choice):
    # PostgreSQL uses SIMILAR TO instead of GLOB, and different timestamp functions
    query_map = {
        "0": "SELECT domain FROM raw_domains WHERE errors = 0 ORDER BY LENGTH(DOMAIN) ASC",
        "1": f"SELECT domain FROM raw_domains WHERE (failed IS NULL OR failed = FALSE) AND (ignore IS NULL OR ignore = FALSE) AND (nxdomain IS NULL OR nxdomain = FALSE) AND (norobots IS NULL OR norobots = FALSE) AND (baddata IS NULL OR baddata = FALSE) AND (errors <= %s OR errors IS NULL) ORDER BY domain ASC",
        "6": "SELECT domain FROM raw_domains WHERE ignore = TRUE ORDER BY domain",
        "7": "SELECT domain FROM raw_domains WHERE failed = TRUE ORDER BY domain",
        "8": "SELECT domain FROM raw_domains WHERE nxdomain = TRUE ORDER BY domain",
        "9": "SELECT domain FROM raw_domains WHERE norobots = TRUE ORDER BY domain",
        "10": "SELECT domain FROM raw_domains WHERE reason = 'SSL' ORDER BY errors ASC",
        "11": "SELECT domain FROM raw_domains WHERE reason = 'HTTP' ORDER BY errors ASC",
        "12": "SELECT domain FROM raw_domains WHERE reason IN ('TIMEOUT', 'TIME') ORDER BY errors ASC",
        "13": "SELECT domain FROM raw_domains WHERE reason = 'MAX' ORDER BY errors ASC",
        "14": "SELECT domain FROM raw_domains WHERE reason = 'DNS' ORDER BY errors ASC",
        "20": "SELECT domain FROM raw_domains WHERE reason ~ '^2[0-9]{2}' ORDER BY errors ASC",
        "21": "SELECT domain FROM raw_domains WHERE reason ~ '^3[0-9]{2}' ORDER BY errors ASC",
        "22": "SELECT domain FROM raw_domains WHERE reason ~ '^4[0-9]{2}' ORDER BY errors ASC",
        "23": "SELECT domain FROM raw_domains WHERE reason ~ '^5[0-9]{2}' ORDER BY errors ASC",
        "30": "SELECT domain FROM raw_domains WHERE reason = '###' ORDER BY errors ASC",
        "31": "SELECT domain FROM raw_domains WHERE reason = 'JSON' ORDER BY errors ASC",
        "32": "SELECT domain FROM raw_domains WHERE reason = 'TXT' ORDER BY errors ASC",
        "33": "SELECT domain FROM raw_domains WHERE reason = 'XML' ORDER BY errors ASC",
        "34": "SELECT domain FROM raw_domains WHERE reason = 'API' ORDER BY errors ASC",
        "40": "SELECT domain FROM mastodon_domains WHERE timestamp <= (CURRENT_TIMESTAMP - INTERVAL '7 days') AT TIME ZONE 'UTC' ORDER BY timestamp ASC",
        "41": "SELECT domain FROM mastodon_domains WHERE software_version != ALL(%(versions)s::text[]) ORDER BY active_users_monthly DESC",
        "42": f"SELECT domain FROM mastodon_domains WHERE software_version LIKE %s ORDER BY active_users_monthly DESC",
        "43": "SELECT domain FROM mastodon_domains WHERE active_users_monthly = '0' ORDER BY active_users_monthly DESC",
        "44": "SELECT domain FROM mastodon_domains ORDER BY active_users_monthly DESC",
        "50": f"SELECT domain FROM raw_domains WHERE errors > %s ORDER BY errors ASC",
        "51": f"SELECT domain FROM raw_domains WHERE errors < %s ORDER BY errors ASC",
        "52": f"SELECT domain FROM raw_domains WHERE errors >= %s AND errors <= %s ORDER BY errors ASC",
    }

    if user_choice in ["2", "3"]: # Reverse or Random
        query = query_map["1"]  # Default query
        params = [error_threshold]
    else:
        query = query_map.get(user_choice)

        # Set parameters based on query type
        params = []
        if user_choice in ["1", "51"]:
            params = [error_threshold]
        elif user_choice == "52":
            params = [error_threshold, error_threshold + error_threshold]
        elif user_choice == "50":
            params = [error_threshold * 2]
        # elif user_choice == "40":
        #     params = [error_threshold]
        elif user_choice == "41":
            params = {'versions': all_patched_versions}
            print("Exclusing versions:")
            for version in params['versions']:
                print(f" - {version}")
        elif user_choice == "42":
            params = [f"{version_main_branch}%"]

    if not query:
        print_colored(f"Choice {user_choice} was not available, using default query…", "pink")
        query = query_map["1"]  # Default query
        params = [error_threshold]

    cursor = conn.cursor()
    try:
        cursor.execute(query, params if params else None) # type: ignore
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
                cursor.execute('SELECT COUNT(*) FROM raw_domains WHERE domain = %s', (domain,))
                result = cursor.fetchone()
                exists = result is not None and result[0] > 0

                # If not, insert the new domain into the database
                if not exists:
                    cursor.execute('INSERT INTO raw_domains (domain, errors) VALUES (%s, %s)', (domain, None))
                    cursor.close()
                conn.commit()
    return domain_list

def print_menu() -> None:
    menu_options = {
        "Process new domains": {"0": "Recently Fetched"},
        "Change process direction": {"1": "Standard", "2": "Reverse", "3": "Random"},
        "Retry fatal errors": {"6": "Not Mastodon", "7": "Marked Failed", "8": "Bad Domains", "9": "No Robots"},
        "Retry connection errors": {"10": "SSL", "11": "HTTP", "12": "TIME", "13": "MAX", "14": "DNS"},
        "Retry HTTP errors": {"20": "2xx", "21": "3xx", "22": "4xx", "23": "5xx"},
        "Retry specific errors": {"30": "###", "31": "JSON", "32": "TXT", "33": "XML", "34": "API"},
        "Retry good data": {"40": f"Stale ≥{error_threshold}", "41": "Unpatched", "42": "Main", "43": "Inactive", "44": "All Good"},
        "Retry general errors": {"50": f"Domains w/ >{error_threshold * 2} Errors", "51": f"Domains w/ <{error_threshold} Errors", "52": f"Domains w/ {error_threshold}-{error_threshold + error_threshold} Errors"},
    }

    for category, options in menu_options.items():
        options_str = " ".join(f"({key}) {value}" for key, value in options.items())
        print_colored(f"{category}: ", "bold", end="")
        print_colored(options_str, "")  # Print options without bold
    print_colored("Enter your choice (1, 2, 3, etc):", "bold", end=" ")
    sys.stdout.flush()

def get_user_choice() -> str:
    return sys.stdin.readline().strip()

# Main program starts here
print_colored(f"{appname} v{appversion} ({current_filename})", "bold")
if is_running_headless():
    print_colored("Running in headless mode", "pink")
else:
    print_colored("Running in interactive mode", "pink")
try:
    domain_list_file = args.file if args.file is not None else None
    single_domain_target = args.target if args.target is not None else None
    try:
        if domain_list_file:  # File name provided as argument
            user_choice = 1
            domain_list = load_from_file(domain_list_file)
            print("Crawling domains from file…")
        elif single_domain_target:  # Single domain provided as argument
            user_choice = 1
            domain_list = single_domain_target.replace(' ', '').split(',')
            print(f"Crawling domain{'s' if len(domain_list) > 1 else ''} from target…")
        else:  # Load from database by default
            if args.new:
                user_choice = "0"
            elif args.buffer:
                user_choice = "52"
            elif is_running_headless():
                user_choice = "3"  # Default to random crawl in headless mode
            else:
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
    except psycopg.Error as e:
        print(f"Database error: {e}")
        sys.exit(1)

    junk_domains = get_junk_keywords()
    bad_tlds = get_bad_tld()
    domain_endings = get_domain_endings()
    failed_domains = get_failed_domains()
    ignored_domains = get_ignored_domains()
    baddata_domains = get_baddata_domains()
    nxdomain_domains = get_nxdomain_domains()
    norobots_domains = get_norobots_domains()
    iftas_domains = get_iftas_dni()

    check_and_record_domains(domain_list, ignored_domains, baddata_domains, failed_domains, user_choice, junk_domains, bad_tlds, domain_endings, http_client, nxdomain_domains, norobots_domains, iftas_domains)

    print_colored("Crawling complete!", "bold")
except KeyboardInterrupt:
    print_colored(f"\n{appname} interrupted by user", "bold")
finally:
    conn.close()
    http_client.close()