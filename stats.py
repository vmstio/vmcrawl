#!/usr/bin/env python3

# Import common modules
from common import *
# Import additional modules

# Detect the current filename
current_filename = os.path.basename(__file__)

def get_total_raw_domains():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COUNT(domain) AS total_domains FROM raw_domains;")
        result = cursor.fetchone()
        total_raw_domains = result[0] if result is not None else 0
        conn.commit()
        return total_raw_domains
    except Exception as e:
        print(f"Failed to obtain total raw domains: {e}")
        conn.rollback()
    finally:
        cursor.close()
    return []

def get_total_failed_domains():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COUNT(domain) AS total_domains FROM raw_domains WHERE failed = True;")
        result = cursor.fetchone()
        total_raw_domains = result[0] if result is not None else 0
        conn.commit()
        return total_raw_domains
    except Exception as e:
        print(f"Failed to obtain total failed domains: {e}")
        conn.rollback()
    finally:
        cursor.close()
    return []

def get_total_mastodon_domains():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COUNT(domain) AS total_domains FROM mastodon_domains;")
        result = cursor.fetchone()
        total_raw_domains = result[0] if result is not None else 0
        conn.commit()
        return total_raw_domains
    except Exception as e:
        print(f"Failed to obtain total Mastodon domains: {e}")
        conn.rollback()
    finally:
        cursor.close()
    return []

def get_total_ignored_domains():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COUNT(domain) AS total_domains FROM raw_domains WHERE ignore = True;")
        result = cursor.fetchone()
        total_raw_domains = result[0] if result is not None else 0
        conn.commit()
        return total_raw_domains
    except Exception as e:
        print(f"Failed to obtain total non-Mastodon domains: {e}")
        conn.rollback()
    finally:
        cursor.close()
    return []

def get_total_nxdomains():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COUNT(domain) AS total_domains FROM raw_domains WHERE nxdomain = True;")
        result = cursor.fetchone()
        total_raw_domains = result[0] if result is not None else 0
        conn.commit()
        return total_raw_domains
    except Exception as e:
        print(f"Failed to obtain total nxdomain domains: {e}")
        conn.rollback()
    finally:
        cursor.close()
    return []

def get_total_norobots():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COUNT(domain) AS total_domains FROM raw_domains WHERE norobots = True;")
        result = cursor.fetchone()
        total_raw_domains = result[0] if result is not None else 0
        conn.commit()
        return total_raw_domains
    except Exception as e:
        print(f"Failed to obtain total norobots domains: {e}")
        conn.rollback()
    finally:
        cursor.close()
    return []

def get_total_baddata():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COUNT(domain) AS total_domains FROM raw_domains WHERE baddata = True;")
        result = cursor.fetchone()
        total_raw_domains = result[0] if result is not None else 0
        conn.commit()
        return total_raw_domains
    except Exception as e:
        print(f"Failed to obtain total baddata domains: {e}")
        conn.rollback()
    finally:
        cursor.close()
    return []

def get_total_error_over():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COUNT(domain) AS total_domains FROM raw_domains WHERE errors >= 8;")
        result = cursor.fetchone()
        total_raw_domains = result[0] if result is not None else 0
        conn.commit()
        return total_raw_domains
    except Exception as e:
        print(f"Failed to obtain total error over domains: {e}")
        conn.rollback()
    finally:
        cursor.close()
    return []

def get_total_error_under():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COUNT(domain) AS total_domains FROM raw_domains WHERE errors <= 7;")
        result = cursor.fetchone()
        total_raw_domains = result[0] if result is not None else 0
        conn.commit()
        return total_raw_domains
    except Exception as e:
        print(f"Failed to obtain total error under domains: {e}")
        conn.rollback()
    finally:
        cursor.close()
    return []

def get_total_users():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT SUM(total_users) AS total_users FROM mastodon_domains;")
        result = cursor.fetchone()
        total_raw_domains = result[0] if result is not None else 0
        conn.commit()
        return total_raw_domains
    except Exception as e:
        print(f"Failed to obtain total users: {e}")
        conn.rollback()
    finally:
        cursor.close()
    return []

def get_total_active_users():
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT SUM(active_users_monthly) AS total_users FROM mastodon_domains;")
        result = cursor.fetchone()
        total_raw_domains = result[0] if result is not None else 0
        conn.commit()
        return total_raw_domains
    except Exception as e:
        print(f"Failed to obtain active users: {e}")
        conn.rollback()
    finally:
        cursor.close()
    return []

if __name__ == "__main__":
    try:
        print_colored(f"{appname} v{appversion} ({current_filename})", "bold")
        if is_running_headless():
            print_colored("Running in headless mode", "pink")
        else:
            print_colored("Running in interactive mode", "pink")

        total_raw_domains = get_total_raw_domains()
        print(f"Total raw domains: {total_raw_domains}")
        total_failed_domains = get_total_failed_domains()
        print(f"Total failed (410) domains: {total_failed_domains}")
        total_mastodon_domains = get_total_mastodon_domains()
        print(f"Total Mastodon domains: {total_mastodon_domains}")
        total_ignored_domains = get_total_ignored_domains()
        print(f"Total ignored (non-Masto) domains: {total_ignored_domains}")
        total_nxdomains = get_total_nxdomains()
        print(f"Total nxdomain domains: {total_nxdomains}")
        total_norobots = get_total_norobots()
        print(f"Total crawling prohibited by robots.txt domains: {total_norobots}")
        total_baddata = get_total_baddata()
        print(f"Total baddata domains: {total_baddata}")
        total_error_over = get_total_error_over()
        print(f"Total error over domains: {total_error_over}")
        total_error_under = get_total_error_under()
        print(f"Total error under domains: {total_error_under}")
        total_users = get_total_users()
        print(f"Total users: {total_users}")
        total_active_users = get_total_active_users()
        print(f"Total active users: {total_active_users}")

    except KeyboardInterrupt:
        print_colored(f"\n{appname} interrupted by user", "bold")
    finally:
        conn.close()
        http_client.close()
