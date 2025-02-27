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


def get_total_failed_domains():
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT COUNT(domain) AS total_domains FROM raw_domains WHERE failed = True;"
        )
        result = cursor.fetchone()
        total_raw_domains = result[0] if result is not None else 0
        conn.commit()
        return total_raw_domains
    except Exception as e:
        print(f"Failed to obtain total failed domains: {e}")
        conn.rollback()
    finally:
        cursor.close()


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


def get_total_ignored_domains():
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT COUNT(domain) AS total_domains FROM raw_domains WHERE ignore = True;"
        )
        result = cursor.fetchone()
        total_raw_domains = result[0] if result is not None else 0
        conn.commit()
        return total_raw_domains
    except Exception as e:
        print(f"Failed to obtain total non-Mastodon domains: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_total_nxdomains():
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT COUNT(domain) AS total_domains FROM raw_domains WHERE nxdomain = True;"
        )
        result = cursor.fetchone()
        total_raw_domains = result[0] if result is not None else 0
        conn.commit()
        return total_raw_domains
    except Exception as e:
        print(f"Failed to obtain total nxdomain domains: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_total_norobots():
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT COUNT(domain) AS total_domains FROM raw_domains WHERE norobots = True;"
        )
        result = cursor.fetchone()
        total_raw_domains = result[0] if result is not None else 0
        conn.commit()
        return total_raw_domains
    except Exception as e:
        print(f"Failed to obtain total norobots domains: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_total_baddata():
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT COUNT(domain) AS total_domains FROM raw_domains WHERE baddata = True;"
        )
        result = cursor.fetchone()
        total_raw_domains = result[0] if result is not None else 0
        conn.commit()
        return total_raw_domains
    except Exception as e:
        print(f"Failed to obtain total baddata domains: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_total_error_over():
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT COUNT(domain) AS total_domains FROM raw_domains WHERE errors >= 8;"
        )
        result = cursor.fetchone()
        total_raw_domains = result[0] if result is not None else 0
        conn.commit()
        return total_raw_domains
    except Exception as e:
        print(f"Failed to obtain total error over domains: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_total_error_under():
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT COUNT(domain) AS total_domains FROM raw_domains WHERE errors <= 7;"
        )
        result = cursor.fetchone()
        total_raw_domains = result[0] if result is not None else 0
        conn.commit()
        return total_raw_domains
    except Exception as e:
        print(f"Failed to obtain total error under domains: {e}")
        conn.rollback()
    finally:
        cursor.close()


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


def get_total_active_users():
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT SUM(active_users_monthly) AS total_users FROM mastodon_domains;"
        )
        result = cursor.fetchone()
        total_raw_domains = result[0] if result is not None else 0
        conn.commit()
        return total_raw_domains
    except Exception as e:
        print(f"Failed to obtain active users: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_total_unique_versions():
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT COUNT(DISTINCT software_version) AS unique_software_versions FROM mastodon_domains;"
        )
        result = cursor.fetchone()
        total_raw_domains = result[0] if result is not None else 0
        conn.commit()
        return total_raw_domains
    except Exception as e:
        print(f"Failed to obtain unique versions: {e}")
        conn.rollback()
    finally:
        cursor.close()

def get_total_main__branch_instances():
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT COUNT(DISTINCT domain) as "Main Total"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT branch || '.%'
                FROM patch_versions
                WHERE n_level = -1
            );
        """
        )
        result = cursor.fetchone()
        total_raw_domains = result[0] if result is not None else 0
        conn.commit()
        return total_raw_domains
    except Exception as e:
        print(f"Failed to obtain total main instances: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_total_release_branch_instances():
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT COUNT(DISTINCT domain) as "Latest Total"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT branch || '.%'
                FROM patch_versions
                WHERE n_level = 0
            );
        """
        )
        result = cursor.fetchone()
        total_raw_domains = result[0] if result is not None else 0
        conn.commit()
        return total_raw_domains
    except Exception as e:
        print(f"Failed to obtain total latest instances: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_total_previous_branch_instances():
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT COUNT(DISTINCT domain) as "Latest Total"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT branch || '.%'
                FROM patch_versions
                WHERE n_level = 1
            );
        """
        )
        result = cursor.fetchone()
        total_raw_domains = result[0] if result is not None else 0
        conn.commit()
        return total_raw_domains
    except Exception as e:
        print(f"Failed to obtain total previous instances: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_total_pending_eol_branch_instances():
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT COUNT(DISTINCT domain) as "Latest Total"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT branch || '.%'
                FROM patch_versions
                WHERE n_level = 2
            );
        """
        )
        result = cursor.fetchone()
        total_raw_domains = result[0] if result is not None else 0
        conn.commit()
        return total_raw_domains
    except Exception as e:
        print(f"Failed to obtain total pending EOL instances: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_total_eol_branch_instances():
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT COUNT(DISTINCT mastodon_domains.domain) as "Latest Total"
            FROM mastodon_domains
            WHERE EXISTS (
                SELECT 1
                FROM eol_versions
                WHERE mastodon_domains.software_version LIKE eol_versions.software_version || '%'
            );
        """
        )
        result = cursor.fetchone()
        total_raw_domains = result[0] if result is not None else 0
        conn.commit()
        return total_raw_domains
    except Exception as e:
        print(f"Failed to obtain total EOL instances: {e}")
        conn.rollback()
    finally:
        cursor.close()

def get_total_main_patched_instances():
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT COUNT(DISTINCT domain) as "Main Patched"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT software_version
                FROM patch_versions
                WHERE main = True
            ) || '%';
        """
        )
        result = cursor.fetchone()
        total_raw_domains = result[0] if result is not None else 0
        conn.commit()
        return total_raw_domains
    except Exception as e:
        print(f"Failed to obtain main patched instances: {e}")
        conn.rollback()
    finally:
        cursor.close()

def get_total_release_patched_instances():
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT COUNT(DISTINCT domain) as "Latest Patched"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT software_version
                FROM patch_versions
                WHERE n_level = 0
            ) || '%';
        """
        )
        result = cursor.fetchone()
        total_raw_domains = result[0] if result is not None else 0
        conn.commit()
        return total_raw_domains
    except Exception as e:
        print(f"Failed to obtain release patched instances: {e}")
        conn.rollback()
    finally:
        cursor.close()

def get_total_previous_patched_instances():
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT COUNT(DISTINCT domain) as "Previous Patched"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT software_version
                FROM patch_versions
                WHERE n_level = 1
            ) || '%';
        """
        )
        result = cursor.fetchone()
        total_raw_domains = result[0] if result is not None else 0
        conn.commit()
        return total_raw_domains
    except Exception as e:
        print(f"Failed to obtain previous patched instances: {e}")
        conn.rollback()
    finally:
        cursor.close()

def get_total_pending_eol_patched_instances():
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT COUNT(DISTINCT domain) as "Pending EOL Patched"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT software_version
                FROM patch_versions
                WHERE n_level = 2
            ) || '%';
        """
        )
        result = cursor.fetchone()
        total_raw_domains = result[0] if result is not None else 0
        conn.commit()
        return total_raw_domains
    except Exception as e:
        print(f"Failed to obtain ending EOL patched instances: {e}")
        conn.rollback()
    finally:
        cursor.close()

def get_total_main_branch_users():
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT SUM(total_users) as "Main Total"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT branch || '.%'
                FROM patch_versions
                WHERE n_level = -1
            );
        """
        )
        result = cursor.fetchone()
        total_users = result[0] if result is not None else 0
        conn.commit()
        return total_users
    except Exception as e:
        print(f"Failed to obtain total main instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_total_release_branch_users():
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT SUM(total_users) as "Latest Total"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT branch || '.%'
                FROM patch_versions
                WHERE n_level = 0
            );
        """
        )
        result = cursor.fetchone()
        total_users = result[0] if result is not None else 0
        conn.commit()
        return total_users
    except Exception as e:
        print(f"Failed to obtain total latest instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_total_previous_branch_users():
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT SUM(total_users) as "Latest Total"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT branch || '.%'
                FROM patch_versions
                WHERE n_level = 1
            );
        """
        )
        result = cursor.fetchone()
        total_users = result[0] if result is not None else 0
        conn.commit()
        return total_users
    except Exception as e:
        print(f"Failed to obtain total previous instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_total_pending_eol_branch_users():
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT SUM(total_users) as "Latest Total"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT branch || '.%'
                FROM patch_versions
                WHERE n_level = 2
            );
        """
        )
        result = cursor.fetchone()
        total_users = result[0] if result is not None else 0
        conn.commit()
        return total_users
    except Exception as e:
        print(f"Failed to obtain total pending EOL instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_total_eol_branch_users():
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT SUM(mastodon_domains.total_users) as "Latest Total"
            FROM mastodon_domains
            WHERE EXISTS (
                SELECT 1
                FROM eol_versions
                WHERE mastodon_domains.software_version LIKE eol_versions.software_version || '%'
            );
        """
        )
        result = cursor.fetchone()
        total_users = result[0] if result is not None else 0
        conn.commit()
        return total_users
    except Exception as e:
        print(f"Failed to obtain total EOL instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()

def get_total_main_patched_users():
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT SUM(total_users) as "Main Patched"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT software_version
                FROM patch_versions
                WHERE main = True
            ) || '%';
        """
        )
        result = cursor.fetchone()
        total_users = result[0] if result is not None else 0
        conn.commit()
        return total_users
    except Exception as e:
        print(f"Failed to obtain main patched instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()

def get_total_release_patched_users():
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT SUM(total_users) as "Latest Patched"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT software_version
                FROM patch_versions
                WHERE n_level = 0
            ) || '%';
        """
        )
        result = cursor.fetchone()
        total_users = result[0] if result is not None else 0
        conn.commit()
        return total_users
    except Exception as e:
        print(f"Failed to obtain release patched instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()

def get_total_previous_patched_users():
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT SUM(total_users) as "Previous Patched"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT software_version
                FROM patch_versions
                WHERE n_level = 1
            ) || '%';
        """
        )
        result = cursor.fetchone()
        total_users = result[0] if result is not None else 0
        conn.commit()
        return total_users
    except Exception as e:
        print(f"Failed to obtain previous patched instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()

def get_total_pending_eol_patched_users():
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT SUM(total_users) as "Pending EOL Patched"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT software_version
                FROM patch_versions
                WHERE n_level = 2
            ) || '%';
        """
        )
        result = cursor.fetchone()
        total_users = result[0] if result is not None else 0
        conn.commit()
        return total_users
    except Exception as e:
        print(f"Failed to obtain pending EOL patched instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()

def get_active_main_branch_users():
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT SUM(active_users_monthly) as "Main Total"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT branch || '.%'
                FROM patch_versions
                WHERE n_level = -1
            );
        """
        )
        result = cursor.fetchone()
        active_users = result[0] if result is not None else 0
        conn.commit()
        return active_users
    except Exception as e:
        print(f"Failed to obtain active main instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_active_release_branch_users():
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT SUM(active_users_monthly) as "Latest Total"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT branch || '.%'
                FROM patch_versions
                WHERE n_level = 0
            );
        """
        )
        result = cursor.fetchone()
        active_users = result[0] if result is not None else 0
        conn.commit()
        return active_users
    except Exception as e:
        print(f"Failed to obtain active latest instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_active_previous_branch_users():
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT SUM(active_users_monthly) as "Latest Total"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT branch || '.%'
                FROM patch_versions
                WHERE n_level = 1
            );
        """
        )
        result = cursor.fetchone()
        active_users = result[0] if result is not None else 0
        conn.commit()
        return active_users
    except Exception as e:
        print(f"Failed to obtain active previous instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_active_pending_eol_branch_users():
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT SUM(active_users_monthly) as "Latest Total"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT branch || '.%'
                FROM patch_versions
                WHERE n_level = 2
            );
        """
        )
        result = cursor.fetchone()
        active_users = result[0] if result is not None else 0
        conn.commit()
        return active_users
    except Exception as e:
        print(f"Failed to obtain active pending EOL instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_active_eol_branch_users():
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT SUM(mastodon_domains.active_users_monthly) as "Latest Total"
            FROM mastodon_domains
            WHERE EXISTS (
                SELECT 1
                FROM eol_versions
                WHERE mastodon_domains.software_version LIKE eol_versions.software_version || '%'
            );
        """
        )
        result = cursor.fetchone()
        active_users = result[0] if result is not None else 0
        conn.commit()
        return active_users
    except Exception as e:
        print(f"Failed to obtain active EOL instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()

def get_active_main_patched_users():
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT SUM(active_users_monthly) as "Main Patched"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT software_version
                FROM patch_versions
                WHERE main = True
            ) || '%';
        """
        )
        result = cursor.fetchone()
        active_users = result[0] if result is not None else 0
        conn.commit()
        return active_users
    except Exception as e:
        print(f"Failed to obtain active main patched instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()

def get_active_release_patched_users():
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT SUM(active_users_monthly) as "Latest Patched"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT software_version
                FROM patch_versions
                WHERE n_level = 0
            ) || '%';
        """
        )
        result = cursor.fetchone()
        active_users = result[0] if result is not None else 0
        conn.commit()
        return active_users
    except Exception as e:
        print(f"Failed to obtain active release patched instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()

def get_active_previous_patched_users():
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT SUM(active_users_monthly) as "Previous Patched"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT software_version
                FROM patch_versions
                WHERE n_level = 1
            ) || '%';
        """
        )
        result = cursor.fetchone()
        active_users = result[0] if result is not None else 0
        conn.commit()
        return active_users
    except Exception as e:
        print(f"Failed to obtain active previous patched instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()

def get_active_pending_eol_patched_users():
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT SUM(active_users_monthly) as "Pending EOL Patched"
            FROM mastodon_domains
            WHERE software_version LIKE (
                SELECT software_version
                FROM patch_versions
                WHERE n_level = 2
            ) || '%';
        """
        )
        result = cursor.fetchone()
        active_users = result[0] if result is not None else 0
        conn.commit()
        return active_users
    except Exception as e:
        print(f"Failed to obtain active pending EOL patched instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()

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
        total_unique_versions = get_total_unique_versions()
        print(f"Total unique versions: {total_unique_versions}")
        total_main_instances = get_total_main__branch_instances()
        print(f"Total main branch instances: {total_main_instances}")
        total_release_instances = get_total_release_branch_instances()
        print(f"Total release branch instances: {total_release_instances}")
        total_previous_instances = get_total_previous_branch_instances()
        print(f"Total previous branch instances: {total_previous_instances}")
        total_pending_eol_instances = get_total_pending_eol_branch_instances()
        print(f"Total pending EOL branch instances: {total_pending_eol_instances}")
        total_eol_instances = get_total_eol_branch_instances()
        print(f"Total EOL branch instances: {total_eol_instances}")
        total_main_patched_instances = get_total_main_patched_instances()
        print(f"Total main patched instances: {total_main_patched_instances}")
        total_release_patched_instances = get_total_release_patched_instances()
        print(f"Total release patched instances: {total_release_patched_instances}")
        total_previous_patched_instances = get_total_previous_patched_instances()
        print(f"Total previous patched instances: {total_previous_patched_instances}")
        total_pending_eol_patched_instances = get_total_pending_eol_patched_instances()
        print(f"Total pending EOL patched instances: {total_pending_eol_patched_instances}")
        total_main_branch_users = get_total_main_branch_users()
        print(f"Total main branch users: {total_main_branch_users}")
        total_release_branch_users = get_total_release_branch_users()
        print(f"Total release branch users: {total_release_branch_users}")
        total_previous_branch_users = get_total_previous_branch_users()
        print(f"Total previous branch users: {total_previous_branch_users}")
        total_pending_eol_branch_users = get_total_pending_eol_branch_users()
        print(f"Total pending EOL branch users: {total_pending_eol_branch_users}")
        total_eol_branch_users = get_total_eol_branch_users()
        print(f"Total EOL branch users: {total_eol_branch_users}")
        total_main_patched_users = get_total_main_patched_users()
        print(f"Total main patched users: {total_main_patched_users}")
        total_release_patched_users = get_total_release_patched_users()
        print(f"Total release patched users: {total_release_patched_users}")
        total_previous_patched_users = get_total_previous_patched_users()
        print(f"Total previous patched users: {total_previous_patched_users}")
        total_pending_eol_patched_users = get_total_pending_eol_patched_users()
        print(f"Total pending EOL patched users: {total_pending_eol_patched_users}")
        total_active_main_branch_users = get_active_main_branch_users()
        print(f"Total active main branch users: {total_active_main_branch_users}")
        total_active_release_branch_users = get_active_release_branch_users()
        print(f"Total active release branch users: {total_active_release_branch_users}")
        total_active_previous_branch_users = get_active_previous_branch_users()
        print(f"Total active previous branch users: {total_active_previous_branch_users}")
        total_active_pending_eol_branch_users = get_active_pending_eol_branch_users()
        print(f"Total active pending EOL branch users: {total_active_pending_eol_branch_users}")
        total_active_eol_branch_users = get_active_eol_branch_users()
        print(f"Total active EOL branch users: {total_active_eol_branch_users}")
        total_active_main_patched_users = get_active_main_patched_users()
        print(f"Total active main patched users: {total_active_main_patched_users}")
        total_active_release_patched_users = get_active_release_patched_users()
        print(f"Total active release patched users: {total_active_release_patched_users}")
        total_active_previous_patched_users = get_active_previous_patched_users()
        print(f"Total active previous patched users: {total_active_previous_patched_users}")
        total_active_pending_eol_patched_users = get_active_pending_eol_patched_users()
        print(f"Total active pending EOL patched users: {total_active_pending_eol_patched_users}")

    except KeyboardInterrupt:
        print_colored(f"\n{appname} interrupted by user", "bold")
    finally:
        conn.close()
        http_client.close()
