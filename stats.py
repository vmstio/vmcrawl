#!/usr/bin/env python3

# =============================================================================
# IMPORTS
# =============================================================================

try:
    import os
    import sys

    from crawler import (
        appname,
        appversion,
        conn,
        db_pool,
        is_running_headless,
        vmc_output,
    )
except ImportError as e:
    print(f"Error importing module: {e}")
    sys.exit(1)

# =============================================================================
# CONSTANTS
# =============================================================================

current_filename = os.path.basename(__file__)


# =============================================================================
# STATISTICS FUNCTIONS - Raw Domain Counts
# =============================================================================


def get_total_raw_domains():
    """Get total count of raw domains."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                cursor.execute(
                    "SELECT COUNT(domain) AS total_domains FROM raw_domains;"
                )
                result = cursor.fetchone()
                return result[0] if result is not None else 0
            except Exception as e:
                print(f"Failed to obtain total raw domains: {e}")
                conn.rollback()
                return 0


def get_total_failed_domains():
    """Get count of domains marked as failed."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                cursor.execute(
                    "SELECT COUNT(domain) AS total_domains FROM raw_domains WHERE failed = True;"
                )
                result = cursor.fetchone()
                return result[0] if result is not None else 0
            except Exception as e:
                print(f"Failed to obtain total failed domains: {e}")
                conn.rollback()
                return 0


def get_total_ignored_domains():
    """Get count of domains marked as ignored (non-Mastodon)."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                cursor.execute(
                    "SELECT COUNT(domain) AS total_domains FROM raw_domains WHERE ignore = True;"
                )
                result = cursor.fetchone()
                return result[0] if result is not None else 0
            except Exception as e:
                print(f"Failed to obtain total non-Mastodon domains: {e}")
                conn.rollback()
                return 0


def get_total_nxdomains():
    """Get count of domains marked as NXDOMAIN."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                cursor.execute(
                    "SELECT COUNT(domain) AS total_domains FROM raw_domains WHERE nxdomain = True;"
                )
                result = cursor.fetchone()
                return result[0] if result is not None else 0
            except Exception as e:
                print(f"Failed to obtain total nxdomain domains: {e}")
                conn.rollback()
                return 0


def get_total_norobots():
    """Get count of domains that prohibit crawling."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                cursor.execute(
                    "SELECT COUNT(domain) AS total_domains FROM raw_domains WHERE norobots = True;"
                )
                result = cursor.fetchone()
                return result[0] if result is not None else 0
            except Exception as e:
                print(f"Failed to obtain total norobots domains: {e}")
                conn.rollback()
                return 0


def get_total_baddata():
    """Get count of domains with bad data."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                cursor.execute(
                    "SELECT COUNT(domain) AS total_domains FROM raw_domains WHERE baddata = True;"
                )
                result = cursor.fetchone()
                return result[0] if result is not None else 0
            except Exception as e:
                print(f"Failed to obtain total baddata domains: {e}")
                conn.rollback()
                return 0


def get_total_error_over():
    """Get count of domains with 8 or more errors."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                cursor.execute(
                    "SELECT COUNT(domain) AS total_domains FROM raw_domains WHERE errors >= 8;"
                )
                result = cursor.fetchone()
                return result[0] if result is not None else 0
            except Exception as e:
                print(f"Failed to obtain total error over domains: {e}")
                conn.rollback()
                return 0


def get_total_error_under():
    """Get count of domains with 7 or fewer errors."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                cursor.execute(
                    "SELECT COUNT(domain) AS total_domains FROM raw_domains WHERE errors <= 7;"
                )
                result = cursor.fetchone()
                return result[0] if result is not None else 0
            except Exception as e:
                print(f"Failed to obtain total error under domains: {e}")
                conn.rollback()
                return 0


# =============================================================================
# STATISTICS FUNCTIONS - Mastodon Domain Counts
# =============================================================================


def get_total_mastodon_domains():
    """Get total count of known Mastodon domains."""
    cursor = conn.cursor()
    value_to_return = 0
    try:
        cursor.execute("SELECT COUNT(domain) AS total_domains FROM mastodon_domains;")
        result = cursor.fetchone()
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain total Mastodon domains: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_total_unique_versions():
    """Get count of unique software versions."""
    cursor = conn.cursor()
    value_to_return = 0
    try:
        cursor.execute(
            "SELECT COUNT(DISTINCT software_version) AS unique_software_versions FROM mastodon_domains;"
        )
        result = cursor.fetchone()
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain unique versions: {e}")
        conn.rollback()
    finally:
        cursor.close()


# =============================================================================
# STATISTICS FUNCTIONS - User Counts
# =============================================================================


def get_total_users():
    """Get total user count across all instances."""
    cursor = conn.cursor()
    value_to_return = 0
    try:
        cursor.execute("SELECT SUM(total_users) AS total_users FROM mastodon_domains;")
        result = cursor.fetchone()
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain total users: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_total_active_users():
    """Get total monthly active user count across all instances."""
    cursor = conn.cursor()
    value_to_return = 0
    try:
        cursor.execute(
            "SELECT SUM(active_users_monthly) AS total_users FROM mastodon_domains;"
        )
        result = cursor.fetchone()
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain active users: {e}")
        conn.rollback()
    finally:
        cursor.close()


# =============================================================================
# STATISTICS FUNCTIONS - Branch Instance Counts
# =============================================================================


def get_total_main_branch_instances():
    """Get count of instances on main branch."""
    cursor = conn.cursor()
    value_to_return = 0
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
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain total main instances: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_total_release_branch_instances():
    """Get count of instances on current release branch."""
    cursor = conn.cursor()
    value_to_return = 0
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
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain total latest instances: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_total_previous_branch_instances():
    """Get count of instances on previous release branch."""
    cursor = conn.cursor()
    value_to_return = 0
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
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain total previous instances: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_total_pending_eol_branch_instances():
    """Get count of instances on deprecated branches."""
    cursor = conn.cursor()
    value_to_return = 0
    try:
        cursor.execute(
            """
            SELECT COUNT(DISTINCT domain) as "Latest Total"
            FROM mastodon_domains
            WHERE EXISTS (
                SELECT 1
                FROM patch_versions
                WHERE n_level >= 2
                  AND mastodon_domains.software_version LIKE patch_versions.branch || '.%'
            );
        """
        )
        result = cursor.fetchone()
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain total deprecated instances: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_total_eol_branch_instances():
    """Get count of instances on EOL branches."""
    cursor = conn.cursor()
    value_to_return = 0
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
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain total EOL instances: {e}")
        conn.rollback()
    finally:
        cursor.close()


# =============================================================================
# STATISTICS FUNCTIONS - Patched Instance Counts
# =============================================================================


def get_total_main_patched_instances():
    """Get count of instances on latest main version."""
    cursor = conn.cursor()
    value_to_return = 0
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
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain main patched instances: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_total_release_patched_instances():
    """Get count of instances on latest release version."""
    cursor = conn.cursor()
    value_to_return = 0
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
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain release patched instances: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_total_previous_patched_instances():
    """Get count of instances on latest previous branch version."""
    cursor = conn.cursor()
    value_to_return = 0
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
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain previous patched instances: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_total_pending_eol_patched_instances():
    """Get count of instances on latest deprecated branch versions."""
    cursor = conn.cursor()
    value_to_return = 0
    try:
        cursor.execute(
            """
            SELECT COUNT(DISTINCT domain) as "Deprecated Patched"
            FROM mastodon_domains
            WHERE EXISTS (
                SELECT 1
                FROM patch_versions
                WHERE n_level >= 2
                  AND mastodon_domains.software_version LIKE patch_versions.software_version || '%'
            );
        """
        )
        result = cursor.fetchone()
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain deprecated patched instances: {e}")
        conn.rollback()
    finally:
        cursor.close()


# =============================================================================
# STATISTICS FUNCTIONS - Branch User Counts (Total)
# =============================================================================


def get_total_main_branch_users():
    """Get total users on main branch instances."""
    cursor = conn.cursor()
    value_to_return = 0
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
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain total main instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_total_release_branch_users():
    """Get total users on current release branch instances."""
    cursor = conn.cursor()
    value_to_return = 0
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
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain total latest instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_total_previous_branch_users():
    """Get total users on previous release branch instances."""
    cursor = conn.cursor()
    value_to_return = 0
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
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain total previous instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_total_pending_eol_branch_users():
    """Get total users on deprecated branch instances."""
    cursor = conn.cursor()
    value_to_return = 0
    try:
        cursor.execute(
            """
            SELECT SUM(total_users) as "Latest Total"
            FROM mastodon_domains
            WHERE EXISTS (
                SELECT 1
                FROM patch_versions
                WHERE n_level >= 2
                  AND mastodon_domains.software_version LIKE patch_versions.branch || '.%'
            );
        """
        )
        result = cursor.fetchone()
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain total deprecated instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_total_eol_branch_users():
    """Get total users on EOL branch instances."""
    cursor = conn.cursor()
    value_to_return = 0
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
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain total EOL instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


# =============================================================================
# STATISTICS FUNCTIONS - Patched User Counts (Total)
# =============================================================================


def get_total_main_patched_users():
    """Get total users on latest main version instances."""
    cursor = conn.cursor()
    value_to_return = 0
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
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain main patched instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_total_release_patched_users():
    """Get total users on latest release version instances."""
    cursor = conn.cursor()
    value_to_return = 0
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
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain release patched instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_total_previous_patched_users():
    """Get total users on latest previous branch version instances."""
    cursor = conn.cursor()
    value_to_return = 0
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
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain previous patched instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_total_pending_eol_patched_users():
    """Get total users on latest deprecated branch version instances."""
    cursor = conn.cursor()
    value_to_return = 0
    try:
        cursor.execute(
            """
            SELECT SUM(total_users) as "Deprecated Patched"
            FROM mastodon_domains
            WHERE EXISTS (
                SELECT 1
                FROM patch_versions
                WHERE n_level >= 2
                  AND mastodon_domains.software_version LIKE patch_versions.software_version || '%'
            );
        """
        )
        result = cursor.fetchone()
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain deprecated patched instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


# =============================================================================
# STATISTICS FUNCTIONS - Branch User Counts (Active)
# =============================================================================


def get_active_main_branch_users():
    """Get active users on main branch instances."""
    cursor = conn.cursor()
    value_to_return = 0
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
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain active main instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_active_release_branch_users():
    """Get active users on current release branch instances."""
    cursor = conn.cursor()
    value_to_return = 0
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
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain active latest instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_active_previous_branch_users():
    """Get active users on previous release branch instances."""
    cursor = conn.cursor()
    value_to_return = 0
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
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain active previous instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_active_pending_eol_branch_users():
    """Get active users on deprecated branch instances."""
    cursor = conn.cursor()
    value_to_return = 0
    try:
        cursor.execute(
            """
            SELECT SUM(active_users_monthly) as "Latest Total"
            FROM mastodon_domains
            WHERE EXISTS (
                SELECT 1
                FROM patch_versions
                WHERE n_level >= 2
                  AND mastodon_domains.software_version LIKE patch_versions.branch || '.%'
            );
        """
        )
        result = cursor.fetchone()
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain active deprecated instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_active_eol_branch_users():
    """Get active users on EOL branch instances."""
    cursor = conn.cursor()
    value_to_return = 0
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
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain active EOL instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


# =============================================================================
# STATISTICS FUNCTIONS - Patched User Counts (Active)
# =============================================================================


def get_active_main_patched_users():
    """Get active users on latest main version instances."""
    cursor = conn.cursor()
    value_to_return = 0
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
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain active main patched instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_active_release_patched_users():
    """Get active users on latest release version instances."""
    cursor = conn.cursor()
    value_to_return = 0
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
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain active release patched instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_active_previous_patched_users():
    """Get active users on latest previous branch version instances."""
    cursor = conn.cursor()
    value_to_return = 0
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
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain active previous patched instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


def get_active_pending_eol_patched_users():
    """Get active users on latest deprecated branch version instances."""
    cursor = conn.cursor()
    value_to_return = 0
    try:
        cursor.execute(
            """
            SELECT SUM(active_users_monthly) as "Deprecated Patched"
            FROM mastodon_domains
            WHERE EXISTS (
                SELECT 1
                FROM patch_versions
                WHERE n_level >= 2
                  AND mastodon_domains.software_version LIKE patch_versions.software_version || '%'
            );
        """
        )
        result = cursor.fetchone()
        value_to_return = result[0] if result is not None else 0
        conn.commit()
        return value_to_return
    except Exception as e:
        print(f"Failed to obtain active deprecated patched instances users: {e}")
        conn.rollback()
    finally:
        cursor.close()


# =============================================================================
# STATISTICS CONFIGURATION
# =============================================================================

# Define all statistics to collect
STATS_CONFIG = [
    ("total_raw_domains", get_total_raw_domains, "Total raw domains"),
    ("total_failed_domains", get_total_failed_domains, "Total failed (410) domains"),
    ("total_mastodon_domains", get_total_mastodon_domains, "Total Mastodon domains"),
    (
        "total_ignored_domains",
        get_total_ignored_domains,
        "Total ignored (non-Masto) domains",
    ),
    ("total_nxdomains", get_total_nxdomains, "Total nxdomain domains"),
    ("total_norobots", get_total_norobots, "Total robots.txt prohibited domains"),
    ("total_baddata", get_total_baddata, "Total baddata domains"),
    ("total_error_over", get_total_error_over, "Total error over domains"),
    ("total_error_under", get_total_error_under, "Total error under domains"),
    ("total_users", get_total_users, "Total users"),
    ("total_active_users", get_total_active_users, "Total active users"),
    ("total_unique_versions", get_total_unique_versions, "Total unique versions"),
    (
        "total_main_instances",
        get_total_main_branch_instances,
        "Total main branch instances",
    ),
    (
        "total_release_instances",
        get_total_release_branch_instances,
        "Total release branch instances",
    ),
    (
        "total_previous_instances",
        get_total_previous_branch_instances,
        "Total previous branch instances",
    ),
    (
        "total_pending_eol_instances",
        get_total_pending_eol_branch_instances,
        "Total deprecated branch instances",
    ),
    (
        "total_eol_instances",
        get_total_eol_branch_instances,
        "Total EOL branch instances",
    ),
    (
        "total_main_patched_instances",
        get_total_main_patched_instances,
        "Total main patched instances",
    ),
    (
        "total_release_patched_instances",
        get_total_release_patched_instances,
        "Total release patched instances",
    ),
    (
        "total_previous_patched_instances",
        get_total_previous_patched_instances,
        "Total previous patched instances",
    ),
    (
        "total_pending_eol_patched_instances",
        get_total_pending_eol_patched_instances,
        "Total deprecated patched instances",
    ),
    ("total_main_branch_users", get_total_main_branch_users, "Total main branch users"),
    (
        "total_release_branch_users",
        get_total_release_branch_users,
        "Total release branch users",
    ),
    (
        "total_previous_branch_users",
        get_total_previous_branch_users,
        "Total previous branch users",
    ),
    (
        "total_pending_eol_branch_users",
        get_total_pending_eol_branch_users,
        "Total deprecated branch users",
    ),
    ("total_eol_branch_users", get_total_eol_branch_users, "Total EOL branch users"),
    (
        "total_main_patched_users",
        get_total_main_patched_users,
        "Total main patched users",
    ),
    (
        "total_release_patched_users",
        get_total_release_patched_users,
        "Total release patched users",
    ),
    (
        "total_previous_patched_users",
        get_total_previous_patched_users,
        "Total previous patched users",
    ),
    (
        "total_pending_eol_patched_users",
        get_total_pending_eol_patched_users,
        "Total deprecated patched users",
    ),
    (
        "total_active_main_branch_users",
        get_active_main_branch_users,
        "Total active main branch users",
    ),
    (
        "total_active_release_branch_users",
        get_active_release_branch_users,
        "Total active release branch users",
    ),
    (
        "total_active_previous_branch_users",
        get_active_previous_branch_users,
        "Total active previous branch users",
    ),
    (
        "total_active_pending_eol_branch_users",
        get_active_pending_eol_branch_users,
        "Total active deprecated branch users",
    ),
    (
        "total_active_eol_branch_users",
        get_active_eol_branch_users,
        "Total active EOL branch users",
    ),
    (
        "total_active_main_patched_users",
        get_active_main_patched_users,
        "Total active main patched users",
    ),
    (
        "total_active_release_patched_users",
        get_active_release_patched_users,
        "Total active release patched users",
    ),
    (
        "total_active_previous_patched_users",
        get_active_previous_patched_users,
        "Total active previous patched users",
    ),
    (
        "total_active_pending_eol_patched_users",
        get_active_pending_eol_patched_users,
        "Total active deprecated patched users",
    ),
]


# =============================================================================
# DATABASE FUNCTIONS - Write Statistics
# =============================================================================


def write_statistics_to_database(stats_values):
    """Write collected statistics to the database."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                cursor.execute(
                    """
        INSERT INTO statistics (
        date, total_raw_domains, total_failed_domains, total_mastodon_domains,
        total_ignored_domains, total_nxdomains, total_norobots, total_baddata,
        total_error_over, total_error_under, total_users, total_active_users,
        total_unique_versions, total_main_instances, total_release_instances,
        total_previous_instances, total_pending_eol_instances, total_eol_instances,
        total_main_patched_instances, total_release_patched_instances,
        total_previous_patched_instances, total_pending_eol_patched_instances,
        total_main_branch_users, total_release_branch_users,
        total_previous_branch_users, total_pending_eol_branch_users,
        total_eol_branch_users, total_main_patched_users,
        total_release_patched_users, total_previous_patched_users,
        total_pending_eol_patched_users, total_active_main_branch_users,
        total_active_release_branch_users, total_active_previous_branch_users,
        total_active_pending_eol_branch_users, total_active_eol_branch_users,
        total_active_main_patched_users, total_active_release_patched_users,
        total_active_previous_patched_users, total_active_pending_eol_patched_users
        )
        VALUES (
        (SELECT CURRENT_DATE AT TIME ZONE 'UTC'), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
        %s, %s, %s, %s, %s, %s, %s, %s
        )
        ON CONFLICT (date) DO UPDATE SET
        total_raw_domains = EXCLUDED.total_raw_domains,
        total_failed_domains = EXCLUDED.total_failed_domains,
        total_mastodon_domains = EXCLUDED.total_mastodon_domains,
        total_ignored_domains = EXCLUDED.total_ignored_domains,
        total_nxdomains = EXCLUDED.total_nxdomains,
        total_norobots = EXCLUDED.total_norobots,
        total_baddata = EXCLUDED.total_baddata,
        total_error_over = EXCLUDED.total_error_over,
        total_error_under = EXCLUDED.total_error_under,
        total_users = EXCLUDED.total_users,
        total_active_users = EXCLUDED.total_active_users,
        total_unique_versions = EXCLUDED.total_unique_versions,
        total_main_instances = EXCLUDED.total_main_instances,
        total_release_instances = EXCLUDED.total_release_instances,
        total_previous_instances = EXCLUDED.total_previous_instances,
        total_pending_eol_instances = EXCLUDED.total_pending_eol_instances,
        total_eol_instances = EXCLUDED.total_eol_instances,
        total_main_patched_instances = EXCLUDED.total_main_patched_instances,
        total_release_patched_instances = EXCLUDED.total_release_patched_instances,
        total_previous_patched_instances = EXCLUDED.total_previous_patched_instances,
        total_pending_eol_patched_instances = EXCLUDED.total_pending_eol_patched_instances,
        total_main_branch_users = EXCLUDED.total_main_branch_users,
        total_release_branch_users = EXCLUDED.total_release_branch_users,
        total_previous_branch_users = EXCLUDED.total_previous_branch_users,
        total_pending_eol_branch_users = EXCLUDED.total_pending_eol_branch_users,
        total_eol_branch_users = EXCLUDED.total_eol_branch_users,
        total_main_patched_users = EXCLUDED.total_main_patched_users,
        total_release_patched_users = EXCLUDED.total_release_patched_users,
        total_previous_patched_users = EXCLUDED.total_previous_patched_users,
        total_pending_eol_patched_users = EXCLUDED.total_pending_eol_patched_users,
        total_active_main_branch_users = EXCLUDED.total_active_main_branch_users,
        total_active_release_branch_users = EXCLUDED.total_active_release_branch_users,
        total_active_previous_branch_users = EXCLUDED.total_active_previous_branch_users,
        total_active_pending_eol_branch_users = EXCLUDED.total_active_pending_eol_branch_users,
        total_active_eol_branch_users = EXCLUDED.total_active_eol_branch_users,
        total_active_main_patched_users = EXCLUDED.total_active_main_patched_users,
        total_active_release_patched_users = EXCLUDED.total_active_release_patched_users,
        total_active_previous_patched_users = EXCLUDED.total_active_previous_patched_users,
        total_active_pending_eol_patched_users = EXCLUDED.total_active_pending_eol_patched_users
        """,
                    stats_values,
                )
                conn.commit()
                vmc_output("Statistics inserted/updated successfully", "green")
            except Exception as e:
                print(f"Failed to insert/update statistics: {e}")
                conn.rollback()


# =============================================================================
# MAIN FUNCTION
# =============================================================================


if __name__ == "__main__":
    try:
        vmc_output(f"{appname} v{appversion} ({current_filename})", "bold")
        if is_running_headless():
            vmc_output("Running in headless mode", "pink")
        else:
            vmc_output("Running in interactive mode", "pink")

        # Initialize statistics dictionary
        stats_data = {}

        # Collect all statistics
        for name, fn, label in STATS_CONFIG:
            value = fn()
            stats_data[name] = value if value is not None else 0
            print(f"{label}: {stats_data[name]}")

        # Prompt for database write in interactive mode
        if not is_running_headless():
            vmc_output("Write this data to the statistics database?", "pink")
            choice = input("yes/no: ").strip().lower()
            if choice not in ("y", "yes"):
                vmc_output("Exiting without writing to the database", "yellow")
                sys.exit(0)

        # Prepare values tuple in correct order
        stats_values = tuple(stats_data[name] for name, _, _ in STATS_CONFIG)

        # Write to database
        write_statistics_to_database(stats_values)

    except KeyboardInterrupt:
        vmc_output(f"\n{appname} interrupted by user", "bold")
    finally:
        conn.close()
        db_pool.close()
