#!/usr/bin/env python3

# Import required modules
try:
    import argparse
    import os
    import sys
    from datetime import datetime, timedelta

    from crawler import (
        appname,
        appversion,
        conn,
        print_colored,
        is_running_headless,
    )
except ImportError as e:
    print(f"Error importing module: {e}")
    sys.exit(1)

# Detect the current filename
current_filename = os.path.basename(__file__)


def display_current_versions():
    """Display all current nightly version entries."""
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT version, start_date, end_date 
                FROM nightly_versions 
                ORDER BY start_date DESC
            """
            )
            versions = cur.fetchall()

            if not versions:
                print_colored("No nightly versions found in database", "yellow")
                return

            print_colored("\nCurrent Nightly Versions:", "cyan")
            print_colored("-" * 70, "cyan")
            print_colored(
                f"{'Version':<20} {'Start Date':<15} {'End Date':<15}", "bold"
            )
            print_colored("-" * 70, "cyan")

            for version, start_date, end_date in versions:
                print(f"{version:<20} {start_date} {end_date}")
            print()

    except Exception as e:
        print_colored(f"Error fetching nightly versions: {e}", "red")
        sys.exit(1)


def get_active_version():
    """Get the currently active nightly version (end_date = 2099-12-31)."""
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT version, start_date, end_date 
                FROM nightly_versions 
                WHERE end_date = '2099-12-31'
                ORDER BY start_date DESC
                LIMIT 1
            """
            )
            result = cur.fetchone()
            return result if result else None
    except Exception as e:
        print_colored(f"Error fetching active version: {e}", "red")
        return None


def validate_date(date_string):
    """Validate date format (YYYY-MM-DD)."""
    try:
        datetime.strptime(date_string, "%Y-%m-%d")
        return True
    except ValueError:
        return False


def add_nightly_version(
    version, start_date, end_date="2099-12-31", auto_update_previous=True
):
    """
    Add a new nightly version to the database.

    Args:
        version: Version string (e.g., '4.9.0-alpha.7')
        start_date: Start date in YYYY-MM-DD format
        end_date: End date in YYYY-MM-DD format (default: 2099-12-31)
        auto_update_previous: If True, automatically update the previous active version's end_date
    """
    try:
        # Validate dates
        if not validate_date(start_date):
            print_colored(
                f"Invalid start_date format: {start_date}. Use YYYY-MM-DD", "red"
            )
            return False

        if not validate_date(end_date):
            print_colored(f"Invalid end_date format: {end_date}. Use YYYY-MM-DD", "red")
            return False

        # Check if version already exists
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT version FROM nightly_versions WHERE version = %s
            """,
                (version,),
            )
            if cur.fetchone():
                print_colored(f"Version {version} already exists in database", "yellow")
                return False

        # If auto-update is enabled, update the previous active version
        if auto_update_previous:
            active_version = get_active_version()
            if active_version:
                old_version, old_start, old_end = active_version
                # Calculate new end date (one day before new start_date)
                new_end_date = (
                    datetime.strptime(start_date, "%Y-%m-%d") - timedelta(days=1)
                ).strftime("%Y-%m-%d")

                print_colored(f"\nUpdating previous active version:", "cyan")
                print_colored(f"  Version: {old_version}", "cyan")
                print_colored(f"  Old end date: {old_end}", "cyan")
                print_colored(f"  New end date: {new_end_date}", "cyan")

                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE nightly_versions 
                        SET end_date = %s 
                        WHERE version = %s
                    """,
                        (new_end_date, old_version),
                    )
                    conn.commit()

                print_colored(
                    f"✓ Updated {old_version} end date to {new_end_date}", "green"
                )

        # Insert new version
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO nightly_versions (version, start_date, end_date)
                VALUES (%s, %s, %s)
            """,
                (version, start_date, end_date),
            )
            conn.commit()

        print_colored(f"\n✓ Successfully added nightly version:", "green")
        print_colored(f"  Version: {version}", "green")
        print_colored(f"  Start date: {start_date}", "green")
        print_colored(f"  End date: {end_date}", "green")

        return True

    except Exception as e:
        conn.rollback()
        print_colored(f"Error adding nightly version: {e}", "red")
        return False


def update_end_date(version, new_end_date):
    """Update the end_date for a specific version."""
    try:
        if not validate_date(new_end_date):
            print_colored(f"Invalid date format: {new_end_date}. Use YYYY-MM-DD", "red")
            return False

        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE nightly_versions 
                SET end_date = %s 
                WHERE version = %s
            """,
                (new_end_date, version),
            )

            if cur.rowcount == 0:
                print_colored(f"Version {version} not found in database", "yellow")
                return False

            conn.commit()

        print_colored(f"✓ Updated {version} end date to {new_end_date}", "green")
        return True

    except Exception as e:
        conn.rollback()
        print_colored(f"Error updating end date: {e}", "red")
        return False


def interactive_add():
    """Interactive mode for adding a new nightly version."""
    print_colored("\n=== Add New Nightly Version ===", "bold")

    # Show current versions
    display_current_versions()

    # Get version
    version = input("Enter version (e.g., 4.9.0-alpha.7): ").strip()
    if not version:
        print_colored("Version cannot be empty", "red")
        return

    # Get start date
    default_start_date = datetime.now().strftime("%Y-%m-%d")
    start_date_input = input(f"Enter start date (YYYY-MM-DD) [default: {default_start_date}]: ").strip()
    start_date = start_date_input if start_date_input else default_start_date

    # Get end date (optional)
    end_date = input("Enter end date (YYYY-MM-DD) [default: 2099-12-31]: ").strip()
    if not end_date:
        end_date = "2099-12-31"

    # Confirm update of previous version
    active = get_active_version()
    if active and end_date == "2099-12-31":
        old_version, old_start, old_end = active
        new_end = (
            datetime.strptime(start_date, "%Y-%m-%d") - timedelta(days=1)
        ).strftime("%Y-%m-%d")

        print_colored(f"\nThis will update the previous active version:", "yellow")
        print_colored(f"  {old_version}: {old_end} → {new_end}", "yellow")

        confirm = input("Continue? (y/n): ").strip().lower()
        if confirm != "y":
            print_colored("Operation cancelled", "pink")
            return

    # Add the version
    add_nightly_version(version, start_date, end_date)


def main():
    """Main execution logic."""
    parser = argparse.ArgumentParser(
        description="Manage nightly version entries in the database"
    )
    parser.add_argument(
        "-l", "--list", action="store_true", help="List all nightly versions"
    )
    parser.add_argument(
        "-a",
        "--add",
        action="store_true",
        help="Add a new nightly version (interactive)",
    )
    parser.add_argument(
        "-v",
        "--version",
        type=str,
        help="Version string (e.g., 4.9.0-alpha.7)",
    )
    parser.add_argument(
        "-s", "--start-date", type=str, help="Start date in YYYY-MM-DD format"
    )
    parser.add_argument(
        "-e",
        "--end-date",
        type=str,
        default="2099-12-31",
        help="End date in YYYY-MM-DD format (default: 2099-12-31)",
    )
    parser.add_argument(
        "--no-auto-update",
        action="store_true",
        help="Don't automatically update the previous active version's end date",
    )
    parser.add_argument(
        "--update-end-date",
        nargs=2,
        metavar=("VERSION", "END_DATE"),
        help="Update end_date for a specific version",
    )

    args = parser.parse_args()

    # Print header
    print_colored(f"{appname} v{appversion} ({current_filename})", "bold")
    if is_running_headless():
        print_colored("Running in headless mode", "pink")
    else:
        print_colored("Running in interactive mode", "pink")

    try:
        # List versions
        if args.list:
            display_current_versions()

        # Update end date
        elif args.update_end_date:
            version, end_date = args.update_end_date
            update_end_date(version, end_date)

        # Add version (command line)
        elif args.version and args.start_date:
            add_nightly_version(
                args.version,
                args.start_date,
                args.end_date,
                auto_update_previous=not args.no_auto_update,
            )

        # Add version (interactive) - now the default behavior
        else:
            interactive_add()

    except KeyboardInterrupt:
        print_colored(f"\n{appname} interrupted by user", "bold")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
