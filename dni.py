#!/usr/bin/env python3

# =============================================================================
# IMPORTS
# =============================================================================

try:
    import argparse
    import csv
    import os
    import sys

    from crawler import (
        appname,
        appversion,
        conn,
        db_pool,
        get_httpx,
        http_client,
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
DNI_CSV_URL = "https://about.iftas.org/wp-content/uploads/2025/10/iftas-dni-latest.csv"

# =============================================================================
# ARGUMENT PARSING
# =============================================================================

parser = argparse.ArgumentParser(
    description="Fetch IFTAS DNI (Do Not Interact) list and update database."
)
_ = parser.add_argument(
    "-l",
    "--list",
    action="store_true",
    help="List all domains currently in the DNI table",
)
_ = parser.add_argument(
    "-c",
    "--count",
    action="store_true",
    help="Show count of domains in the DNI table",
)
_ = parser.add_argument(
    "-u",
    "--url",
    type=str,
    default=DNI_CSV_URL,
    help=f"Custom URL for DNI CSV file (default: {DNI_CSV_URL})",
)

args = parser.parse_args()

# =============================================================================
# DATABASE FUNCTIONS
# =============================================================================


def create_dni_table() -> None:
    """Create the dni table if it doesn't exist."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                _ = cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS dni (
                        domain TEXT PRIMARY KEY,
                        comment TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """
                )
                conn.commit()
                vmc_output("DNI table verified/created", "green")
            except Exception as e:
                vmc_output(f"Failed to create DNI table: {e}", "red")
                conn.rollback()
                sys.exit(1)


def get_existing_dni_domains() -> set[str]:
    """Get list of domains already in dni table."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                _ = cursor.execute("SELECT domain FROM dni")
                existing_domains: set[str] = {
                    row[0]
                    for row in cursor.fetchall()  # pyright: ignore[reportAny]
                }
                return existing_domains
            except Exception as e:
                vmc_output(f"Failed to get existing DNI domains: {e}", "orange")
                conn.rollback()
                return set()


def import_dni_domains(domains: list[str], comment: str = "iftas") -> int:
    """Import new domains into dni table with comment."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                if domains:
                    # Use batch insert for efficiency
                    values: list[tuple[str, str]] = [
                        (domain.lower(), comment) for domain in domains
                    ]
                    args_str = ",".join(["(%s, %s)" for _ in values])
                    flattened_values: list[str] = [
                        item for sublist in values for item in sublist
                    ]
                    _ = cursor.execute(
                        "INSERT INTO dni (domain, comment) VALUES "
                        + args_str
                        + " ON CONFLICT (domain) DO NOTHING",
                        flattened_values,
                    )
                    inserted_count = cursor.rowcount
                    vmc_output(f"Imported {inserted_count} new DNI domains", "green")
                    conn.commit()
                    return inserted_count
                else:
                    vmc_output("No new domains to import", "yellow")
                    return 0
            except Exception as e:
                vmc_output(f"Failed to import DNI domains: {e}", "orange")
                conn.rollback()
                return 0


def list_dni_domains() -> None:
    """Display all domains in the dni table."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                _ = cursor.execute(
                    "SELECT domain, comment, timestamp FROM dni ORDER BY domain"
                )
                domains = cursor.fetchall()

                if not domains:
                    vmc_output("No domains found in DNI table", "yellow")
                    return

                vmc_output(f"\nDNI Domains ({len(domains)} total):", "cyan")
                vmc_output("-" * 80, "cyan")

                for domain, comment, timestamp in domains:  # pyright: ignore[reportAny]
                    comment_str = comment if comment else ""
                    print(f"{domain:<40} {comment_str:<15} {timestamp}")
                print()

            except Exception as e:
                vmc_output(f"Failed to list DNI domains: {e}", "red")
                conn.rollback()


def count_dni_domains() -> int:
    """Display count of domains in the dni table."""
    with db_pool.connection() as conn:
        with conn.cursor() as cursor:
            try:
                _ = cursor.execute("SELECT COUNT(*) FROM dni")
                result = cursor.fetchone()
                count: int = result[0] if result else 0
                vmc_output(f"Total DNI domains: {count}", "green")
                return count
            except Exception as e:
                vmc_output(f"Failed to count DNI domains: {e}", "red")
                conn.rollback()
                return 0


# =============================================================================
# CSV FETCHING AND PARSING
# =============================================================================


def fetch_dni_csv(url: str) -> str | None:
    """Fetch the DNI CSV file from the specified URL."""
    try:
        vmc_output(f"Fetching DNI list from {url}…", "bold")
        response = get_httpx(url, http_client)

        if response.status_code != 200:
            vmc_output(f"Failed to fetch DNI CSV: HTTP {response.status_code}", "red")
            return None

        vmc_output("DNI CSV fetched successfully", "green")
        return response.text

    except Exception as e:
        vmc_output(f"Error fetching DNI CSV: {e}", "red")
        return None


def parse_dni_csv(csv_content: str) -> list[str]:
    """Parse the DNI CSV content and extract domains.

    The CSV file uses #domain as the header for the domain column.
    """
    domains: list[str] = []

    try:
        lines = csv_content.strip().split("\n")
        reader = csv.DictReader(lines)

        # Check if #domain column exists
        if not reader.fieldnames or "#domain" not in reader.fieldnames:
            vmc_output(
                f"CSV header '#domain' not found. Available headers: {reader.fieldnames}",
                "red",
            )
            return []

        for row in reader:
            domain = row.get("#domain", "").strip()
            if domain and domain != "#domain":  # Skip empty rows and header repeats
                domains.append(domain.lower())

        vmc_output(f"Parsed {len(domains)} domains from CSV", "green")
        return domains

    except Exception as e:
        vmc_output(f"Error parsing DNI CSV: {e}", "red")
        return []


# =============================================================================
# MAIN FUNCTION
# =============================================================================


def main() -> None:
    """Main entry point for DNI list management."""
    vmc_output(f"{appname} v{appversion} ({current_filename})", "bold")
    if is_running_headless():
        vmc_output("Running in headless mode", "pink")
    else:
        vmc_output("Running in interactive mode", "pink")

    # Ensure table exists
    create_dni_table()

    try:
        # List domains
        if args.list:  # pyright: ignore[reportAny]
            list_dni_domains()
            return

        # Count domains
        if args.count:  # pyright: ignore[reportAny]
            _ = count_dni_domains()
            return

        # Fetch and import DNI list (default behavior)
        csv_content = fetch_dni_csv(args.url)  # pyright: ignore[reportAny]
        if not csv_content:
            vmc_output("Failed to fetch DNI CSV, exiting…", "pink")
            sys.exit(1)

        domains = parse_dni_csv(csv_content)
        if not domains:
            vmc_output("No domains parsed from CSV, exiting…", "pink")
            sys.exit(1)

        # Get existing domains to avoid duplicates
        existing_domains = get_existing_dni_domains()
        new_domains = [d for d in domains if d not in existing_domains]

        vmc_output(
            f"Found {len(new_domains)} new domains (out of {len(domains)} total)",
            "cyan",
        )

        if new_domains:
            _ = import_dni_domains(new_domains)
        else:
            vmc_output("All domains already exist in database", "yellow")

        # Show final count
        _ = count_dni_domains()
        vmc_output("DNI import complete!", "bold")

    except KeyboardInterrupt:
        vmc_output(f"\n{appname} interrupted by user", "bold")
    finally:
        conn.close()
        db_pool.close()


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    main()
