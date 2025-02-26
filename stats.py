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

if __name__ == "__main__":
    try:
        print_colored(f"{appname} v{appversion} ({current_filename})", "bold")
        if is_running_headless():
            print_colored("Running in headless mode", "pink")
        else:
            print_colored("Running in interactive mode", "pink")

        total_raw_domains = get_total_raw_domains()
        print(f"Total raw domains: {total_raw_domains}")

    except KeyboardInterrupt:
        print_colored(f"\n{appname} interrupted by user", "bold")
    finally:
        conn.close()
        http_client.close()
