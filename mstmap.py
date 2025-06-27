#!/usr/bin/env python3

from datetime import datetime

# Define backport branches (adjust as needed)
backport_branches = ["4.3", "4.2"]

# Define nightly version ranges with their respective start and end dates
# First date is the date on the -security release or the first nightly
nightly_version_ranges = [
    ("4.4.0-rc.1", datetime(2025, 8, 1), datetime(2029, 6, 30)),
    ("4.4.0-beta.2", datetime(2025, 6, 18), datetime(2025, 7, 31)),
    ("4.4.0-beta.1", datetime(2025, 6, 5), datetime(2025, 6, 17)),
    ("4.4.0-alpha.5", datetime(2025, 5, 7), datetime(2025, 6, 3)),
    ("4.4.0-alpha.4", datetime(2025, 3, 14), datetime(2025, 5, 6)),
    ("4.4.0-alpha.3", datetime(2025, 2, 28), datetime(2025, 3, 13)),
    ("4.4.0-alpha.2", datetime(2025, 1, 17), datetime(2025, 2, 27)),
    ("4.4.0-alpha.1", datetime(2024, 10, 8), datetime(2025, 1, 16)),
    ("4.3.0-rc.1", datetime(2024, 10, 1), datetime(2024, 10, 7)),
    ("4.3.0-beta.2", datetime(2024, 9, 18), datetime(2024, 9, 30)),
    ("4.3.0-beta.1", datetime(2024, 8, 24), datetime(2024, 9, 17)),
    ("4.3.0-alpha.5", datetime(2024, 7, 5), datetime(2024, 8, 23)),
    ("4.3.0-alpha.4", datetime(2024, 5, 31), datetime(2024, 7, 4)),
    ("4.3.0-alpha.3", datetime(2024, 2, 17), datetime(2024, 5, 30)),
    ("4.3.0-alpha.2", datetime(2024, 2, 15), datetime(2024, 2, 17)),
    ("4.3.0-alpha.1", datetime(2024, 1, 30), datetime(2024, 2, 14)),
    ("4.3.0-alpha.0", datetime(2023, 9, 28), datetime(2024, 1, 29))
]
