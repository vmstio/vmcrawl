#!/bin/bash
# vmstats startup script
# This script activates the virtual environment and runs stats.py

set -e

# Change to the application directory
cd /opt/vmcrawl

# Activate the virtual environment
source .venv/bin/activate

# Run the stats generator
exec python3 stats.py "$@"
