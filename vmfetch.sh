#!/bin/bash
# vmfetch startup script
# This script activates the virtual environment and runs fetch.py

set -e

# Change to the application directory
cd /opt/vmcrawl

# Activate the virtual environment
source .venv/bin/activate

# Run the fetcher
exec python3 fetch.py "$@"
