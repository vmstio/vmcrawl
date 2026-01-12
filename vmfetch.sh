#!/bin/bash
# vmfetch startup script
# This script activates the virtual environment and runs fetch.py

set -e

# Change to the application directory
# Try multiple potential installation locations
if [ -d "/opt/vmcrawl" ]; then
    cd /opt/vmcrawl
elif [ -d "$HOME/vmcrawl" ]; then
    cd "$HOME/vmcrawl"
else
    # Fall back to the directory where this script is located
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cd "$SCRIPT_DIR"
fi

# Activate the virtual environment
source .venv/bin/activate

# Run the fetcher
exec python3 fetch.py "$@"
