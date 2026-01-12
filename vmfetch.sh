#!/bin/bash
# vmfetch startup script
# This script uses uv to run fetch.py

set -e

# Add common uv installation locations to PATH
export PATH="$HOME/.local/bin:/usr/local/bin:$PATH"

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

# Run the fetcher using uv
exec uv run fetch.py "$@"
