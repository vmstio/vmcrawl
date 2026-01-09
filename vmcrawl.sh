#!/bin/bash
# vmcrawl startup script
# This script activates the virtual environment and runs crawler.py

set -e

# Change to the application directory
cd /opt/vmcrawl

# Activate the virtual environment
source venv/bin/activate

# Run the crawler
exec python3 crawler.py "$@"
