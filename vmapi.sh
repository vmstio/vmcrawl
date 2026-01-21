#!/bin/bash
# vmapi startup script
# This script uses uv to run the FastAPI service

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

# Default values
HOST="${VMAPI_HOST:-0.0.0.0}"
PORT="${VMAPI_PORT:-8000}"
WORKERS="${VMAPI_WORKERS:-1}"
RELOAD=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --host)
            HOST="$2"
            shift 2
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        --workers)
            WORKERS="$2"
            shift 2
            ;;
        --reload)
            RELOAD="--reload"
            shift
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --host HOST       Bind to host (default: 0.0.0.0, env: VMAPI_HOST)"
            echo "  --port PORT       Bind to port (default: 8000, env: VMAPI_PORT)"
            echo "  --workers NUM     Number of worker processes (default: 1, env: VMAPI_WORKERS)"
            echo "  --reload          Enable auto-reload for development"
            echo "  --help            Show this help message"
            echo ""
            echo "Environment variables:"
            echo "  VMAPI_HOST        Default host to bind to"
            echo "  VMAPI_PORT        Default port to bind to"
            echo "  VMAPI_WORKERS     Default number of workers"
            echo ""
            echo "Examples:"
            echo "  $0                                    # Run with defaults"
            echo "  $0 --reload                           # Development mode with auto-reload"
            echo "  $0 --workers 4                        # Production with 4 workers"
            echo "  $0 --host 127.0.0.1 --port 8080       # Custom host and port"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Build uvicorn command
if [ -n "$RELOAD" ]; then
    # Development mode - single worker with reload
    echo "Starting vmapi in development mode..."
    echo "  Host: $HOST"
    echo "  Port: $PORT"
    echo "  Auto-reload: enabled"
    exec uv run uvicorn api:app --host "$HOST" --port "$PORT" $RELOAD
else
    # Production mode
    echo "Starting vmapi in production mode..."
    echo "  Host: $HOST"
    echo "  Port: $PORT"
    echo "  Workers: $WORKERS"
    exec uv run uvicorn api:app --host "$HOST" --port "$PORT" --workers "$WORKERS"
fi
