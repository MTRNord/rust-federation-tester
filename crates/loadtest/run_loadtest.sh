#!/bin/bash

# Default values
HOST="http://localhost:8080"
USERS="50"
RUN_TIME="60s"
SERVER_NAME="mtrnord.blog"

# Help function
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Run load test for rust-federation-tester server"
    echo ""
    echo "Options:"
    echo "  --host HOST          Target host (default: $HOST)"
    echo "  --users USERS        Number of concurrent users (default: $USERS)"
    echo "  --run-time TIME      Test duration (default: $RUN_TIME)"
    echo "  --server-name NAME   Server name for API calls (default: $SERVER_NAME)"
    echo "  --help               Show this help"
    echo ""
    echo "Examples:"
    echo "  $0                                                # Quick test with defaults"
    echo "  $0 --users 50 --run-time 2m                     # 50 users for 2 minutes"
    echo "  $0 --host https://example.com --server-name test.org  # Test remote server"
    echo ""
    echo "All Goose options are also available, see --help for full list:"
    echo "  cargo run --package loadtest -- --help"
}

# Parse command line arguments
ARGS=()
while [[ $# -gt 0 ]]; do
    case $1 in
        --host)
            HOST="$2"
            shift 2
            ;;
        --users)
            USERS="$2"
            shift 2
            ;;
        --run-time)
            RUN_TIME="$2"
            shift 2
            ;;
        --server-name)
            SERVER_NAME="$2"
            shift 2
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            # Pass through other arguments to Goose
            ARGS+=("$1")
            shift
            ;;
    esac
done

echo "Starting load test..."
echo "Host: $HOST"
echo "Users: $USERS"
echo "Duration: $RUN_TIME"
echo "Server Name: $SERVER_NAME"
echo ""

# Set server name environment variable and run the load test
SERVER_NAME="$SERVER_NAME" cargo run --package loadtest --release -- \
    --host "$HOST" \
    --users "$USERS" \
    --run-time "$RUN_TIME" \
    --startup-time "1m" \
    --report-file=report.html \
    "${ARGS[@]}"

