#!/bin/bash
# start.sh - Launch the bpfscript system monitor
# Usage: ./start.sh [--bpf] [--port PORT] [--interval SECONDS]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Defaults
PORT=8080
INTERVAL=1
USE_BPF=""
EXTRA=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --bpf)    USE_BPF="--bpf"; shift ;;
        --port)   PORT="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        --host)   EXTRA="$EXTRA --host $2"; shift 2 ;;
        *)        echo "Unknown: $1"; exit 1 ;;
    esac
done

echo "Starting bpfscript monitor..."
echo "  Port:     $PORT"
echo "  Interval: ${INTERVAL}s"
echo "  BPF:      ${USE_BPF:-disabled}"
echo ""

if [ -n "$USE_BPF" ]; then
    # Need root for BPF
    if [ "$(id -u)" -ne 0 ]; then
        echo "BPF mode requires root. Re-launching with sudo..."
        exec sudo python3 monitor_server.py --port "$PORT" --interval "$INTERVAL" --bpf $EXTRA
    else
        exec python3 monitor_server.py --port "$PORT" --interval "$INTERVAL" --bpf $EXTRA
    fi
else
    exec python3 monitor_server.py --port "$PORT" --interval "$INTERVAL" $EXTRA
fi
