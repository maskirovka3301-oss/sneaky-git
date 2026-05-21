#!/bin/bash

# Minimal cleanup script - just kills processes on the port

PROXY_PORT=""
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --proxy-port) PROXY_PORT="$2"; shift 2 ;;
        --verbose) VERBOSE=true; shift ;;
        *) shift ;;
    esac
done

if [[ -z "$PROXY_PORT" ]]; then
    echo "ERROR: Missing --proxy-port argument" >&2
    exit 1
fi

[[ "$VERBOSE" == true ]] && echo "Cleaning up port $PROXY_PORT"

# Method 1: Kill by PID file
if [[ -f "/tmp/proxy-$PROXY_PORT.pid" ]]; then
    PID=$(cat "/tmp/proxy-$PROXY_PORT.pid")
    kill $PID 2>/dev/null && [[ "$VERBOSE" == true ]] && echo "Killed PID $PID"
    rm -f "/tmp/proxy-$PROXY_PORT.pid"
fi

# Method 2: Kill by port
PIDS=$(lsof -ti :$PROXY_PORT 2>/dev/null)
if [[ -n "$PIDS" ]]; then
    for PID in $PIDS; do
        kill -TERM $PID 2>/dev/null
        [[ "$VERBOSE" == true ]] && echo "Killed process $PID on port $PROXY_PORT"
    done
    sleep 1
    for PID in $PIDS; do
        kill -KILL $PID 2>/dev/null
    done
fi

# Method 3: Kill socat processes
pkill -f "socat.*LISTEN:$PROXY_PORT" 2>/dev/null

# Method 4: Remove temp files
rm -f "/tmp/proxy-$PROXY_PORT.log" "/tmp/docker-proxy-$PROXY_PORT.txt"

exit 0
