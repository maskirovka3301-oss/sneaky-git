#!/bin/bash

# start-residential-proxy.sh - Launches a residential proxy based on provider
# All parameters are passed from config.json

PROVIDER=""
API_KEY=""
API_SECRET=""
USERNAME=""
PASSWORD=""
COUNTRY=""
SESSION_ID=""
STICKY=""
CLIENT_IP=""
TARGET_PORT=""
PROXY_PORT=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --provider) PROVIDER="$2"; shift 2 ;;
        --api-key) API_KEY="$2"; shift 2 ;;
        --api-secret) API_SECRET="$2"; shift 2 ;;
        --username) USERNAME="$2"; shift 2 ;;
        --password) PASSWORD="$2"; shift 2 ;;
        --country) COUNTRY="$2"; shift 2 ;;
        --session-id) SESSION_ID="$2"; shift 2 ;;
        --sticky) STICKY="$2"; shift 2 ;;
        --client-ip) CLIENT_IP="$2"; shift 2 ;;
        --target-port) TARGET_PORT="$2"; shift 2 ;;
        --proxy-port) PROXY_PORT="$2"; shift 2 ;;
        *) shift ;;
    esac
done

echo "Starting proxy for provider: $PROVIDER"
echo "Client: $CLIENT_IP:$TARGET_PORT -> Local port: $PROXY_PORT"

case $PROVIDER in
    oxylabs)
        # Oxylabs specific configuration
        # Use socat to forward to Oxylabs' entry point with authentication
        socat TCP-LISTEN:$PROXY_PORT,fork,reuseaddr \
              SOCKS5:pr.oxylabs.io:$CLIENT_IP:$TARGET_PORT,socksport=7777,user=$USERNAME,pass=$PASSWORD &
        echo $! > /tmp/proxy-$PROXY_PORT.pid
        ;;
        
    brightdata|luminati)
        # BrightData (formerly Luminati) configuration
        # Use their tunnel endpoint
        brightdata proxy start \
            --port $PROXY_PORT \
            --target $CLIENT_IP:$TARGET_PORT \
            --country $COUNTRY \
            --session $SESSION_ID &
        ;;
        
    smartproxy)
        # Smartproxy configuration
        smartproxy-cli start \
            --listen-port $PROXY_PORT \
            --forward-to $CLIENT_IP:$TARGET_PORT \
            --gateway "gw.smartproxy.com:10000" \
            --auth "$USERNAME:$PASSWORD" &
        ;;
        
    geosurf)
        # GeoSurf configuration
        geosurf-proxy \
            --local-port $PROXY_PORT \
            --remote $CLIENT_IP:$TARGET_PORT \
            --credentials "$USERNAME:$PASSWORD" \
            --location $COUNTRY &
        ;;
        
    netnut)
        # NetNut configuration
        netnut-client \
            --port $PROXY_PORT \
            --destination $CLIENT_IP:$TARGET_PORT \
            --api-key $API_KEY &
        ;;
        
    custom|*)
        # Generic fallback - simple TCP forward
        socat TCP-LISTEN:$PROXY_PORT,fork,reuseaddr TCP:$CLIENT_IP:$TARGET_PORT &
        echo $! > /tmp/proxy-$PROXY_PORT.pid
        ;;
esac

echo "Proxy started successfully"
exit 0
