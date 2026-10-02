#!/bin/bash
# Soak test simulation script for AnonGuard
# This script continuously builds circuits and pumps traffic to test for resource leaks.

set -e

echo "[+] Starting soak test against local mesh"
echo "[+] Expected: Memory stays stable, FD limits are respected"

TARGET_IP="127.0.0.1"
SOCKS_PORT=9050

# We assume a 3-node mesh is already running. 

duration=7200 # 2 hours
end=$((SECONDS + duration))

circuits_built=0

while [ $SECONDS -lt $end ]; do
    # Perform a SOCKS5 request through the gateway
    # This will trigger circuit building
    if curl --socks5-hostname $TARGET_IP:$SOCKS_PORT http://1.1.1.1 -s --max-time 5 >/dev/null; then
        circuits_built=$((circuits_built+1))
        if [ $((circuits_built % 100)) -eq 0 ]; then
            echo "[*] Circuits built: $circuits_built"
        fi
    else
        echo "[!] SOCKS5 request failed. (Rate limit or circuit drop)"
        sleep 1
    fi
done

echo "[+] Soak test completed. $circuits_built circuits built."
