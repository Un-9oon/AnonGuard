#!/usr/bin/env bash
set -euo pipefail

PCAP_FILE="/tmp/anonguard_capture.pcap"
rm -f "$PCAP_FILE"

echo "[1/5] Starting sudo tcpdump live packet capture on loopback..."
echo '4dam.3v3' | sudo -S tcpdump -i lo -nn -s0 -w "$PCAP_FILE" 'port 18080 or port 19080' >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1

echo "[2/5] Running AnonGuard packet inspection and kill switch test..."
python3 /home/we/AnonGuard/research_benchmarks/packet_verifier.py

echo "[3/5] Stopping packet capture..."
sleep 1
echo '4dam.3v3' | sudo -S kill -INT "$TCPDUMP_PID" 2>/dev/null || true
sleep 1

echo "[4/5] Captured PCAP Summary via tshark:"
echo "-----------------------------------------------------------------"
echo '4dam.3v3' | sudo -S tshark -r "$PCAP_FILE" -c 25
echo "-----------------------------------------------------------------"

echo "[5/5] Detailed HTTP Packet Analysis (Source IP, Method, URI, Leak Headers):"
echo "-----------------------------------------------------------------"
echo '4dam.3v3' | sudo -S tshark -r "$PCAP_FILE" -Y "http.request" -T fields \
    -e frame.number \
    -e ip.src \
    -e tcp.srcport \
    -e ip.dst \
    -e tcp.dstport \
    -e http.request.method \
    -e http.request.uri \
    -e http.user_agent \
    -e http.x_forwarded_for
echo "-----------------------------------------------------------------"

echo "[✓] Packet capture and verification completed successfully!"
