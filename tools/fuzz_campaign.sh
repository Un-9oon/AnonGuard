#!/bin/bash
set -e

echo "[+] Starting 24-hour AnonGuard Fuzzing Campaign..."
echo "[+] Target: fuzz_proxy_node_parse"
echo "[+] Duration: 86400 seconds (24 hours)"

# Run for 24 hours (86400 seconds)
# Uses multiple jobs if possible (-workers)
# Saves corpus to fuzz/corpus/fuzz_proxy_node_parse

cargo +nightly fuzz run fuzz_proxy_node_parse -- -max_total_time=86400 -workers=$(nproc)

echo "[+] Fuzzing campaign completed."
