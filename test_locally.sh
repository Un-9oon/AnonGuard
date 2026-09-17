#!/bin/bash
set -e

echo "Building the project..."
cargo build

echo "Starting Tracker..."
cargo run -- --tracker --listen 127.0.0.1:8000 &
TRACKER_PID=$!
sleep 2

echo "Starting Relay 1..."
cargo run -- --relay --listen 127.0.0.1:9001 --fetch-from http://127.0.0.1:8000 &
RELAY1_PID=$!

echo "Starting Relay 2..."
cargo run -- --relay --listen 127.0.0.1:9002 --fetch-from http://127.0.0.1:8000 &
RELAY2_PID=$!

echo "Starting Relay 3..."
cargo run -- --relay --listen 127.0.0.1:9003 --fetch-from http://127.0.0.1:8000 &
RELAY3_PID=$!
sleep 3

echo "Starting Client Gateway..."
cargo run -- --listen 127.0.0.1:1080 --fetch-from http://127.0.0.1:8000 --onion &
GATEWAY_PID=$!
sleep 3

echo "Testing connection through the AnonGuard network..."
curl --socks5-hostname 127.0.0.1:1080 -s https://check.torproject.org/api/ip

echo -e "\n\nCleaning up..."
kill $GATEWAY_PID $RELAY3_PID $RELAY2_PID $RELAY1_PID $TRACKER_PID
