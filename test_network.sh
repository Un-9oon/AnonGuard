#!/bin/bash
set -e

echo "Starting Tracker..."
./target/release/anonguard-daemon --tracker --listen 127.0.0.1:8080 > tracker.log 2>&1 &
TRACKER_PID=$!
sleep 1

echo "Starting Relay 1 (Port 1081)..."
./target/release/anonguard-daemon --relay --listen 127.0.0.1:1081 --announce http://127.0.0.1:8080 > relay1.log 2>&1 &
RELAY1_PID=$!

echo "Starting Relay 2 (Port 1082)..."
./target/release/anonguard-daemon --relay --listen 127.0.0.1:1082 --announce http://127.0.0.1:8080 > relay2.log 2>&1 &
RELAY2_PID=$!

echo "Starting Relay 3 (Port 1083)..."
./target/release/anonguard-daemon --relay --listen 127.0.0.1:1083 --announce http://127.0.0.1:8080 > relay3.log 2>&1 &
RELAY3_PID=$!

echo "Waiting for relays to register..."
sleep 2

echo "Starting Client (Port 9050)..."
./target/release/anonguard-daemon --listen 127.0.0.1:9050 --fetch-from http://127.0.0.1:8080 > client.log 2>&1 &
CLIENT_PID=$!

echo "Waiting for client to fetch nodes..."
sleep 2

echo "Testing connection through Onion Network via curl..."
curl -s -x socks5h://127.0.0.1:9050 https://httpbin.org/ip

echo "Test complete. Cleaning up..."
kill $TRACKER_PID $RELAY1_PID $RELAY2_PID $RELAY3_PID $CLIENT_PID
