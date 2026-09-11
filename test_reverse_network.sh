#!/bin/bash
set -e

echo "Starting Rendezvous Tracker..."
./target/release/anonguard-daemon --tracker --listen 127.0.0.1:8080 > tracker_rev.log 2>&1 &
TRACKER_PID=$!
sleep 1

echo "Starting Volunteer Reverse Relay 1 (Behind NAT)..."
./target/release/anonguard-daemon --reverse-relay --announce http://127.0.0.1:8080 > relay1_rev.log 2>&1 &
RELAY1_PID=$!

echo "Waiting for relay to register..."
sleep 2

echo "Starting Client (Port 9050)..."
./target/release/anonguard-daemon --listen 127.0.0.1:9050 --fetch-from http://127.0.0.1:8080 > client_rev.log 2>&1 &
CLIENT_PID=$!

echo "Waiting for client to fetch nodes..."
sleep 5

echo "Testing connection through Reverse Onion Network via curl..."
curl -s -x socks5h://127.0.0.1:9050 https://httpbin.org/ip

echo "Test complete. Cleaning up..."
kill $TRACKER_PID $RELAY1_PID $CLIENT_PID
