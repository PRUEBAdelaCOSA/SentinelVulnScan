#!/bin/bash

echo "Starting SentinelVulnScan Test Environment"

echo
echo "[1/2] Starting VulnerableTestServer..."
cd "$PWD/VulnerableTestServer" && dotnet run &
SERVER_PID=$!

echo
echo "Waiting for server to start..."
sleep 5

echo
echo "[2/2] Running SentinelVulnScan against the vulnerable server..."
echo
cd "$PWD/src/SentinelVulnScan"
dotnet run --test-local

echo
echo "Test completed. The vulnerable server is still running."
echo "Press Enter to close the vulnerable server or Ctrl+C to exit and leave it running."
read

echo "Stopping the vulnerable server..."
kill $SERVER_PID
