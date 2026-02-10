#!/usr/bin/env bash
#
# Port Knocking Demo Script
# Assignment 2: Network Security
#
# Demonstrates the port knocking system:
# 1. Shows the protected port is blocked before knocking
# 2. Performs the knock sequence
# 3. Shows the protected port is now accessible
#
# Usage:
#   ./demo.sh [target_ip] [sequence] [protected_port]
#   ./demo.sh 172.20.0.40 1234,5678,9012 2222

set -euo pipefail

TARGET_IP=${1:-172.20.0.40}
SEQUENCE=${2:-"1234,5678,9012"}
PROTECTED_PORT=${3:-2222}

echo "=============================================="
echo "  Port Knocking Demo"
echo "=============================================="
echo ""
echo "  Target:          $TARGET_IP"
echo "  Knock Sequence:  $SEQUENCE"
echo "  Protected Port:  $PROTECTED_PORT"
echo ""

echo "----------------------------------------------"
echo "[1/3] Attempting to connect to protected port BEFORE knocking"
echo "----------------------------------------------"
echo "  Trying to connect to $TARGET_IP:$PROTECTED_PORT ..."
if nc -z -w 2 "$TARGET_IP" "$PROTECTED_PORT" 2>/dev/null; then
    echo "  [!] Port is already open (unexpected)"
else
    echo "  [-] Connection FAILED - port is blocked (expected)"
fi
echo ""

echo "----------------------------------------------"
echo "[2/3] Sending knock sequence: $SEQUENCE"
echo "----------------------------------------------"
python3 knock_client.py --target "$TARGET_IP" --sequence "$SEQUENCE" --delay 0.5
echo ""

echo "----------------------------------------------"
echo "[3/3] Attempting to connect to protected port AFTER knocking"
echo "----------------------------------------------"
echo "  Trying to connect to $TARGET_IP:$PROTECTED_PORT ..."
sleep 1
if nc -z -w 2 "$TARGET_IP" "$PROTECTED_PORT" 2>/dev/null; then
    echo "  [+] Connection SUCCEEDED - port is now open!"
    echo ""
    echo "  You can now connect to the service:"
    echo "    ssh sshuser@$TARGET_IP -p $PROTECTED_PORT"
else
    echo "  [-] Connection FAILED"
    echo "  (If running in demo mode without iptables, this is expected)"
fi

echo ""
echo "=============================================="
echo "  Demo Complete"
echo "=============================================="