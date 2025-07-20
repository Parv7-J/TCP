#!/bin/bash

# This command makes the script exit immediately if any command fails.
set -e

# --- Configuration ---
DEVICE="tun0"
IP_ADDRESS="10.0.0.1/24"
# ---------------------

echo "Configuring device: $DEVICE"

# 1. Bring the network interface online.
ip link set dev $DEVICE up

# 2. Assign the IP address to the interface.
ip addr add $IP_ADDRESS dev $DEVICE

echo "Device $DEVICE configured successfully with IP $IP_ADDRESS"