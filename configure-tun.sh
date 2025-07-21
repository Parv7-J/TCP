#!/bin/bash

set -e

DEVICE="tun0"
IP_ADDRESS="10.0.0.1/24"

sysctl -w net.ipv6.conf.$DEVICE.disable_ipv6=1

ip link set dev $DEVICE up
# echo "$DEVICE is up for communication, ipv6 is set by default"
echo "$DEVICE is up for communication, ipv6 has been disabled"

ip addr add $IP_ADDRESS dev $DEVICE
echo "$DEVICE got ipv4 $IP_ADDRESS"