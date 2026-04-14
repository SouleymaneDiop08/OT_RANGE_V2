#!/bin/sh
# SCADA Station A — L1 (192.168.10.20), gateway R1-R3 = 192.168.10.254
ip route add 192.168.30.0/24 via 192.168.10.254 || true
ip route add 192.168.20.0/24 via 192.168.10.254 || true

exec "$@"
