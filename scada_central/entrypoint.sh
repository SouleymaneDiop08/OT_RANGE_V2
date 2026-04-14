#!/bin/sh
# SCADA Central — L3 (192.168.30.10)
# L1 via R1-R3, L2 via R2-R3
ip route add 192.168.10.0/24 via 192.168.30.254 || true
ip route add 192.168.20.0/24 via 192.168.30.253 || true

exec "$@"
