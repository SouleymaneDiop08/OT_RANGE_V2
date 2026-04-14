#!/bin/sh
# SCADA Station B — L2 (192.168.20.20), gateway R2-R3 = 192.168.20.254
ip route add 192.168.30.0/24 via 192.168.20.254 || true
ip route add 192.168.10.0/24 via 192.168.20.254 || true

exec "$@"
