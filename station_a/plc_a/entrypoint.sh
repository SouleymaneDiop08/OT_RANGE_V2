#!/bin/bash
# PLC Station A — L1 (192.168.10.10), gateway R1-R3 = 192.168.10.254
echo "Configuration des routes PLC Station A..."
ip route add 192.168.30.0/24 via 192.168.10.254 || true
ip route add 192.168.20.0/24 via 192.168.10.254 || true

echo "Démarrage OpenPLC..."
exec ./start_openplc.sh
