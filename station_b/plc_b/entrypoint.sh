#!/bin/bash
# PLC Station B — L2 (192.168.20.10), gateway R2-R3 = 192.168.20.254
echo "Configuration des routes PLC Station B..."
ip route add 192.168.30.0/24 via 192.168.20.254 || true
ip route add 192.168.10.0/24 via 192.168.20.254 || true

echo "Démarrage OpenPLC..."
exec ./start_openplc.sh
