#!/bin/bash
set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo bash demo.sh"
    exit 1
fi

if [ ! -d "rootfs" ]; then
    echo "rootfs not found — running setup..."
    bash setup_rootfs.sh
fi

echo ""
echo "Starting Minetest server inside Modbox container..."
echo "Connect a Minetest/Luanti client to:  localhost:30000"
echo "Resource limits: 4096 MB RAM, 80% CPU, 64 processes"
echo ""

python3 src/main.py \
    --memory-limit 4096 \
    --cpu-limit 0.8 \
    --pid-limit 64 \
    --port 30000:30000 \
    minetestserver --config /etc/luanti.conf
