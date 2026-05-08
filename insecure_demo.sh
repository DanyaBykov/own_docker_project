#!/bin/bash
# Unsandboxed server — for attack surface comparison tests only.
# NO namespaces, NO cgroups, NO seccomp, NO network isolation.
# The server runs as root inside a plain chroot.
# DO NOT use this in production.

set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo bash insecure_demo.sh"
    exit 1
fi

if [ ! -d "rootfs" ]; then
    echo "rootfs not found — run setup_rootfs.sh first"
    exit 1
fi

echo ""
echo "============================================================"
echo "  INSECURE SERVER — NO SANDBOXING"
echo "  For security testing only."
echo "  This process has FULL host access from inside the chroot."
echo "============================================================"
echo ""
echo "Connect a Minetest/Luanti client to:  localhost:30000"
echo "Port:  30000 (direct bind, no NAT)"
echo ""

# Mount proc and dev so the server can function normally
mount -t proc proc rootfs/proc 2>/dev/null || true
mount -t devtmpfs devtmpfs rootfs/dev 2>/dev/null || true

cleanup() {
    echo ""
    echo "Stopping insecure server..."
    umount rootfs/proc 2>/dev/null || true
    umount rootfs/dev  2>/dev/null || true
    echo "Done."
}
trap cleanup EXIT INT TERM

chroot rootfs minetestserver \
    --config /etc/luanti.conf \
    --world /var/luanti/world
