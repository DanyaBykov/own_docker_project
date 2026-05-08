#!/bin/bash
# Unsandboxed server — for attack surface comparison tests only.

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

# Plant the flag on the host, outside the rootfs.
# The evil_mod will try to read this via /proc/1/root/ to escape the chroot.
FLAG_PATH="/tmp/modbox_flag.txt"
echo "FLAG{I_love_ozi}" > "$FLAG_PATH"
echo "Flag planted at $FLAG_PATH (host filesystem, outside chroot)"
echo ""

# Update the evil_mod and jit_disable mod in the persistent world directory.
mkdir -p rootfs/var/luanti/world/worldmods
rm -rf rootfs/var/luanti/world/worldmods/evilmod
cp -r src/evil_mod rootfs/var/luanti/world/worldmods/evilmod
rm -rf rootfs/var/luanti/world/worldmods/jit_disable
cp -r src/jit_disable rootfs/var/luanti/world/worldmods/jit_disable


echo "Connect a Minetest/Luanti client to:  localhost:30000"
echo "Port:  30000 (direct bind, no NAT)"
echo ""

mount -t proc proc rootfs/proc 2>/dev/null || true
mount -t devtmpfs devtmpfs rootfs/dev 2>/dev/null || true
mount -t tmpfs tmpfs rootfs/tmp 2>/dev/null || true

cleanup() {
    echo ""
    echo "Stopping insecure server..."
    umount rootfs/tmp  2>/dev/null || true
    umount rootfs/proc 2>/dev/null || true
    umount rootfs/dev  2>/dev/null || true
    rm -f "$FLAG_PATH"
    echo "Done."
}
trap cleanup EXIT INT TERM

chroot rootfs minetestserver \
    --config /etc/luanti.conf \
    --world /var/luanti/world \
    --gameid mineclone2
