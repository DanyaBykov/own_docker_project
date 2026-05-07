#!/bin/bash
set -e

mkdir -p rootfs

ALPINE_VERSION="3.21.7"
ALPINE_TARBALL="alpine-minirootfs-${ALPINE_VERSION}-x86_64.tar.gz"
ALPINE_URL="https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/x86_64/${ALPINE_TARBALL}"
ALPINE_SHA256="8cba1ea3e8b500ea986a313d8eecf3d5952a2a0d23a69117bb81c023d9ceac05"

if [ ! -f "$ALPINE_TARBALL" ]; then
    echo "Downloading Alpine rootfs ${ALPINE_VERSION}..."
    curl -L -o "$ALPINE_TARBALL" "$ALPINE_URL"
fi

echo "Verifying SHA256 checksum..."
echo "${ALPINE_SHA256}  ${ALPINE_TARBALL}" | sha256sum -c -

echo "Extracting rootfs..."
rm -rf rootfs/*
tar -xzf "$ALPINE_TARBALL" -C rootfs

echo "Done!"

echo "Preparing DNS for package installation..."
cp /etc/resolv.conf rootfs/etc/resolv.conf

# minetest-server: headless server binary; minetest-mineclone2: the only game in Alpine repos
# libseccomp: required by the host's seccomp filter (loaded via ctypes inside the chroot)
# python3: required for running security tests inside the container
echo "Installing packages..."
chroot rootfs /bin/sh -c "apk update && apk add minetest-server minetest-mineclone2 libseccomp python3"

echo "Copying test scripts into rootfs..."
mkdir -p rootfs/src
cp src/security_test.py rootfs/src/security_test.py
cp src/stress.py rootfs/src/stress.py

echo "Creating world directory, server config, and evil mod..."
mkdir -p rootfs/var/luanti/world/worldmods

cat > rootfs/etc/luanti.conf << 'EOF'
port = 30000
bind_address = 0.0.0.0
world_path = /var/luanti/world
default_game = mineclone2
enable_damage = false
creative_mode = false
server_name = Modbox Demo
server_description = Sandboxed Luanti server
secure.trusted_mods = evilmod
secure.http_mods = evilmod
EOF

cp -r src/evil_mod rootfs/var/luanti/world/worldmods/evilmod

echo "Luanti setup complete."