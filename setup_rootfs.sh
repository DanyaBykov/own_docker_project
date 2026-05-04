#!/bin/bash

mkdir -p rootfs

if [ ! -f alpine-rootfs.tar.gz ]; then
    echo "Downloading Alpine rootfs..."
    wget -O alpine-rootfs.tar.gz https://dl-cdn.alpinelinux.org/alpine/v3.18/releases/x86_64/alpine-minirootfs-3.18.4-x86_64.tar.gz
fi

echo "Extracting rootfs..."
tar -xzf alpine-rootfs.tar.gz -C rootfs

echo "Done!"

echo "Preparing DNS for package installation..."
cp /etc/resolv.conf rootfs/etc/resolv.conf

# minetest-server: headless server binary; minetest-mineclone2: the only game in Alpine 3.18 repos
echo "Installing Minetest server..."
chroot rootfs /bin/sh -c "apk update && apk add minetest-server minetest-mineclone2"

echo "Creating world directory and server config..."
mkdir -p rootfs/var/luanti/world

cat > rootfs/etc/luanti.conf << 'EOF'
port = 30000
bind_address = 0.0.0.0
world_path = /var/luanti/world
default_game = mineclone2
enable_damage = false
creative_mode = false
server_name = Modbox Demo
server_description = Sandboxed Luanti server
EOF

echo "Luanti setup complete."