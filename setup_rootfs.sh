#!/bin/bash

mkdir -p rootfs

if [ ! -f alpine-rootfs.tar.gz ]; then
    echo "Downloading rootfs..."
    wget -O alpine-rootfs.tar.gz https://dl-cdn.alpinelinux.org/alpine/v3.18/releases/x86_64/alpine-minirootfs-3.18.4-x86_64.tar.gz
fi

echo "Extracting rootfs..."
tar -xzf alpine-rootfs.tar.gz -C rootfs

echo "Done!"