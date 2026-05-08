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

echo "Installing packages..."
chroot rootfs /bin/sh -c "apk update && apk add minetest-server libseccomp python3"

MINECLONE2_ZIP="mineclone2-0.91.2.zip"
MINECLONE2_URL="https://content.luanti.org/uploads/9f65a9135f.zip"
MINECLONE2_DEST="rootfs/usr/share/minetest/games/mineclone2"

echo "Downloading MineClone2 0.91.2..."
if [ ! -f "$MINECLONE2_ZIP" ]; then
    curl -L -o "$MINECLONE2_ZIP" "$MINECLONE2_URL"
fi

rm -rf "$MINECLONE2_DEST"
mkdir -p "$(dirname "$MINECLONE2_DEST")"
python3 - "$MINECLONE2_ZIP" "$MINECLONE2_DEST" <<'PYEOF'
import zipfile, sys, os, shutil
zip_path, dest = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(zip_path) as zf:
    zf.extractall("/tmp/mc2_extract")
entries = os.listdir("/tmp/mc2_extract")
src = os.path.join("/tmp/mc2_extract", entries[0]) if len(entries) == 1 else "/tmp/mc2_extract"
shutil.copytree(src, dest)
shutil.rmtree("/tmp/mc2_extract")
print(f"MineClone2 installed at {dest}")
PYEOF

echo "Copying test scripts into rootfs..."
mkdir -p rootfs/src
cp src/security_test.py rootfs/src/security_test.py
cp src/stress.py rootfs/src/stress.py

echo "Creating server config and staging evil mod..."
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
mcl_doWeatherCycle = false
time_speed = 0
EOF

WC="rootfs/usr/share/minetest/games/mineclone2/mods/ENVIRONMENT/mcl_weather/weather_core.lua"
python3 - "$WC" <<'PYEOF'
import sys
path = sys.argv[1]
old = (
    "\tif new_weather then\n"
    "\t\tmcl_weather.change_weather(new_weather)\n"
    "\tend\n"
    "end"
)
new = (
    "\tif new_weather then\n"
    "\t\tmcl_weather.change_weather(new_weather)\n"
    "\telse\n"
    "\t\t-- No transition matched: postpone so globalstep doesn't retry every 5 s.\n"
    "\t\tlocal meta = mcl_weather.reg_weathers[weather_name]\n"
    "\t\tmcl_weather.end_time = mcl_weather.get_rand_end_time(\n"
    "\t\t\tmeta and meta.min_duration, meta and meta.max_duration)\n"
    "\tend\n"
    "end"
)
with open(path) as f:
    content = f.read()
if old in content:
    with open(path, "w") as f:
        f.write(content.replace(old, new, 1))
    print("Patched weather_core.lua")
PYEOF

rm -rf rootfs/usr/local/share/evilmod
mkdir -p rootfs/usr/local/share
cp -r src/evil_mod rootfs/usr/local/share/evilmod

rm -rf rootfs/usr/local/share/jit_disable
cp -r src/jit_disable rootfs/usr/local/share/jit_disable

BUILTIN="rootfs/usr/share/minetest/builtin/init.lua"
if ! grep -q "^jit\.off()" "$BUILTIN"; then
    python3 - "$BUILTIN" <<'PYEOF'
import sys
path = sys.argv[1]
with open(path) as f:
    content = f.read()
with open(path, 'w') as f:
    f.write('jit.off()\n' + content)
print("Patched builtin/init.lua with jit.off()")
PYEOF
fi

echo "Luanti setup complete."
