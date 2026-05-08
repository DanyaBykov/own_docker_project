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

rm -rf rootfs/usr/local/share/evilmod
cp -r src/evil_mod rootfs/usr/local/share/evilmod

rm -rf rootfs/usr/local/share/jit_disable
cp -r src/jit_disable rootfs/usr/local/share/jit_disable

# Prepend jit.off() to the earliest Lua hook so LuaJIT never attempts to
# allocate its JIT arena (mmap RWX), which the seccomp W^X filter blocks.
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

# Disable weather cycling — irrelevant to the security probe demo.
# Without this, weather changes every 10–150 minutes and clutters the output.
if ! grep -q "mcl_doWeatherCycle" rootfs/etc/luanti.conf; then
    echo "mcl_doWeatherCycle = false" >> rootfs/etc/luanti.conf
fi
if ! grep -q "time_speed" rootfs/etc/luanti.conf; then
    echo "time_speed = 0" >> rootfs/etc/luanti.conf
fi

# Fix weather_core.lua: set_random_weather didn't update end_time when no
# transition matched (roll==100 for a <100 boundary), causing a 5-second
# tight retry loop.  Patch idempotently — skip if already applied.
WC="rootfs/usr/share/minetest/games/mineclone2/mods/ENVIRONMENT/mcl_weather/weather_core.lua"
if grep -q "if new_weather then" "$WC" && ! grep -q "No transition matched" "$WC"; then
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
else:
    print("weather_core.lua patch skipped (already applied or structure changed)")
PYEOF
fi

python3 src/main.py \
    --memory-limit 4096 \
    --cpu-limit 0.8 \
    --pid-limit 64 \
    --port 30000:30000 \
    minetestserver --config /etc/luanti.conf --world /var/luanti/world
