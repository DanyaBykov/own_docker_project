# Modbox Demo — Running Luanti in a Container

## Prerequisites

- Linux host with kernel 5.2+ (cgroups v2 required)
- Python 3.8+
- `iptables` and `iproute2` installed
- `libseccomp` installed: `sudo apt install libseccomp-dev` (Debian/Ubuntu)
- Root access (`sudo`)
- ~200 MB free disk space for the rootfs
- A Luanti client to connect (optional, for full demo)

---

## Step 1 — First-Time Setup

Run once to download Alpine Linux and install the Minetest server inside it:

```bash
sudo bash setup_rootfs.sh
```

This will:
1. Download Alpine 3.18 minirootfs (~5 MB)
2. Extract it to `./rootfs/`
3. Install `minetest` via `apk` (requires internet)
4. Create `/var/luanti/world/` and a server config at `/etc/luanti.conf`

Expected output ends with:
```
Luanti setup complete.
```

If you already have a `rootfs/` directory and just want to re-run from scratch:
```bash
sudo rm -rf rootfs
sudo bash setup_rootfs.sh
```

---

## Step 2 — Launch the Demo

```bash
sudo bash demo.sh
```

This starts a Minetest server inside the container with:
- 512 MB memory limit
- 80% CPU limit
- 64 process limit
- Port 30000 forwarded from host to container

Expected output:
```
Starting Minetest server inside Modbox container...
Connect a Minetest/Luanti client to:  localhost:30000
Resource limits: 512 MB RAM, 80% CPU, 64 processes

Seccomp filter loaded.
[...]   MultiCraft/Minetest Server listening on 0.0.0.0:30000
```

The server runs in the foreground. Press `Ctrl+C` to stop it — the container and all cgroups/network rules are cleaned up automatically.

---

## Step 3 — Connect a Client (Optional)

1. Install Minetest or Luanti on your machine
2. Open the game → **Play Online** or **Connect to server**
3. Host: `localhost`, Port: `30000`
4. Create a player name and connect

---

## Step 4 — Verify the Security Features

### Memory limit

In a second terminal while the container is running:

```bash
sudo python3 src/main.py --memory-limit 50 python3 src/stress.py memory
```

Expected: the process allocates ~50 MB then gets killed by the kernel OOM killer.

### CPU limit

```bash
sudo python3 src/main.py --cpu-limit 0.1 python3 src/stress.py cpu
```

Expected: the process runs but is throttled to 10% CPU. Check in a third terminal:
```bash
# Replace <PID> with the container PID printed by the stress script
cat /sys/fs/cgroup/sandbox_<PID>/cpu.stat
```
`usage_usec` should grow much slower than wall time.

### PID limit

```bash
sudo python3 src/main.py --pid-limit 10 python3 src/stress.py pid
```

Expected:
```
Spawned child 1: PID ...
Spawned child 2: PID ...
...
Fork blocked after N children — pids.max is working
```

### Network egress filtering

While the demo is running, in a second terminal try to reach the internet from inside the container:

```bash
sudo python3 src/main.py --port 9999:9999 /usr/bin/wget -q -O- http://example.com 2>&1; echo "exit: $?"
```

Expected: times out or `Connection refused` — `exit: 1`. The container cannot make arbitrary outbound connections; only port 30000 (UDP/TCP) and DNS are allowed.

---

## Troubleshooting

| Problem | Likely cause | Fix |
|---------|-------------|-----|
| `Error: rootfs folder not found` | setup not run | Run `sudo bash setup_rootfs.sh` |
| `mount: permission denied` | not running as root | Use `sudo` |
| `apk: not found` inside chroot | rootfs corrupt | Delete `rootfs/` and re-run setup |
| `Warning: could not load libseccomp` | library missing | `sudo apt install libseccomp-dev` |
| `ip: command not found` | iproute2 missing | `sudo apt install iproute2` |
| Port 30000 already in use | another server running | Kill it or change `--port 30001:30000` in `demo.sh` |
| Cgroup cleanup warning on exit | cgroup already gone | Harmless — ignore |

---

## Running Without the Demo Script

For custom usage:

```bash
sudo python3 src/main.py \
    --memory-limit <MB> \
    --cpu-limit <0.0-1.0> \
    --pid-limit <N> \
    --port <host_port>:<container_port> \
    <command> [args...]
```

Example — run a shell inside the container:
```bash
sudo python3 src/main.py /bin/sh
```

Example — run the server with a higher memory limit:
```bash
sudo python3 src/main.py \
    --memory-limit 1024 \
    --cpu-limit 1.0 \
    --pid-limit 128 \
    --port 30000:30000 \
    minetest --server --config /etc/luanti.conf
```
