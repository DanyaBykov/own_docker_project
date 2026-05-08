# Modbox: Our own engine for containerization based on Namespaces and Cgroups
**Authors:** [Danylo Bykov](https://github.com/DanyaBykov), [Ivan Shevchuk](https://github.com/DoktorTomato)

## Usage

To run a command inside the Modbox container:

```bash
sudo python src/main.py [options] <command> [args...]
```

### Examples

```bash
# Run a shell with default limits
sudo python src/main.py /bin/sh

# Run a command with a 256MB memory limit
sudo python src/main.py --memory-limit 256 ls -la /

# Run a command with a 10% CPU limit and 16 max processes
sudo python src/main.py --cpu-limit 0.1 --pid-limit 16 echo "Hello"
```

## 1. Practical understanding of theme/problem

### 1.а. Where can we use this?
The problem we are trying to solve is widely seen in the game servers hosting. A lot of games (Minecraft, Garry's Mod, Barotrauma) support server modifications that are created using script languages (Lua, Java, etc.). When the admin of any server install mod for a game from the internet, he can basically run untrusted code on his machine. This code can contain an exploit to get out of the limits of game engine, which can compromise the entire system. The same can be easily said for a regular gamer who can unknowingly install a malicious mod. Thus, by creating this kind of engine, we can provide a tool for any gamedeveloper to provide safety for players.

### 1.б. Who needs it?
- Gaming servers hosting providers
- Admins of community-servers
- Game devs who want to support mods

### 1.в. Already existing solutions

From what we researched there are no solutions that try to solve this exact problem. But sandboxing and containerization with the tools listed below can be easily used and seen as an example.

- Docker/Podman
- LXC (Linux Containers)
- Firecracker/gVisor


## 2. High level solution

### 2.а. How should it idealy work
In an ideal environment, this would be a comprehensive rootless orchestration system (running without superuser rights at all). It would include:
1. Full isolation using microVMs instead of regular containers.
2. Dynamic system call filtering, which would automatically analyze game server behavior patterns and block malicious system calls in real time.
3. Some kind of integrated mod analyzer to detect malicious code even before the container is launched.
4. A convenient web panel or other form of UI to monitor sandbox exit attempts.

### 2.б. How do we do it in our project
For this project we develop a Python script, that acts as a launcher for the process (for example our game server or game session). 

We will have three main parts:
1. Isolation (using Namespaces)
2. Resource Limitation (Cgroups v2)
3. Rootfs preparation and execution

### 2.в. Security
**The solution will defend from:**
- Malicious Filesystem Traversal
- DoS attacks
- Unwanted network conections

**The solution will not defend from:**
- Kernel Exploits
- Ingame hacks
- DDoS-attacks

## Running the Demos

### Prerequisites

```bash
sudo apt install iproute2 iptables libseccomp-dev python3
```

### First-time setup

Run once to download Alpine Linux, install the Minetest server, and create the world directory:

```bash
sudo bash setup_rootfs.sh
```

---

### Demo 1 — Sandboxed server (normal use)

Starts the Minetest server inside the full Modbox sandbox: isolated namespaces (UTS, mount, network, PID), cgroups resource limits, seccomp syscall filter, and iptables network rules.

```bash
sudo bash demo.sh
```

Connect a Minetest/Luanti client to `localhost:30000`.

Press `Ctrl+C` to stop — all namespaces, iptables rules, and cgroups are cleaned up automatically.

---

### Demo 2 — Unsandboxed server (attack surface testing)

Starts the **same** server binary inside a plain chroot with **no** isolation whatsoever: no namespaces, no cgroups, no seccomp, no network filtering. Use this to verify that attacks blocked by the sandbox succeed against an unprotected server.

```bash
sudo bash insecure_demo.sh
```

> **Warning:** this server runs as root with full host access. Use only in a controlled test environment.

---

### Installing mods

Place mod folders inside the world's `worldmods/` directory — the server auto-loads them on startup:

```bash
sudo mkdir -p rootfs/var/luanti/world/worldmods
sudo unzip /tmp/yourmod.zip -d rootfs/var/luanti/world/worldmods/
# The extracted folder must be named exactly as the mod's `name` field in mod.conf
```

If a mod has dependencies, install each dependency the same way.

---

### Running the security test suite

```bash
echo "HOST_FLAG" | sudo tee /tmp/flag.txt
sudo python3 src/main.py python3 /src/security_test.py
```

Every line should show `[CONTAINED]`. Any `[ESCAPED]` indicates a sandbox vulnerability.

---

## 3. What have we already done

We have done a simple container that uses alpine-minirootfs as an rootfs image, namespaces and Cgroups for isolation and resource limitation. It still needs a lot of work on security, but it is a solid base
