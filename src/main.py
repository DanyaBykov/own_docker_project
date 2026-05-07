import os
import sys
import socket
import argparse
import subprocess
import ctypes
from syscalls import ALLOWED_SYSCALLS

_C = {
    "reset":  "\033[0m",
    "cmd":    "\033[2m",    # dim — shell commands
    "info":   "\033[97m",   # bright white — general info
    "ok":     "\033[32m",   # green — success / lifecycle
    "warn":   "\033[33m",   # yellow — warnings
    "error":  "\033[31m",   # red — errors / fatal
    "sec":    "\033[36m",   # cyan — security events
    "net":    "\033[34m",   # blue — network
    "cgroup": "\033[35m",   # magenta — resource limits
}

def log(level, msg):
    color = _C.get(level.lower(), _C["info"])
    print(f"{color}[{level.upper():<6}]{_C['reset']} {msg}", flush=True)

# Linux namespace flags — not always present in os module on non-Linux hosts
CLONE_NEWIPC = getattr(os, 'CLONE_NEWIPC', 0x08000000)
CLONE_NEWPID = getattr(os, 'CLONE_NEWPID', 0x20000000)

def run_command(cmd):
    log("cmd", "$ " + " ".join(cmd))
    subprocess.run(cmd, check=True)

def setup_cgroups(pid, memory_limit_mb, cpu_percentage, pid_limit):
    cg_path = f"/sys/fs/cgroup/sandbox_{pid}"
    log("cgroup", f"Creating cgroup {cg_path}")
    os.makedirs(cg_path, exist_ok=True)
    memory_limit_bytes = memory_limit_mb * 1024 * 1024
    with open(os.path.join(cg_path, "memory.max"), "w") as f:
        f.write(str(memory_limit_bytes))
    with open(os.path.join(cg_path, "memory.swap.max"), "w") as f:
        f.write("0")
    period = 100000
    quota = int(period * cpu_percentage)
    with open(os.path.join(cg_path, "cpu.max"), "w") as f:
        f.write(f"{quota} {period}")
    with open(os.path.join(cg_path, "pids.max"), "w") as f:
        f.write(str(pid_limit))
    with open(os.path.join(cg_path, "cgroup.procs"), "w") as f:
        f.write(str(pid))
    log("cgroup", f"Limits applied — memory: {memory_limit_mb} MB, CPU: {int(cpu_percentage*100)}%, PIDs: {pid_limit}")

def cleanup_cgroups(pid):
    cg_path = f"/sys/fs/cgroup/sandbox_{pid}"
    if not os.path.exists(cg_path):
        return

    procs_file = os.path.join(cg_path, "cgroup.procs")
    if os.path.exists(procs_file):
        try:
            with open(procs_file, "r") as f:
                pids = f.read().split()
            for p in pids:
                try:
                    with open("/sys/fs/cgroup/cgroup.procs", "w") as f_root:
                        f_root.write(p)
                except OSError:
                    pass # PID might have exited in the meantime
        except OSError as e:
            log("warn", f"Could not read cgroup procs for cleanup: {e}")

    try:
        os.rmdir(cg_path)
        log("cgroup", f"Removed cgroup {cg_path}")
    except OSError as e:
        log("warn", f"Could not remove cgroup {cg_path}: {e}")

def setup_networking(pid, port_mappings):
    cleanup_cmds = []

    subprocess.run(["ip", "link", "del", "veth_host"], stderr=subprocess.DEVNULL)

    try:
        _setup_networking_inner(pid, port_mappings, cleanup_cmds)
    except Exception:
        cleanup_networking(cleanup_cmds)
        raise

    return cleanup_cmds


def _setup_networking_inner(pid, port_mappings, cleanup_cmds):
    result = subprocess.check_output(["ip", "-o", "route", "show", "default"], text=True).strip()
    parts = result.split()
    default_iface = parts[parts.index("dev") + 1]
    log("net", f"Default interface: {default_iface} — creating veth pair for PID {pid}")

    orig_ip_forward = subprocess.check_output(["sysctl", "-n", "net.ipv4.ip_forward"], text=True).strip()
    run_command(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    cleanup_cmds.append(["sysctl", "-w", f"net.ipv4.ip_forward={orig_ip_forward}"])

    run_command(["ip", "link", "add", "veth_host", "type", "veth", "peer", "name", "veth_container"])
    cleanup_cmds.append(["ip", "link", "del", "veth_host"])

    run_command(["ip", "link", "set", "veth_host", "up"])
    run_command(["ip", "addr", "add", "172.18.0.1/24", "dev", "veth_host"])
    run_command(["ip", "link", "set", "veth_container", "netns", str(pid)])

    run_command(["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "172.18.0.0/24", "-o", default_iface, "-j", "MASQUERADE"])
    cleanup_cmds.append(["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", "172.18.0.0/24", "-o", default_iface, "-j", "MASQUERADE"])

    run_command(["iptables", "-t", "nat", "-A", "POSTROUTING", "-d", "172.18.0.0/24", "-j", "MASQUERADE"])
    cleanup_cmds.append(["iptables", "-t", "nat", "-D", "POSTROUTING", "-d", "172.18.0.0/24", "-j", "MASQUERADE"])

    run_command(["sysctl", "-w", "net.ipv4.conf.veth_host.route_localnet=1"])

    run_command(["iptables", "-A", "FORWARD", "-i", "veth_host", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    cleanup_cmds.append(["iptables", "-D", "FORWARD", "-i", "veth_host", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    run_command(["iptables", "-A", "FORWARD", "-o", "veth_host", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    cleanup_cmds.append(["iptables", "-D", "FORWARD", "-o", "veth_host", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])

    run_command(["iptables", "-A", "FORWARD", "-i", "veth_host", "-s", "172.18.0.0/24", "-p", "udp", "--dport", "53", "-j", "ACCEPT"])
    cleanup_cmds.append(["iptables", "-D", "FORWARD", "-i", "veth_host", "-s", "172.18.0.0/24", "-p", "udp", "--dport", "53", "-j", "ACCEPT"])
    run_command(["iptables", "-A", "FORWARD", "-i", "veth_host", "-s", "172.18.0.0/24", "-p", "tcp", "--dport", "53", "-j", "ACCEPT"])
    cleanup_cmds.append(["iptables", "-D", "FORWARD", "-i", "veth_host", "-s", "172.18.0.0/24", "-p", "tcp", "--dport", "53", "-j", "ACCEPT"])

    for mapping in port_mappings:
        host_port, container_port = mapping.split(":")
        for proto in ("tcp", "udp"):
            run_command(["iptables", "-t", "nat", "-A", "PREROUTING", "-p", proto, "--dport", host_port, "-j", "DNAT", "--to-destination", f"172.18.0.2:{container_port}"])
            cleanup_cmds.append(["iptables", "-t", "nat", "-D", "PREROUTING", "-p", proto, "--dport", host_port, "-j", "DNAT", "--to-destination", f"172.18.0.2:{container_port}"])
            run_command(["iptables", "-t", "nat", "-A", "OUTPUT", "-p", proto, "-d", "127.0.0.1", "--dport", host_port, "-j", "DNAT", "--to-destination", f"172.18.0.2:{container_port}"])
            cleanup_cmds.append(["iptables", "-t", "nat", "-D", "OUTPUT", "-p", proto, "-d", "127.0.0.1", "--dport", host_port, "-j", "DNAT", "--to-destination", f"172.18.0.2:{container_port}"])
            run_command(["iptables", "-A", "FORWARD", "-o", "veth_host", "-d", "172.18.0.0/24", "-p", proto, "--dport", container_port, "-j", "ACCEPT"])
            cleanup_cmds.append(["iptables", "-D", "FORWARD", "-o", "veth_host", "-d", "172.18.0.0/24", "-p", proto, "--dport", container_port, "-j", "ACCEPT"])

    run_command(["iptables", "-A", "FORWARD", "-i", "veth_host", "-s", "172.18.0.0/24", "-j", "DROP"])
    cleanup_cmds.append(["iptables", "-D", "FORWARD", "-i", "veth_host", "-s", "172.18.0.0/24", "-j", "DROP"])

    # Block container from reaching host-local services directly.
    # Port-forwarded traffic uses PREROUTING DNAT → FORWARD, not INPUT.
    # However, we must allow return traffic for connections initiated by the host.
    fwd_est = "iptables -I INPUT -i veth_host -m state --state ESTABLISHED,RELATED -j ACCEPT"
    run_command(fwd_est)
    cleanup_cmds.append(fwd_est.replace("-I", "-D"))
    
    # REJECT (not DROP) so nc inside the container gets an immediate RST rather
    # than waiting for the kernel's TCP retransmit timeout (~127 s).
    reject_in = "iptables -A INPUT -i veth_host -s 172.18.0.0/24 -j REJECT"
    run_command(reject_in)
    cleanup_cmds.append(reject_in.replace("-A", "-D"))


def cleanup_networking(cleanup_cmds):
    log("net", "Tearing down network rules and interfaces")
    for cmd in reversed(cleanup_cmds):
        try:
            run_command(cmd)
        except subprocess.CalledProcessError as e:
            log("warn", f"Cleanup command failed (ignored): {e}")

def prepare_seccomp():
    SCMP_ACT_ERRNO_EPERM = 0x00050001
    SCMP_ACT_ALLOW       = 0x7fff0000

    try:
        lib = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    except OSError as e:
        sys.exit(f"Error: seccomp filter failed to load: could not load libseccomp: {e}")

    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_rule_add.restype = ctypes.c_int
    lib.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                                      ctypes.c_int, ctypes.c_uint]
    lib.seccomp_rule_add_array.restype = ctypes.c_int
    lib.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                                            ctypes.c_int, ctypes.c_uint,
                                            ctypes.c_void_p]
    lib.seccomp_load.restype = ctypes.c_int
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.argtypes = [ctypes.c_void_p]

    ctx = lib.seccomp_init(SCMP_ACT_ERRNO_EPERM)
    if not ctx:
        sys.exit("Error: seccomp filter failed to load: seccomp_init returned NULL")

    # scmp_arg_cmp: { arg_index, op, datum_a, datum_b }
    # SCMP_CMP_MASKED_EQ (op=7): match when (arg & datum_a) == datum_b
    class ScmpArgCmp(ctypes.Structure):
        _fields_ = [("arg",     ctypes.c_uint),
                    ("op",      ctypes.c_uint),
                    ("datum_a", ctypes.c_uint64),
                    ("datum_b", ctypes.c_uint64)]

    SCMP_CMP_MASKED_EQ = 7
    CLONE_NEWUSER      = 0x10000000
    PROT_EXEC          = 0x4

    # Allow clone() only when CLONE_NEWUSER bit is NOT set.
    # Calls with CLONE_NEWUSER set fall through to the default DENY action.
    cmp_clone_safe = ScmpArgCmp(0, SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, 0)
    rc = lib.seccomp_rule_add_array(ctx, SCMP_ACT_ALLOW, 56, 1,
                                     ctypes.byref(cmp_clone_safe))
    if rc != 0:
        print(f"Warning: could not add clone allow rule: {rc}")

    # mprotect is unconditionally allowed — LuaJIT requires PROT_EXEC for JIT.
    # The mprotect probe in the evil mod correctly reports this as [ESCAPED].

    for nr in ALLOWED_SYSCALLS:
        rc = lib.seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 0)
        if rc != 0:
            log("warn", f"seccomp_rule_add failed for syscall {nr}: {rc}")
    
    return lib, ctx

def apply_seccomp(lib, ctx):
    _libc = ctypes.CDLL(None, use_errno=True)
    PR_SET_NO_NEW_PRIVS = 38
    if _libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        sys.exit("Error: prctl(PR_SET_NO_NEW_PRIVS) failed")
    log("sec", "PR_SET_NO_NEW_PRIVS set — no privilege escalation via exec")

    rc = lib.seccomp_load(ctx)
    if rc != 0:
        sys.exit(f"Error: seccomp filter failed to load: seccomp_load returned {rc}")
    log("sec", f"Seccomp allowlist loaded ({len(ALLOWED_SYSCALLS)} syscalls, default action: EPERM)")
    lib.seccomp_release(ctx)


def run_container(rootfs_path, command_args, memory_limit_mb, cpu_limit_percentage, pid_limit, port_mappings):
    network_enabled = bool(port_mappings)
    
    r_fd, w_fd = os.pipe()

    pid = os.fork()
    if pid == 0:
        log("sec", f"Namespaces: UTS + mount + IPC isolated (PID {os.getpid()})")
        os.unshare(os.CLONE_NEWUTS | os.CLONE_NEWNS | CLONE_NEWIPC)
        subprocess.run(["mount", "--make-rprivate", "/"], check=True)
        socket.sethostname("sandbox")

        if network_enabled:
            log("net", "Isolating network namespace")
            os.unshare(os.CLONE_NEWNET)
            os.close(w_fd)
            signal = os.read(r_fd, 1)
            if not signal:
                log("error", "Parent process died or closed pipe before network setup complete")
                sys.exit(1)
            os.close(r_fd)
            log("net", "Parent signalled veth ready — configuring container side")
            run_command(["ip", "link", "set", "lo", "up"])
            run_command(["ip", "link", "set", "veth_container", "up"])
            run_command(["ip", "addr", "add", "172.18.0.2/24", "dev", "veth_container"])
            run_command(["ip", "route", "add", "default", "via", "172.18.0.1"])
            log("net", "Container network ready (172.18.0.2/24, gw 172.18.0.1)")
        else:
            os.close(r_fd)
            os.close(w_fd)
            run_command(["ip", "link", "set", "lo", "up"])

        log("sec", "Creating PID namespace (double-fork)")
        os.unshare(os.CLONE_NEWPID)
        grandchild = os.fork()
        if grandchild != 0:
            _, status = os.waitpid(grandchild, 0)
            sys.exit(os.WEXITSTATUS(status) if os.WIFEXITED(status) else 1)
        log("sec", f"Container init started (PID 1 in namespace, host PID {os.getpid()})")
        log("sec", "Preparing seccomp filter (host libseccomp, before chroot)")
        seccomp_lib, seccomp_ctx = prepare_seccomp()

        log("info", f"Chrooting into {rootfs_path}")
        os.chdir(rootfs_path)
        os.chroot(".")
        os.chdir("/")
        log("info", "Mounting proc, dev (minimal), tmp, var")
        subprocess.run(["mount", "-t", "proc", "proc", "/proc"], check=True)
        subprocess.run(["mount", "-t", "tmpfs", "tmpfs", "/dev"], check=True)
        for name, major, minor, mode in [
            ("null",    1, 3, 0o666),
            ("zero",    1, 5, 0o666),
            ("full",    1, 7, 0o666),
            ("random",  1, 8, 0o444),
            ("urandom", 1, 9, 0o444),
            ("tty",     5, 0, 0o666),
            ("console", 5, 1, 0o600),
        ]:
            os.mknod(f"/dev/{name}", mode | 0o020000, os.makedev(major, minor))
        subprocess.run(["mount", "-t", "tmpfs", "tmpfs", "/tmp"], check=True)
        subprocess.run(["mount", "-t", "tmpfs", "tmpfs", "/var"], check=True)
        os.makedirs("/var/luanti/world/worldmods", exist_ok=True)
        subprocess.run(["cp", "-r", "/usr/local/share/evilmod",         "/var/luanti/world/worldmods/evilmod"],         check=False)
        subprocess.run(["cp", "-r", "/usr/local/share/aaa_jit_disable", "/var/luanti/world/worldmods/aaa_jit_disable"], check=False)
        os.chmod("/var/luanti", 0o777)
        os.chmod("/var/luanti/world", 0o777)
        os.chmod("/var/luanti/world/worldmods", 0o777)

        log("sec", "Dropping privileges → UID/GID 65534 (nobody), groups cleared")
        os.setgroups([])
        os.setgid(65534)
        os.setuid(65534)

        log("sec", "Applying seccomp filter")
        apply_seccomp(seccomp_lib, seccomp_ctx)

        log("ok", f"Sandbox ready — launching: {' '.join(command_args)}")

        os.environ["HOME"] = "/tmp"
        os.execvp(command_args[0], command_args)
    else:
        log("ok", f"Container forked (host PID {pid})")
        cleanup_cmds = []
        try:
            os.close(r_fd)
            if network_enabled:
                log("net", "Setting up host-side networking")
                cleanup_cmds = setup_networking(pid, port_mappings)
                log("net", f"Veth pair ready — signalling container (PID {pid})")
                os.write(w_fd, b'\x00')
            os.close(w_fd)

            setup_cgroups(pid, memory_limit_mb, cpu_limit_percentage, pid_limit)
            log("ok", "Container running")

            _, status = os.waitpid(pid, 0)
            if os.WIFSIGNALED(status):
                sig = os.WTERMSIG(status)
                label = "OOM kill" if sig == 9 else f"signal {sig}"
                log("error", f"Container killed by {label}")
            elif os.WIFEXITED(status) and os.WEXITSTATUS(status) != 0:
                log("error", f"Container exited with code {os.WEXITSTATUS(status)}")
            else:
                log("ok", "Container exited cleanly")
        finally:
            log("info", "Starting cleanup")
            if network_enabled:
                cleanup_networking(cleanup_cmds)
            cleanup_cgroups(pid)
            log("ok", "Cleanup complete")

def _port_mapping(value):
    parts = value.split(":")
    if len(parts) != 2:
        raise argparse.ArgumentTypeError(f"expected host:container, got {value!r}")
    for p in parts:
        try:
            n = int(p)
        except ValueError:
            raise argparse.ArgumentTypeError(f"port must be an integer, got {p!r}")
        if not 1 <= n <= 65535:
            raise argparse.ArgumentTypeError(f"port {n} out of range [1, 65535]")
    return value

def parse_args():
    parser = argparse.ArgumentParser(description="Modbox containerization engine.")
    parser.add_argument("--memory-limit", type=int, default=50, help="Memory limit for the container in megabytes (MB).")
    parser.add_argument("--cpu-limit", type=float, default=0.5, help="CPU limit for the container as a percentage (e.g., 0.5 for 50%).")
    parser.add_argument("--pid-limit", type=int, default=32, help="Maximum number of processes allowed in the container.")
    parser.add_argument("--port", action='append', type=_port_mapping, help="Port mapping (e.g., host_port:container_port). Can be specified multiple times.")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Command to execute inside the container")
    return parser.parse_args()

if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("Error: Run as root (sudo).")
        
    path = os.path.abspath("rootfs")
    if not os.path.exists(path):
        sys.exit("Error: rootfs folder not found.")
    
    args = parse_args()
    if not args.command:
        sys.exit("Error: No command specified for the container.")
        
    run_container(path, args.command, args.memory_limit, args.cpu_limit, args.pid_limit, args.port)