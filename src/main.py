import os
import sys
import socket
import argparse
import subprocess
import ctypes

def run_command(cmd):
    print(f"Executing: {cmd}")
    subprocess.run(cmd, shell=True, check=True)

def setup_cgroups(pid, memory_limit_mb, cpu_percentage, pid_limit):
    cg_path = f"/sys/fs/cgroup/sandbox_{pid}"
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

def cleanup_cgroups(pid):
    cg_path = f"/sys/fs/cgroup/sandbox_{pid}"
    if not os.path.exists(cg_path):
        return
    try:
        with open("/sys/fs/cgroup/cgroup.procs", "w") as f:
            f.write(str(os.getpid()))
    except OSError as e:
        print(f"Warning: could not drain cgroup procs: {e}")
    try:
        os.rmdir(cg_path)
        print(f"Cleaned up cgroup: {cg_path}")
    except OSError as e:
        print(f"Warning: could not remove cgroup {cg_path}: {e}")

def setup_networking(pid, port_mappings):
    cleanup_cmds = []

    # Delete any leftover veth from a previous crashed run — safe to ignore failure.
    subprocess.run("ip link del veth_host", shell=True, stderr=subprocess.DEVNULL)

    try:
        _setup_networking_inner(pid, port_mappings, cleanup_cmds)
    except Exception:
        cleanup_networking(cleanup_cmds)
        raise

    return cleanup_cmds


def _setup_networking_inner(pid, port_mappings, cleanup_cmds):
    default_iface = subprocess.check_output("ip route | grep '^default' | awk '{print $5}'", shell=True).decode().strip()

    run_command("sysctl -w net.ipv4.ip_forward=1")
    cleanup_cmds.append("sysctl -w net.ipv4.ip_forward=0")

    run_command("ip link add veth_host type veth peer name veth_container")
    cleanup_cmds.append("ip link del veth_host")
    
    run_command("ip link set veth_host up")
    run_command("ip addr add 172.18.0.1/24 dev veth_host")
    run_command(f"ip link set veth_container netns {pid}")
    
    nat_rule = f"iptables -t nat -A POSTROUTING -s 172.18.0.0/24 -o {default_iface} -j MASQUERADE"
    run_command(nat_rule)
    cleanup_cmds.append(nat_rule.replace("-A", "-D"))

    # MASQUERADE traffic going into the container so its responses route back via
    # veth_host rather than trying to reach 127.0.0.1 through a non-loopback path.
    run_command("iptables -t nat -A POSTROUTING -d 172.18.0.0/24 -j MASQUERADE")
    cleanup_cmds.append("iptables -t nat -D POSTROUTING -d 172.18.0.0/24 -j MASQUERADE")

    # Allow the kernel to route loopback-addressed packets through veth interfaces.
    run_command("sysctl -w net.ipv4.conf.all.route_localnet=1")
    cleanup_cmds.append("sysctl -w net.ipv4.conf.all.route_localnet=0")

    # Allow return traffic for established connections
    run_command("iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT")
    cleanup_cmds.append("iptables -D FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT")

    # Allow DNS outbound so the server can resolve hostnames
    run_command("iptables -A FORWARD -s 172.18.0.0/24 -p udp --dport 53 -j ACCEPT")
    cleanup_cmds.append("iptables -D FORWARD -s 172.18.0.0/24 -p udp --dport 53 -j ACCEPT")
    run_command("iptables -A FORWARD -s 172.18.0.0/24 -p tcp --dport 53 -j ACCEPT")
    cleanup_cmds.append("iptables -D FORWARD -s 172.18.0.0/24 -p tcp --dport 53 -j ACCEPT")

    for mapping in port_mappings:
        host_port, container_port = mapping.split(":")
        for proto in ("tcp", "udp"):
            # PREROUTING: packets arriving on a real interface
            dnat_pre = f"iptables -t nat -A PREROUTING -p {proto} --dport {host_port} -j DNAT --to-destination 172.18.0.2:{container_port}"
            run_command(dnat_pre)
            cleanup_cmds.append(dnat_pre.replace("-A", "-D"))
            # OUTPUT: packets from localhost connecting to localhost:host_port
            dnat_out = f"iptables -t nat -A OUTPUT -p {proto} -d 127.0.0.1 --dport {host_port} -j DNAT --to-destination 172.18.0.2:{container_port}"
            run_command(dnat_out)
            cleanup_cmds.append(dnat_out.replace("-A", "-D"))
            # FORWARD inbound: traffic arriving at the container after DNAT
            fwd_in = f"iptables -A FORWARD -d 172.18.0.0/24 -p {proto} --dport {container_port} -j ACCEPT"
            run_command(fwd_in)
            cleanup_cmds.append(fwd_in.replace("-A", "-D"))

    # Drop all other outbound traffic from the container
    run_command("iptables -A FORWARD -s 172.18.0.0/24 -j DROP")
    cleanup_cmds.append("iptables -D FORWARD -s 172.18.0.0/24 -j DROP")


def cleanup_networking(cleanup_cmds):
    for cmd in reversed(cleanup_cmds):
        try:
            run_command(cmd)
        except subprocess.CalledProcessError as e:
            print(f"Warning: cleanup command failed (ignored): {e}")

def setup_seccomp():
    SCMP_ACT_ERRNO_EPERM = 0x00050001
    SCMP_ACT_ALLOW       = 0x7fff0000

    # syscall numbers for x86_64 Linux
    ALLOWED_SYSCALLS = [
        0,   # read
        1,   # write
        2,   # open
        3,   # close
        4,   # stat
        5,   # fstat
        6,   # lstat
        8,   # lseek
        9,   # mmap
        10,  # mprotect
        11,  # munmap
        12,  # brk
        13,  # rt_sigaction
        14,  # rt_sigprocmask
        17,  # pread64
        18,  # pwrite64
        19,  # readv
        20,  # writev
        21,  # access
        23,  # select
        24,  # sched_yield
        28,  # madvise
        32,  # dup
        33,  # dup2
        39,  # getpid
        41,  # socket
        42,  # connect
        43,  # accept
        44,  # sendto
        45,  # recvfrom
        46,  # sendmsg
        47,  # recvmsg
        48,  # shutdown
        49,  # bind
        50,  # listen
        51,  # getsockname
        52,  # getpeername
        54,  # setsockopt
        55,  # getsockopt
        56,  # clone
        57,  # fork
        58,  # vfork
        60,  # exit
        61,  # wait4
        63,  # uname
        72,  # fcntl
        73,  # flock
        74,  # fsync
        78,  # getdents
        79,  # getcwd
        80,  # chdir
        82,  # rename
        83,  # mkdir
        84,  # rmdir
        85,  # creat
        86,  # link
        87,  # unlink
        88,  # symlink
        89,  # readlink
        90,  # chmod
        91,  # fchmod
        95,  # umask
        96,  # gettimeofday
        97,  # getrlimit
        99,  # sysinfo
        100, # times
        102, # getuid
        104, # getgid
        107, # geteuid
        108, # getegid
        110, # getppid
        111, # getpgrp
        112, # setsid
        128, # rt_sigreturn
        158, # arch_prctl
        186, # gettid
        202, # futex
        218, # set_tid_address
        228, # clock_gettime
        231, # exit_group
        257, # openat
        262, # newfstatat
        267, # readlinkat
        273, # set_robust_list
        274, # get_robust_list
        293, # pipe2
        302, # prlimit64
        318, # getrandom
        334, # rseq
    ]

    try:
        lib = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    except OSError as e:
        print(f"Warning: could not load libseccomp, skipping seccomp filter: {e}")
        return

    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_rule_add.restype = ctypes.c_int
    lib.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                                      ctypes.c_int, ctypes.c_uint]
    lib.seccomp_load.restype = ctypes.c_int
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.argtypes = [ctypes.c_void_p]

    ctx = lib.seccomp_init(SCMP_ACT_ERRNO_EPERM)
    if not ctx:
        print("Warning: seccomp_init returned NULL, skipping seccomp filter")
        return

    for nr in ALLOWED_SYSCALLS:
        rc = lib.seccomp_rule_add(ctx, SCMP_ACT_ALLOW, nr, 0)
        if rc != 0:
            print(f"Warning: seccomp_rule_add failed for syscall {nr}: {rc}")

    rc = lib.seccomp_load(ctx)
    if rc != 0:
        print(f"Warning: seccomp_load failed: {rc}. Continuing without seccomp.")
    else:
        print("Seccomp filter loaded.")

    lib.seccomp_release(ctx)


def run_container(rootfs_path, command_args, memory_limit_mb, cpu_limit_percentage, pid_limit, port_mappings):
    network_enabled = bool(port_mappings)
    
    r_fd, w_fd = os.pipe()

    pid = os.fork()
    if pid == 0:
        # Create isolated namespaces in the child so the parent's subprocesses
        # (ip, iptables, sysctl) stay in the host namespaces and can see the
        # child's PID when setting up the veth pair.
        os.unshare(os.CLONE_NEWUTS | os.CLONE_NEWNS)
        # Prevent mount events from propagating back to the host namespace.
        # Without this, mounts inside the container leak into the host's /dev.
        os.system("mount --make-rprivate /")
        socket.sethostname("sandbox")
        os.chdir(rootfs_path)
        os.chroot(".")
        os.chdir("/")
        os.system("mount -t proc proc /proc")
        os.system("mount -t devtmpfs devtmpfs /dev")
        os.system("mount -t tmpfs tmpfs /tmp")
        os.system("mount -t tmpfs tmpfs /var")
        # Create world and home dirs in the fresh /var and /tmp tmpfs while
        # still root, then open them to writes by the unprivileged process.
        os.system("mkdir -p /var/luanti/world")
        os.system("chmod 777 /var/luanti /var/luanti/world")
        
        if network_enabled:
            os.unshare(os.CLONE_NEWNET)
            os.close(w_fd)
            os.read(r_fd, 1)   # block until parent finishes veth setup
            os.close(r_fd)
            run_command("ip link set lo up")
            run_command("ip link set veth_container up")
            run_command("ip addr add 172.18.0.2/24 dev veth_container")
            run_command("ip route add default via 172.18.0.1")
        else:
            os.close(r_fd)
            os.close(w_fd)

        os.setgid(65534)
        os.setuid(65534)

        setup_seccomp()

        os.environ["HOME"] = "/tmp"
        os.execvp(command_args[0], command_args)
    else:
        cleanup_cmds = []
        try:
            os.close(r_fd)
            if network_enabled:
                cleanup_cmds = setup_networking(pid, port_mappings)
                os.write(w_fd, b'\x00')
            os.close(w_fd)

            setup_cgroups(pid, memory_limit_mb, cpu_limit_percentage, pid_limit)

            _, status = os.waitpid(pid, 0)
            if os.WIFSIGNALED(status):
                sig = os.WTERMSIG(status)
                label = "OOM kill" if sig == 9 else f"signal {sig}"
                print(f"Container process killed by {label}.")
            elif os.WIFEXITED(status) and os.WEXITSTATUS(status) != 0:
                print(f"Container process exited with code {os.WEXITSTATUS(status)}.")
        finally:
            if network_enabled:
                cleanup_networking(cleanup_cmds)
            cleanup_cgroups(pid)

def parse_args():
    parser = argparse.ArgumentParser(description="Modbox containerization engine.")
    parser.add_argument("--memory-limit", type=int, default=50, help="Memory limit for the container in megabytes (MB).")
    parser.add_argument("--cpu-limit", type=float, default=0.5, help="CPU limit for the container as a percentage (e.g., 0.5 for 50%).")
    parser.add_argument("--pid-limit", type=int, default=32, help="Maximum number of processes allowed in the container.")
    parser.add_argument("--port", action='append', help="Port mapping (e.g., host_port:container_port). Can be specified multiple times.")
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