import os
import sys
import socket
import argparse
import subprocess

def run_command(cmd):
    print(f"Executing: {cmd}")
    os.system(cmd)

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

def setup_networking(pid, port_mappings):
    cleanup_cmds = []
    
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
    
    for mapping in port_mappings:
        host_port, container_port = mapping.split(":")
        dnat_rule = f"iptables -t nat -A PREROUTING -p tcp --dport {host_port} -j DNAT --to-destination 172.18.0.2:{container_port}"
        run_command(dnat_rule)
        cleanup_cmds.append(dnat_rule.replace("-A", "-D"))
        
    return cleanup_cmds

def cleanup_networking(cleanup_cmds):
    for cmd in reversed(cleanup_cmds):
        run_command(cmd)

def run_container(rootfs_path, command_args, memory_limit_mb, cpu_limit_percentage, pid_limit, port_mappings):
    network_enabled = bool(port_mappings)
    
    unshare_flags = os.CLONE_NEWPID | os.CLONE_NEWUTS | os.CLONE_NEWNS
    if network_enabled:
        unshare_flags |= os.CLONE_NEWNET

    os.unshare(unshare_flags)
    
    pid = os.fork()
    if pid == 0:
        socket.sethostname("sandbox")
        os.chdir(rootfs_path)
        os.chroot(".")
        os.chdir("/")
        os.system("mount -t proc proc /proc")
        os.system("mount -o remount,ro /")
        
        if network_enabled:
            run_command("ip link set lo up")
            run_command("ip link set veth_container up")
            run_command("ip addr add 172.18.0.2/24 dev veth_container")
            run_command("ip route add default via 172.18.0.1")

        os.setgid(65534)
        os.setuid(65534)

        os.execvp(command_args[0], command_args)
    else:
        cleanup_cmds = []
        try:
            if network_enabled:
                cleanup_cmds = setup_networking(pid, port_mappings)
            
            setup_cgroups(pid, memory_limit_mb, cpu_limit_percentage, pid_limit)
            
            os.waitpid(pid, 0)
        finally:
            if network_enabled:
                cleanup_networking(cleanup_cmds)

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