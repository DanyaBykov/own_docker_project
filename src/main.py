import os
import sys
import socket

def set_memory_limit(pid, limit_bytes):
    cg_path = f"/sys/fs/cgroup/sandbox_{pid}"
    os.makedirs(cg_path, exist_ok=True)
    
    with open(os.path.join(cg_path, "memory.max"), "w") as f:
        f.write(str(limit_bytes))
        
    with open(os.path.join(cg_path, "memory.swap.max"), "w") as f:
        f.write("0")
    
    with open(os.path.join(cg_path, "cgroup.procs"), "w") as f:
        f.write(str(pid))

def run_container(rootfs_path):
    os.unshare(os.CLONE_NEWPID | os.CLONE_NEWUTS | os.CLONE_NEWNS | os.CLONE_NEWNET)
    
    pid = os.fork()
    if pid == 0:
        socket.sethostname("sandbox")
        
        os.chdir(rootfs_path)
        os.chroot(".")
        os.chdir("/")
        
        os.system("mount -t proc proc /proc")
        os.execvp("/bin/sh", ["/bin/sh"])
    else:
        try:
            set_memory_limit(pid, 50 * 1024 * 1024)
        except Exception as e:
            print(f"Warning: Could not set cgroup limit: {e}")

        os.waitpid(pid, 0)

if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("Error: Run as root (sudo).")
    
    path = os.path.abspath("rootfs")
    if not os.path.exists(path):
        sys.exit("Error: rootfs folder not found.")
        
    run_container(path)