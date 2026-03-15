import os
import sys
import socket

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
        os.waitpid(pid, 0)

if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("Error: Run as root (sudo).")
    
    path = os.path.abspath("rootfs")
    if not os.path.exists(path):
        sys.exit("Error: rootfs folder not found.")
        
    run_container(path)