import os
import sys
import socket
import subprocess
import ctypes
import threading
import time

def report(name, result, detail=""):
    status = "[ESCAPED]" if result else "[CONTAINED]"
    print(f"{name:.<40} {status} {detail}")

def probe_fs():
    targets = ["/tmp/flag.txt", "/etc/shadow", "/proc/1/maps"]
    escaped = False
    details = []
    for t in targets:
        try:
            with open(t, "r") as f:
                content = f.read(32).strip()
                if t == "/tmp/flag.txt" and "HOST_FLAG" in content:
                    escaped = True
                details.append(f"Read {t}: {content[:15]}...")
        except Exception as e:
            details.append(f"Blocked {t}: {type(e).__name__}")
    
    report("Filesystem Isolation", escaped, " | ".join(details))

def probe_privs():
    escaped = False
    detail = ""
    try:
        os.setuid(0)
        escaped = (os.getuid() == 0)
    except Exception as e:
        detail = str(e)
    
    report("Privilege Escalation (setuid 0)", escaped, detail if not escaped else "Became ROOT")

def probe_syscalls():
    escaped = False
    detail = ""
    try:
        from ctypes.util import find_library
        libc_path = find_library("c")
        if not libc_path:
            # Fallback for Alpine/musl
            libc_path = "libc.musl-x86_64.so.1"
        libc = ctypes.CDLL(libc_path, use_errno=True)
        # ptrace(PTRACE_TRACEME, 0, 0, 0)
        res = libc.ptrace(0, 0, 0, 0)
        escaped = (res == 0)
    except Exception as e:
        detail = str(e)
    
    report("Syscall Jailbreak (ptrace)", escaped, "Allowed" if escaped else f"Blocked/Crashed: {detail}")

def probe_network():
    escaped = False
    detail = ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 53))
        escaped = True
        s.close()
    except Exception as e:
        detail = str(e)
    
    report("Network Leak (8.8.8.8:53)", escaped, detail if not escaped else "Connected")

def probe_resources():
    print("Testing Memory Limit (targeting 100MB)...")
    try:
        chunks = []
        for i in range(1, 11):
            chunks.append(bytearray(10 * 1024 * 1024))
            print(f"Allocated {i*10}MB...")
            time.sleep(0.1)
        report("Resource: Memory Limit", True, "Used 100MB (FAILED TO LIMIT)")
    except MemoryError:
        report("Resource: Memory Limit", False, "OOM caught in Python")
    except Exception as e:
        report("Resource: Memory Limit", False, str(e))

    print("Testing PID Limit (forking 50 times)...")
    pids = []
    success_count = 0
    for i in range(50):
        try:
            pid = os.fork()
            if pid == 0:
                time.sleep(1)
                os._exit(0)
            pids.append(pid)
            success_count += 1
        except Exception:
            break
    
    escaped = (success_count >= 50)
    report("Resource: PID Limit", escaped, f"Spawned {success_count} procs")
    
    for p in pids:
        try: os.waitpid(p, 0)
        except: pass

if __name__ == "__main__":
    print("--- Security Test: Security Audit Suite ---")
    print(f"Running as UID: {os.getuid()}, GID: {os.getgid()}")
    probe_fs()
    probe_privs()
    probe_syscalls()
    probe_network()
    probe_resources()
