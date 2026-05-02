import time
import sys
import os


def memory_stress():
    print("Starting memory allocation")
    data = []
    try:
        while True:
            data.append(bytearray(10 * 1024 * 1024))
            print(f"Allocated {len(data) * 10}MB")
            time.sleep(0.5)
    except MemoryError:
        print("Python caught a MemoryError.")


def cpu_stress():
    print("Starting CPU stress — run with --cpu-limit and watch htop or cpu.stat")
    print(f"PID: {os.getpid()}")
    count = 0
    while True:
        count += 1
        if count % 50_000_000 == 0:
            print(f"Iterations: {count} (check: cat /sys/fs/cgroup/sandbox_<PID>/cpu.stat)")


def pid_stress():
    print("Starting PID fork bomb — should fail when pids.max is hit")
    children = []
    try:
        while True:
            pid = os.fork()
            if pid == 0:
                time.sleep(30)
                sys.exit(0)
            children.append(pid)
            print(f"Spawned child {len(children)}: PID {pid}")
    except BlockingIOError:
        print(f"Fork blocked after {len(children)} children — pids.max is working")
    finally:
        for p in children:
            try:
                os.kill(p, 9)
                os.waitpid(p, 0)
            except OSError:
                pass


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "memory"
    if mode == "cpu":
        cpu_stress()
    elif mode == "pid":
        pid_stress()
    else:
        memory_stress()
