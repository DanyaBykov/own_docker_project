# Custom Container Project: How it Works and Security

This project is a simple version of Docker. It lets you run an application in a "box" so it doesn't interfere with the rest of your computer.

## 1. How the "Box" is Built

To create this box, we use two main features of the Linux system: **Namespaces** and **Control Groups**.

### Making the Container Private (Namespaces)
Namespaces act like walls that hide parts of the system from the container.

*   **Files (Mount):** The container has its own isolated mounted drive. It can only see the files inside the Alpine Linux folder.
*   **Processes (PID):** The container thinks it is the only thing running. It can't see other apps running on host machine.
*   **Networking (Net):** The container gets its own isolated network. It can't listen to or mess with the host computer's network traffic.
*   **Identity (User):** Even if someone becomes root inside the container, the host computer still sees them as a regular user. This keeps your actual system safe.

### Setting limits (cgroups)
If a container has no limitation on power and resources of a host machine, it can eat a lot of them, which can be used to crash the host. We use cgroups to limit that:

*   **Memory Limit:** We tell the container exactly how much RAM it can use. If it tries to take more, it is stopped.
*   **CPU Limit:** We limit how much of the CPU the container can use.
*   **Process Limit:** This stops the container from creating a huge amount of tiny tasks to try and freeze the system.

---

# Custom Container Project: How it Works and Security

This project is a simple version of Docker that allows you to run an application in a "box" so it doesn't interfere with the rest of your computer. It uses standard Linux features to create an isolated environment, primarily using an Alpine Linux root filesystem.

## 1. How the "Box" is Built

To create this box, we use two main features of the Linux kernel: **Namespaces** and **Control Groups**.

### Making the Container Private (Namespaces)
Namespaces act like walls that hide parts of the system from the container.
* **Files (Mount):** The container has its own isolated mounted drive and can only see files inside the Alpine Linux folder.
* **Processes (PID):** The container thinks it is the only thing running and cannot see or signal other applications running on the host machine.
* **Networking (Net):** The container gets its own isolated network stack, preventing it from messing with the host's traffic.
* **Identity (User):** Even if a user becomes root inside the container, they are treated as a regular user on the host system to keep the actual system safe.
* **System Identity (UTS & IPC):** The container has its own hostname ("sandbox") and its own internal communication channels, separated from the host.

### Setting Limits (cgroups)
If a container has no resource limits, it could crash the host by eating all the power. We use cgroups v2 to set a "budget":
* **Memory Limit:** We set a maximum amount of RAM the container can use; if it tries to take more, it is stopped.
* **CPU Limit:** We restrict how much processing power the container can use.
* **Process Limit:** This stops the container from creating a huge number of tiny tasks (like a fork bomb) to freeze the system.

---

## 2. Advanced Defenses in `main.py`

The `main.py` script also adds several layers of active defense to keep the container locked down:
* **System Call Filter (Seccomp):** This acts like a security guard that only allows the container to use a specific list of approved syscalls.
* **The "No-New-Privileges" Rule:** A permanent lock is set so the container can never gain more power than it started with, even if it finds a security hole.
* **Pivot Root:** The script physically moves the container into its own folder and removes the link to the host's files.
* **Privilege Dropping:** Right before starting the app, the container drops root privelege and becomes a nobody user with zero permissions.
* **Firewall Rules (Iptables):** Special rules are set up to let the container talk to the internet while explicitly blocking it from attacking the host's private network ports.
* **Disable JIT** Disable JIT at compilation, so the mod can't execute code at runtime

---

## 3. Attack Vectors in `init.lua` (The "Evil Mod")

The `init.lua` file is a test script designed to see if the container's defences are solid by trying common escape and spying methods:
* **Spying on Processes:** It tries to look inside the `/proc` folder to see if host processes or the container manager are visible.
* **Network Probing:** It attempts to ping the host machine on various ports to see if it can reach the host from the inside.
* **Memory Execution Attack:** It tries to create a piece of memory and mark it as "Executable," and try to run some malicious code.
* **Resource Leak Hunting:** It looks for "leaked" file handles that the manager might have accidentally left open, which could point back to host files.
* **The /proc/1/root Trick:** It tries to use a shortcut in the system folder to read a secret flag file from the host's temporary folder. If PID namespaces are not isolated, /proc/1/root points at the host root; the mod can read /proc/1/root/tmp/flag.txt directly.