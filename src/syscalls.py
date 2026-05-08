ALLOWED_SYSCALLS = [
    # --- I/O ---
    0,   # read
    1,   # write
    17,  # pread64
    18,  # pwrite64
    19,  # readv
    20,  # writev
    22,  # pipe
    32,  # dup
    33,  # dup2
    293, # pipe2

    # --- File system ---
    2,   # open
    3,   # close
    4,   # stat
    5,   # fstat
    6,   # lstat
    8,   # lseek
    21,  # access
    72,  # fcntl
    73,  # flock
    74,  # fsync
    75,  # fdatasync
    76,  # truncate
    77,  # ftruncate
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
    217, # getdents64
    221, # fadvise64
    257, # openat
    262, # newfstatat
    267, # readlinkat
    277, # sync_file_range
    285, # fallocate
    332, # statx

    # --- Memory ---
    # mmap (9) and mprotect (10) are handled with PROT_EXEC conditions in prepare_seccomp()
    11,  # munmap
    12,  # brk
    25,  # mremap
    28,  # madvise
    318, # getrandom

    # --- Process / thread ---
    39,  # getpid
    56,  # clone
    57,  # fork
    58,  # vfork
    59,  # execve
    60,  # exit
    61,  # wait4
    63,  # uname
    97,  # getrlimit
    99,  # sysinfo
    100, # times
    110, # getppid
    111, # getpgrp
    112, # setsid
    158, # arch_prctl
    186, # gettid
    218, # set_tid_address
    231, # exit_group
    234, # tgkill
    247, # waitid
    273, # set_robust_list
    274, # get_robust_list
    302, # prlimit64
    334, # rseq

    # --- Credentials ---
    102, # getuid
    104, # getgid
    105, # setuid
    106, # setgid
    107, # geteuid
    108, # getegid
    113, # setreuid
    114, # setregid
    116, # setgroups
    117, # setresuid
    119, # setresgid

    # --- Signals ---
    13,  # rt_sigaction
    14,  # rt_sigprocmask
    128, # rt_sigreturn
    131, # sigaltstack

    # --- Scheduling / time ---
    24,  # sched_yield
    96,  # gettimeofday
    228, # clock_gettime
    230, # clock_nanosleep
    35,  # nanosleep

    # --- Synchronisation ---
    202, # futex

    # --- Sockets ---
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
    299, # recvmmsg
    307, # sendmmsg

    # --- Polling / event ---
    7,   # poll
    23,  # select
    232, # epoll_wait
    233, # epoll_ctl
    270, # pselect6
    281, # epoll_pwait
    291, # epoll_create1

    # --- Misc ---
    16,  # ioctl
    157, # prctl
]
