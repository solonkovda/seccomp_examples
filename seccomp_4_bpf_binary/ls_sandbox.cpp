/* A simple sandbox for "ls" binary(without flags support).

   This example demonstrates how to sandbox given binary, without access to its
   source code.
   Since now we are forced to setup seccomp, before launching binary our policy
   is more complex (we need to allow memory allocation and etc)
   
   To create sandbox policy, first strace was run multiple times on different
   "ls" invocations, gathering data about syscalls.
   
   Then the data was used to find, which syscalls were used and how they were
   used. Some syscalls were fully allowed (close, brk, etc), and some syscalls
   were too powerful and additional restrictions were applied(arch_prctl)
   
   In order to keep this example simple, sandbox was built only for basic "ls",
   without flags support. Also, some syscalls could
   be filtered more(mmap, mprotect, etc), but once again, for simplicity they
   were fully allowed.
*/

#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/syscall.h>
#include <asm/prctl.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <stdio.h>
#include <stddef.h>

#include "bpf-helper.h"

#include <vector>

int setup_seccomp() {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl failed");
        return 1;
    }
    bpf_labels l = {.count = 0};
    sock_filter filter[] = {
        LOAD_SYSCALL_NR,

        SYSCALL(__NR_fstat, ALLOW),
        SYSCALL(__NR_write, ALLOW),
        SYSCALL(__NR_read, ALLOW),
        SYSCALL(__NR_lseek, ALLOW),
        SYSCALL(__NR_exit_group, ALLOW),
        SYSCALL(__NR_getpid, ALLOW),
        SYSCALL(__NR_execve, ALLOW),
        
        // ls requirements
        SYSCALL(__NR_brk, ALLOW),
        SYSCALL(__NR_access, ALLOW),
        SYSCALL(__NR_open, ALLOW),
        SYSCALL(__NR_close, ALLOW),
        SYSCALL(__NR_mprotect, ALLOW),
        SYSCALL(__NR_munmap, ALLOW),
        SYSCALL(__NR_set_tid_address, ALLOW),
        SYSCALL(__NR_set_robust_list, ALLOW),
        SYSCALL(__NR_rt_sigaction, ALLOW),
        SYSCALL(__NR_rt_sigprocmask, ALLOW),
        SYSCALL(__NR_getrlimit, ALLOW),
        SYSCALL(__NR_statfs, ALLOW),
        SYSCALL(__NR_tgkill, ALLOW),
        SYSCALL(__NR_getdents, ALLOW),
        SYSCALL(__NR_stat, ALLOW),
        SYSCALL(__NR_lstat, ALLOW),
        // arch_prctl is too broad to be fully allowed.
        SYSCALL(__NR_arch_prctl, JUMP(&l, arch_prctl_l)),
        // This syscalls could be filtered more
        SYSCALL(__NR_mmap, ALLOW),
        SYSCALL(__NR_ioctl, ALLOW),
        DENY,
        
        // Allowing only "arch_prct(ARCH_SET_FS, ...)"
        LABEL(&l, arch_prctl_l),
        ARG(0),
        JEQ(ARCH_SET_FS, ALLOW),
        DENY,
    };
    if (bpf_resolve_jumps(&l, filter, (sizeof(filter) / sizeof(filter[0])))) {
        perror("failed to resolve jumps");
        return 1;
    }
    struct sock_fprog prog = {
        .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                SECCOMP_FILTER_FLAG_TSYNC, &prog)) {
        perror("seccomp syscall failed");
        return 1;
    }
    return 0;
}

int start_sandboxee(int argc, char **argv) {
    std::vector<char*> args(argc + 1, NULL);
    args[0] = (char*) "ls";
    for (int i = 1; i < argc; i++) {
        args[i] = argv[i];
    }
    if (execvp("ls", args.data())) {
        perror("ls exec failed");
    }
    return 1;
}

int main(int argc, char **argv) {
    if (setup_seccomp()) {
        return 1;
    }
    if (start_sandboxee(argc, argv)) {
        return 1;
    }
    // We should never reach this.
    return 0;
}
