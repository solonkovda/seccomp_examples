/* Really simple example of using raw seccomp-bpf syntax, to forbid one syscall.

We won't bother doing a full white list policy, since raw syntax is rather hard
to code and read.
*/

#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <stdio.h>
#include <stddef.h>

#include <iostream>

/*
    Since on different architectures programs use different syscalls, we can use
    seccomp policy only on architectures, that we have tested
*/
#ifndef __x86_64__
    #error "architecture not supported"
#endif


static bool setup_seccomp() {
    /* Linux requires that we call PR_SET_NO_NEW_PRIVS before using filters */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl failed");
        return 0;
    }
    
    sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (offsetof(seccomp_data, nr))),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter
    };
    
    if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                SECCOMP_FILTER_FLAG_TSYNC, &prog)) {
        perror("seccomp failed");
        return 0;
    }
    return 1;
}

int main() {
    if (!setup_seccomp()) {
        return 1;
    }
    int a, b;
    std::cin >> a >> b;
    int res = a + b;
    // Evil payload
    if (res == 42) {
        res = getpid();
    }
    std::cout << res << std::endl;
    return 0;
}
