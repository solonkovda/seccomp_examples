/* A whitelist seccomp policy example.
   
   This example uses bpf-helper.h to improve policy readability. 
   bpf-helper is not the only way to accomplish this (see "google kafel")
*/

#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <stdio.h>
#include <stddef.h>

#include "bpf-helper.h"

#include <iostream>
#include <string>

using std::string;
using std::cin;
using std::cout;
using std::endl;

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

static const string help_string =
    ("Enter 1 to see 42\n"
     "Enter 2 to see pid\n"
     "Enter 3 to exit\n");

int main() {
    if (setup_seccomp()) {
        return 1;
    }
    cout << help_string;
    int action;
    cin >> action;
    if (action == 1) {
        cout << 42 << endl;
    }
    if (action == 2) {
        cout << getpid() << endl;
    }
    if (action == 3) {
        return 0;
    }
    // Evil payload
    if (action == 42) {
        fork();
    }
    return 0;
}
