#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/syscall.h>
#include <asm/prctl.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <stdio.h>
#include <stddef.h>

#include <vector>

#include "bpf-helper.h"

int setup_seccomp() {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl failed");
        return 1;
    }
    bpf_labels l = {.count = 0};
    sock_filter filter[] = {
        LOAD_SYSCALL_NR,
        
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

void launch_sandboxee(int argc, char **argv) {
    std::vector<char*> args(argc + 1, NULL);
    args[0] = (char*) "sandboxee";
    for (int i = 1; i < argc; i++) {
        args[i] = argv[i];
    }
    if (execvp("sandboxee", args.data())) {
        perror("sandboxee exec failed");
    }
    return;
}
 
int setup_ptrace(pid_t pid) {
    /* We are using SEIZE and not ATTACH, since
       currently only SEIZE can handle group stops correctly */
    if (ptrace(PTRACE_SEIZE, pid, 0, 0)) {
        perror("ptrace seize");
        return 1;
    }
    int flags = 0;
    /* If tracer dies, all of tracee dies as well */
    flags |= PTRACE_O_EXITKILL;
    /* If tracee calls clone, exec, fork, vfork, tracer will start trace them */
    flags |= PTRACE_O_TRACECLONE;
    flags |= PTRACE_O_TRACEEXEC;
    flags |= PTRACE_O_TRACEFORK;
    flags |= PTRACE_O_TRACEVFORK;
    /* We will intercept seccomp RET_TRACE */
    flags |= PTRACE_O_TRACESECCOMP;
    /* Report to tracer, when tracee dies. It is not really required for 
       proper sandbox, but it provides additional info to log */
    flags |= PTRACE_O_TRACEEXIT;
    if (ptrace(PTRACE_SET_OPTIONS, pid, 0, flags)) {
        perror("ptrace set_options");
        return 1;
    }
    return 0;
}

void ptrace_main_loop() {
    
}

int main(int argc, char **argv) {
    // Create a pipe for communication after work
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        perror("pipe");
        return 1;
    }
    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        return 1;
    }
    if (pid == 0) {
        // Child
        close(pipefd[1]);
        // Wait until parent finish setting up ptrace and send us a signal
        char buffer[1];
        if (read(pipefd[0], buffer, 1) <= 0) {
            perror("child read");
            return 1;
        }
        if (buffer[0] != 'y') {
            perror("parent setup failed");
            return 1;
        }
        close(pipefd[0]);
        launch_sandboxee(argc, argv);
    }
    else {
        // Parent
        close(pipefd[0]);
        if (setup_ptrace(pid)) {
            perror("ptrace failed");
            char buffer[1];
            buffer[0] = 'n';
            write(pipefd[1], buffer, 1);
            return 1;
        }
        // Unfreeze the child
        char buffer[1];
        buffer[0] = 'y';
        write(pipefd[1], buffer, 1);
        close(pipefd[1]);
        ptrace_main_loop();
    }
    return 0;
}
