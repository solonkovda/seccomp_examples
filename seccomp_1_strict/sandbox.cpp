/* A basic example of seccomp_strict mode usage.

Seccomp has a strict mode, that forbids any syscalls, except
read, write, _exit, sigreturn. Any other syscall will result in SIGKILL.

This mode isn't very usable, since almost any program use a lot more syscalls.
*/

#include <linux/seccomp.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <cstdio>

static bool setup_seccomp() {
    if (syscall(__NR_seccomp, SECCOMP_SET_MODE_STRICT, 0, NULL)) {
        fprintf(stderr, "Failed to setup seccomp\n");
        return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    if (!setup_seccomp()) {
        return 1;
    }
    /* Do some important work */
    int a = 2;
    int b = 3;
    int c = a + b;
    if (c != 5) {
        /* Since strict mode forbids exit_group, which is called during normal
           exit, we are forced to call _exit directly */
        syscall(__NR_exit, 1);
    }
    
    /* Hidden backdoor */
    if (argc > 1 && argv[1][0] == 'X') {
        /* Make evil unexpected syscall */
        int pid = getpid();
        printf("%d\n", pid);
    }
    syscall(__NR_exit, 0);
}
