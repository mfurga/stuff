#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>

#define FAIL(...) \
  do { \
    perror(__VA_ARGS__); \
    return 1; \
  } while (0)

int main(int argc, char *argv[]) {
  if (argc < 2) {
    printf("Usage: %s <prog> ...\n", argv[0]);
    return 1;
  }

  pid_t pid = fork();

  if (pid == -1) {
    FAIL("fork failed");
  }

  if (pid == 0) {
    /* Child */
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    raise(SIGSTOP);
    execvp(argv[1], argv + 1);
  }

  /* Parent */
  waitpid(pid, NULL, 0);

  struct user_regs_struct regs;

  for (;;) {
    if (ptrace(PTRACE_SYSCALL, pid, NULL, 0) == -1) {
      FAIL("ptrace syscall");
    }

    if (waitpid(pid, NULL, 0) == -1) {
      FAIL("waitpid error");
    }

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
      FAIL("ptrace getregs");
    }

    printf("%lld(%lld, %lld, %lld, %lld)",
      regs.orig_rax, regs.rdi, regs.rsi, regs.rdx, regs.r10);

    if (ptrace(PTRACE_SYSCALL, pid, NULL, 0) == -1) {
      FAIL("ptrace syscall");
    }

    if (waitpid(pid, NULL, 0) == -1) {
      FAIL("waitpid error");
    }

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
      FAIL("ptrace getregs");
    }

    printf(" = %lld\n", regs.orig_rax);
  }

  return 0;
}
