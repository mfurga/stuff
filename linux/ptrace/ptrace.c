#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>

int main(int argc, char *argv[]) {
  long r;

  if (argc < 2) {
    printf("Usage %s <pid>\n", argv[0]);
    return 1;
  }

  pid_t pid = atoi(argv[1]);

  r = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
  if (r == -1) {
    printf("ptrace failed (PTRACE_ATTACH)\n");
    return 1;
  }

  return 0;
}
