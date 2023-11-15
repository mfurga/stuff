#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#define STACK_SIZE 4096

int child(void *arg) {
  (void)arg;

  printf("I'm child!\n");

  char *argv[] = {
    "/bin/bash",
    NULL
  };

  execv(argv[0], argv);
  return 0;
}

int main(void) {
  void *p = malloc(STACK_SIZE);
  int ns_flags = CLONE_NEWUTS |
                 CLONE_NEWPID |
                 CLONE_NEWIPC |
                 CLONE_NEWNS |
                 CLONE_NEWNET;

  int pid = clone(child,
                  p + STACK_SIZE,
                  ns_flags | SIGCHLD,
                  NULL);

  if (pid == -1) {
    perror("clone error");
    return 1;
  }

  printf("pid=%d\n", pid);

  waitpid(pid, NULL, 0);

  return 0;
}

