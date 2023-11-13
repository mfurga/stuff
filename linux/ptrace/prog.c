#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main(void) {
  pid_t pid = getpid();

  printf("PID: %u\n", pid);

  getchar();
  return 0;
}
