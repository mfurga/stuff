#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

const char *s = "Hello world!";

int main(void) {
  printf("Child:)\n");
  sleep(1);
  printf("Child:)\n");
  return 1;
  
  pid_t pid = getpid();

  printf("PID: %u\n", pid);
  printf("main: %p\n", main);
  printf("str : %p\n", s);

  getchar();
  return 0;
}
