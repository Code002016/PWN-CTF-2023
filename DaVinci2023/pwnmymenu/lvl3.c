#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "seccomp-bpf.h"

void win() {
  exit(0x42);
}

void vuln() {
  char buffer[BUF_LEN] = {0};

  puts("Enter your payload:");
  gets(buffer);
}

void submenu() {
  uint64_t buf;
  puts("Submenu:");
  
  read(0, &buf, sizeof(buf));

  if (buf == SUBMENU)
    vuln();
}

int main() {
  uint64_t buf;

  if (install_syscall_filter == 1)
    exit(0);

  puts("Menu:");
  
  read(0, &buf, sizeof(buf));
  if (buf == MENU)
    submenu();

  return 0;
}

