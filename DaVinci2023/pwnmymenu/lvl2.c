#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
//#include "seccomp-bpf.h"

void win() {
  exit(0x42);
}

void vuln() {
  char buffer[BUF_LEN] = {0};

  puts("Enter your payload:");
  gets(buffer);
}

void submenu() {
  char Submenu[3];
  puts("Submenu:");
  
  fgets(Submenu, sizeof(Submenu), stdin);

  if (*Submenu == SUBMENU)
    vuln();
}


int main() {
  char Menu[3];

  puts("Menu:");
  
  fgets(Menu, sizeof(Menu), stdin);

  if (*Menu == MENU)
    submenu();

  return 0;
}

