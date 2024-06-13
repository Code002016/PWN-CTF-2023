from pwn import *
# context.arch = "amd64"

print((shellcraft.i386.linux.execve("ls -la")))