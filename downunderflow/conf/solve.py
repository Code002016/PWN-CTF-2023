from pwn import *
context.log_level = 'debug'
context.arch = "amd64"

e = context.binary = ELF('confusing')
r= e.process()
# r = remote('challs.n00bzunit3d.xyz', 42450)
# lib = e.libc
# lib= ELF('libc6_2.35-0ubuntu3_amd64.so')

r.sendlineafter(b"d: ",b"13337")
r.sendlineafter(b"s: ",b"1179402567")
# 1179402567
pause()
r.sendlineafter(b"f: ",p64(0x3ff9e3779b9486e5))

r.interactive()
