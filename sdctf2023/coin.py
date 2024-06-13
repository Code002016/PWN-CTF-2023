# -- coding: utf-8 --
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
# ENV
e = context.binary = ELF('./tROPic-thunder')
lib = e.libc
# r = process('./tROPic-thunder')
r = remote("thunder.sdc.tf",1337)
# VARIABLE
 
win=0x145C
pause()
r.sendline(payload)


r.interactive()