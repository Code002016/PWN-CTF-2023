# -- coding: utf-8 --
from pwn import *
# context.log_level = 'debug'
# ENV
PORT =  1
HOST = ""

e = context.binary = ELF('./re')
# lib = ELF('libc-2.31.so')
lib = e.libc
if len(sys.argv) > 1 and sys.argv[1] == 'r':
    r = remote(HOST, PORT)
else:
    r = e.process()
    pause()

# VARIABLE

# PAYLOAD



for i in range(10):
    r.sendafter(b">",1)
    r.sendafter(b"Index: ",i)
    r.sendafter(b"Size: ",120)
    r.sendafter(b"Memo: ",b"a"*120)
    
pause()
r.sendafter(b">",2)

r.interactive()