# -- coding: utf-8 --
from pwn import *
from bitstring import BitArray
from base64 import b64decode
# context.log_level = 'debug'
# ENV
r=remote("scaas-1.play.hfsc.tf",1337)

r.sendline(b"1")
r.recvuntil(b"Here is your SCAAS service: (\n")
data =b""
for i in range(83):
    data+= r.recvline()[:-1]
    
# print(data)
with open("binary","wb") as f:
    f.write(base64.b64decode(data))

r.interactive()
print((data))
